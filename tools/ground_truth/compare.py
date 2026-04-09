#!/usr/bin/env python3
"""Compute per-tool recall against EXPECTED_FINDINGS.md.

Parses the markdown ground-truth table for each cloud, then walks the
GitLab SAST reports to mark each planted issue as caught/missed by each tool.

Recall is the metric we trust here. Precision is intentionally NOT reported:
real IaC scanners legitimately flag many issues we did not plant, so the
"false positive" count would mislead. The dashboard separately surfaces
*unique* findings per tool so reviewers can sanity-check those by hand.

Usage:
    python compare.py \
        --reports ./reports \
        --ground-truth-aws terraform/aws/EXPECTED_FINDINGS.md \
        --ground-truth-azure terraform/azure/EXPECTED_FINDINGS.md \
        --output ./out/precision_recall.json
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


REPORT_RE = re.compile(r"gl-sast-report-(?P<tool>[^-]+)-(?P<cloud>[^.]+)\.json$")
ROW_RE = re.compile(
    r"^\|\s*(?P<num>\d+)\s*\|\s*(?P<file>[^|]+?)\s*\|"
    r"\s*(?P<resource>[^|]+?)\s*\|"
    r"\s*(?P<category>[^|]+?)\s*\|"
    r"\s*(?P<issue>[^|]+?)\s*\|"
    r"\s*(?P<checks>[^|]+?)\s*\|"
)


def parse_ground_truth(md_path: Path) -> list[dict[str, Any]]:
    """Extract planted-issue rows from an EXPECTED_FINDINGS.md table."""
    rows: list[dict[str, Any]] = []
    for line in md_path.read_text().splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        check_ids = [c.strip() for c in m["checks"].split(",") if c.strip()]
        if not check_ids:
            continue
        rows.append(
            {
                "num": int(m["num"]),
                "file": m["file"].strip(),
                "resource": m["resource"].strip(),
                "category": m["category"].strip(),
                "issue": m["issue"].strip(),
                "expected_check_ids": check_ids,
            }
        )
    return rows


def _findings_by_tool(reports_dir: Path) -> dict[tuple[str, str], list[dict]]:
    """Return {(tool, cloud): [vulnerability dicts]}."""
    out: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for path in sorted(reports_dir.rglob("gl-sast-report-*.json")):
        m = REPORT_RE.search(path.name)
        if not m:
            continue
        try:
            report = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        out[(m["tool"], m["cloud"])] = report.get("vulnerabilities", []) or []
    return out


def _check_ids_for(vuln: dict) -> set[str]:
    ids: set[str] = set()
    for ident in vuln.get("identifiers", []) or []:
        val = ident.get("value") or ident.get("name")
        if val:
            ids.add(val)
    name = vuln.get("name")
    if name:
        ids.add(name)
    return ids


def compute_recall(
    ground_truth: dict[str, list[dict]],
    findings: dict[tuple[str, str], list[dict]],
) -> dict[str, Any]:
    tools = sorted({tool for tool, _ in findings})
    clouds = sorted(ground_truth.keys())

    per_tool: dict[str, dict[str, Any]] = {
        tool: {
            "caught": 0,
            "planted": 0,
            "recall": 0.0,
            "missed": [],
            "by_cloud": {},
        }
        for tool in tools
    }

    for cloud in clouds:
        planted = ground_truth[cloud]
        for tool in tools:
            tool_findings = findings.get((tool, cloud), [])
            # Build a flat set of all check IDs this tool reported, plus
            # an index of (file → check IDs) for stricter matching.
            file_index: dict[str, set[str]] = defaultdict(set)
            for v in tool_findings:
                file = (v.get("location") or {}).get("file", "")
                file_basename = Path(file).name
                for cid in _check_ids_for(v):
                    file_index[file_basename].add(cid)

            caught = 0
            missed = []
            for row in planted:
                expected_set = set(row["expected_check_ids"])
                expected_file = row["file"]
                got = file_index.get(expected_file, set())
                # A planted issue counts as caught if ANY of its expected
                # check IDs appear in the same source file.
                if expected_set & got:
                    caught += 1
                else:
                    missed.append(
                        {
                            "num": row["num"],
                            "file": expected_file,
                            "issue": row["issue"],
                            "expected_check_ids": row["expected_check_ids"],
                        }
                    )

            per_tool[tool]["by_cloud"][cloud] = {
                "caught": caught,
                "planted": len(planted),
                "recall": round(caught / len(planted), 3) if planted else 0.0,
                "missed": missed,
            }
            per_tool[tool]["caught"] += caught
            per_tool[tool]["planted"] += len(planted)
            per_tool[tool]["missed"].extend(
                {**m, "cloud": cloud} for m in missed
            )

    for tool, data in per_tool.items():
        data["recall"] = (
            round(data["caught"] / data["planted"], 3) if data["planted"] else 0.0
        )

    return {
        "tools": tools,
        "clouds": clouds,
        "per_tool": per_tool,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--ground-truth-aws", type=Path, required=True)
    parser.add_argument("--ground-truth-azure", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    ground_truth = {
        "aws": parse_ground_truth(args.ground_truth_aws),
        "azure": parse_ground_truth(args.ground_truth_azure),
    }
    if not ground_truth["aws"] or not ground_truth["azure"]:
        print("ERROR: failed to parse ground-truth tables")
        return 1

    findings = _findings_by_tool(args.reports)
    if not findings:
        print(f"ERROR: no reports found under {args.reports}")
        return 1

    result = compute_recall(ground_truth, findings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2))

    print("Recall by tool:")
    for tool in result["tools"]:
        data = result["per_tool"][tool]
        print(f"  {tool:10s}  {data['caught']:>3}/{data['planted']}  ({data['recall']:.0%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
