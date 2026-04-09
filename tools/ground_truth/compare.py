#!/usr/bin/env python3
"""Compute per-tool recall against EXPECTED_FINDINGS.md.

The matcher works by **resource line range**, not by rule ID. Different
scanners use wildly different rule-ID conventions (Checkov: ``CKV_AWS_24``,
Trivy: ``AWS-0107``, Semgrep: ``terraform.aws.security.aws-ec2-...``), so
exact-ID matching only credits the scanner whose vocabulary the ground-truth
table happens to use. Instead we:

1. Parse each .tf file to extract the line range of every ``resource "..." "..."`` block.
2. Look up the resource named in each ground-truth row to get its line range.
3. Mark a planted issue as **caught** if the scanner reported any finding in
   the same file basename whose start line falls within that range.

Recall is the metric we trust here. Precision is intentionally NOT reported:
real IaC scanners legitimately flag many issues we did not plant, so the
"false positive" count would mislead. The dashboard separately surfaces
*unique* findings per tool so reviewers can sanity-check those by hand.

Usage:
    python compare.py \
        --reports ./reports \
        --terraform-aws terraform/aws \
        --terraform-azure terraform/azure \
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

# Markdown row in EXPECTED_FINDINGS.md.
ROW_RE = re.compile(
    r"^\|\s*(?P<num>\d+)\s*\|\s*(?P<file>[^|]+?)\s*\|"
    r"\s*(?P<resource>[^|]+?)\s*\|"
    r"\s*(?P<category>[^|]+?)\s*\|"
    r"\s*(?P<issue>[^|]+?)\s*\|"
    r"\s*(?P<checks>[^|]+?)\s*\|"
)

# Terraform resource block start: `resource "TYPE" "NAME" {`
RESOURCE_DECL_RE = re.compile(
    r'^\s*resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{'
)


def parse_ground_truth(md_path: Path) -> list[dict[str, Any]]:
    """Extract planted-issue rows from an EXPECTED_FINDINGS.md table."""
    rows: list[dict[str, Any]] = []
    for line in md_path.read_text().splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        rows.append(
            {
                "num": int(m["num"]),
                "file": m["file"].strip(),
                "resource": m["resource"].strip(),
                "category": m["category"].strip(),
                "issue": m["issue"].strip(),
                "expected_check_ids": [
                    c.strip() for c in m["checks"].split(",") if c.strip()
                ],
            }
        )
    return rows


def parse_resource_ranges(tf_dir: Path) -> dict[str, tuple[str, int, int]]:
    """Walk a terraform directory and return {resource_address: (file, start, end)}.

    Resource addresses look like ``aws_security_group.app``. End line is the
    last line of the brace-balanced block.
    """
    out: dict[str, tuple[str, int, int]] = {}
    for tf in sorted(tf_dir.glob("*.tf")):
        lines = tf.read_text().splitlines()
        for i, line in enumerate(lines, start=1):
            m = RESOURCE_DECL_RE.match(line)
            if not m:
                continue
            address = f"{m['type']}.{m['name']}"
            # Walk forward, balancing braces, to find the closing line.
            depth = 0
            end = i
            for j in range(i - 1, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                if depth <= 0 and j >= i - 1:
                    end = j + 1
                    break
            out[address] = (tf.name, i, end)
    return out


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


def _index_findings_by_file(vulns: list[dict]) -> dict[str, list[int]]:
    """{file_basename: [start_line, ...]} for one tool/cloud."""
    idx: dict[str, list[int]] = defaultdict(list)
    for v in vulns:
        loc = v.get("location") or {}
        file = Path(loc.get("file", "")).name
        try:
            line = int(loc.get("start_line", 0))
        except (TypeError, ValueError):
            line = 0
        idx[file].append(line)
    return idx


def compute_recall(
    ground_truth: dict[str, list[dict]],
    resource_ranges: dict[str, dict[str, tuple[str, int, int]]],
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

    # File-level fallback: a few ground-truth rows describe account-wide
    # issues (e.g. "no password policy resource") that don't map to a single
    # block. For those rows we fall back to "any finding in this file at all".
    ACCOUNT_LEVEL_KEYWORDS = ("(account)", "no ", "missing", "policy")

    for cloud in clouds:
        planted = ground_truth[cloud]
        ranges = resource_ranges[cloud]

        for tool in tools:
            tool_findings = findings.get((tool, cloud), [])
            file_index = _index_findings_by_file(tool_findings)

            caught = 0
            missed = []
            for row in planted:
                resource = row["resource"]
                expected_file = row["file"]
                rng = ranges.get(resource)

                hit = False
                if rng:
                    rng_file, start, end = rng
                    candidate_lines = file_index.get(rng_file, [])
                    # ±2 line slack to handle scanners that report on the
                    # attribute line just inside / outside the block.
                    hit = any(start - 2 <= ln <= end + 2 for ln in candidate_lines)
                else:
                    # Account-level row — match anything in the same file.
                    candidate_lines = file_index.get(expected_file, [])
                    if any(k in row["resource"].lower() or k in row["issue"].lower()
                           for k in ACCOUNT_LEVEL_KEYWORDS):
                        hit = bool(candidate_lines)
                    # Last resort: substring rule_id match in this file.
                    if not hit:
                        for v in tool_findings:
                            f = Path((v.get("location") or {}).get("file", "")).name
                            if f != expected_file:
                                continue
                            for ident in v.get("identifiers") or []:
                                rid = (ident.get("value") or "").lower()
                                for expected in row["expected_check_ids"]:
                                    e = expected.lower()
                                    if e and (e in rid or rid in e):
                                        hit = True
                                        break
                                if hit:
                                    break
                            if hit:
                                break

                if hit:
                    caught += 1
                else:
                    missed.append(
                        {
                            "num": row["num"],
                            "file": expected_file,
                            "resource": resource,
                            "issue": row["issue"],
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
    parser.add_argument("--terraform-aws", type=Path, required=True)
    parser.add_argument("--terraform-azure", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    ground_truth = {
        "aws": parse_ground_truth(args.terraform_aws / "EXPECTED_FINDINGS.md"),
        "azure": parse_ground_truth(args.terraform_azure / "EXPECTED_FINDINGS.md"),
    }
    if not ground_truth["aws"] or not ground_truth["azure"]:
        print("ERROR: failed to parse ground-truth tables")
        return 1

    resource_ranges = {
        "aws": parse_resource_ranges(args.terraform_aws),
        "azure": parse_resource_ranges(args.terraform_azure),
    }
    print(
        f"Parsed {len(resource_ranges['aws'])} AWS resources, "
        f"{len(resource_ranges['azure'])} Azure resources"
    )

    findings = _findings_by_tool(args.reports)
    if not findings:
        print(f"ERROR: no reports found under {args.reports}")
        return 1

    result = compute_recall(ground_truth, resource_ranges, findings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2))

    print("Recall by tool:")
    for tool in result["tools"]:
        data = result["per_tool"][tool]
        print(f"  {tool:10s}  {data['caught']:>3}/{data['planted']}  ({data['recall']:.0%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
