#!/usr/bin/env python3
"""Merge per-tool GitLab SAST reports into a comparison dataset.

Reads every `gl-sast-report-<tool>-<cloud>.json` under an input directory and
emits:

  - comparison.json   — structured dataset for downstream UI consumption
  - summary.md        — markdown table for $GITHUB_STEP_SUMMARY

Usage:
    python aggregate.py --input ./reports --output ./out
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any


REPORT_RE = re.compile(r"gl-sast-report-(?P<tool>[^-]+)-(?P<cloud>[^.]+)\.json$")
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]


def _basename(file: str) -> str:
    """Strip directory prefix so per-tool path differences (e.g. Trivy
    reporting `compute.tf` vs Checkov reporting `terraform/aws/compute.tf`)
    don't fragment the overlap matrix."""
    return Path(file).name


def _load_reports(input_dir: Path) -> dict[tuple[str, str], dict]:
    """Return {(tool, cloud): report_json}."""
    reports: dict[tuple[str, str], dict] = {}
    for path in sorted(input_dir.rglob("gl-sast-report-*.json")):
        m = REPORT_RE.search(path.name)
        if not m:
            continue
        try:
            reports[(m["tool"], m["cloud"])] = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            print(f"WARN: skipping malformed report {path}: {exc}")
    return reports


def _finding_key(vuln: dict) -> tuple[str, int, str]:
    """Stable cross-tool key for a finding: (file_basename, start_line, rule_id)."""
    loc = vuln.get("location", {}) or {}
    ident = (vuln.get("identifiers") or [{}])[0]
    return (
        _basename(loc.get("file", "?")),
        int(loc.get("start_line", 0)),
        ident.get("value") or vuln.get("name", "?"),
    )


def _resource_key(vuln: dict) -> tuple[str, int]:
    """Coarser key — same file:line regardless of which rule fired."""
    loc = vuln.get("location", {}) or {}
    return (_basename(loc.get("file", "?")), int(loc.get("start_line", 0)))


def _severity_counts(vulns: list[dict]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for v in vulns:
        sev = v.get("severity", "Unknown")
        if sev not in counts:
            sev = "Unknown"
        counts[sev] += 1
    counts["total"] = sum(counts[s] for s in SEVERITIES)
    return counts


def build_comparison(reports: dict[tuple[str, str], dict]) -> dict[str, Any]:
    tools = sorted({tool for tool, _ in reports})
    clouds = sorted({cloud for _, cloud in reports})

    # Per-tool, per-cloud summary.
    summary: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
    for (tool, cloud), report in reports.items():
        vulns = report.get("vulnerabilities", []) or []
        summary[tool][cloud] = _severity_counts(vulns)

    # Resource-level view (which tools flagged which file:line, per cloud).
    by_resource: dict[str, list[dict]] = defaultdict(list)
    for cloud in clouds:
        seen: dict[tuple[str, int], dict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        for (tool, c), report in reports.items():
            if c != cloud:
                continue
            for v in report.get("vulnerabilities", []) or []:
                key = _resource_key(v)
                seen[key]["tools"].add(tool)
                ident = (v.get("identifiers") or [{}])[0]
                seen[key]["rules"].add(ident.get("value") or v.get("name", "?"))
        for (file, line), data in sorted(seen.items()):
            found_by = sorted(data["tools"])
            by_resource[cloud].append(
                {
                    "file": file,
                    "line": line,
                    "found_by": found_by,
                    "missed_by": [t for t in tools if t not in found_by],
                    "rule_ids": sorted(data["rules"]),
                }
            )

    # Unique findings (file:line:rule only one tool reported).
    unique: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for cloud in clouds:
        finding_owners: dict[tuple[str, int, str], set[str]] = defaultdict(set)
        finding_meta: dict[tuple[str, int, str], dict] = {}
        for (tool, c), report in reports.items():
            if c != cloud:
                continue
            for v in report.get("vulnerabilities", []) or []:
                k = _finding_key(v)
                finding_owners[k].add(tool)
                finding_meta.setdefault(k, v)
        for k, owners in finding_owners.items():
            if len(owners) == 1:
                tool = next(iter(owners))
                meta = finding_meta[k]
                unique[tool][cloud].append(
                    {
                        "file": k[0],
                        "line": k[1],
                        "rule_id": k[2],
                        "severity": meta.get("severity", "Unknown"),
                        "name": meta.get("name", ""),
                    }
                )

    # Overlap matrix: |A ∩ B| at the coarser (cloud, file_basename, line)
    # grain — rule_id is excluded because each scanner has its own naming
    # convention (CKV_AWS_24 vs AWS-0107 vs terraform.aws.security.*) and
    # the question we care about is "did both tools flag the same source
    # location", not "did both tools use the same rule name for it".
    overlap: dict[str, dict[str, int]] = {a: {b: 0 for b in tools} for a in tools}
    per_tool_locations: dict[str, set[tuple[str, str, int]]] = defaultdict(set)
    for (tool, cloud), report in reports.items():
        for v in report.get("vulnerabilities", []) or []:
            f, l = _resource_key(v)
            per_tool_locations[tool].add((cloud, f, l))
    for a, b in combinations(tools, 2):
        common = len(per_tool_locations[a] & per_tool_locations[b])
        overlap[a][b] = common
        overlap[b][a] = common
    for t in tools:
        overlap[t][t] = len(per_tool_locations[t])

    return {
        "tools": tools,
        "clouds": clouds,
        "summary": summary,
        "by_resource": by_resource,
        "unique_findings": unique,
        "overlap_matrix": overlap,
        "totals": {
            tool: sum(per_cloud["total"] for per_cloud in cloud_map.values())
            for tool, cloud_map in summary.items()
        },
    }


def render_summary_md(comparison: dict[str, Any]) -> str:
    tools = comparison["tools"]
    clouds = comparison["clouds"]

    lines = ["## IaC Security Bake-Off — Summary", ""]
    lines.append(
        "| Tool | "
        + " | ".join(f"{c.upper()} total" for c in clouds)
        + " | Critical | High | Medium | Low | Info |"
    )
    lines.append("|---|" + "---|" * (len(clouds) + 5))

    for tool in tools:
        per_cloud = comparison["summary"][tool]
        totals_per_cloud = [str(per_cloud.get(c, {}).get("total", 0)) for c in clouds]
        critical = sum(per_cloud.get(c, {}).get("Critical", 0) for c in clouds)
        high = sum(per_cloud.get(c, {}).get("High", 0) for c in clouds)
        medium = sum(per_cloud.get(c, {}).get("Medium", 0) for c in clouds)
        low = sum(per_cloud.get(c, {}).get("Low", 0) for c in clouds)
        info = sum(per_cloud.get(c, {}).get("Info", 0) for c in clouds)
        lines.append(
            f"| **{tool}** | "
            + " | ".join(totals_per_cloud)
            + f" | {critical} | {high} | {medium} | {low} | {info} |"
        )

    lines += ["", "### Unique findings (only one tool flagged)", ""]
    for tool in tools:
        per_cloud = comparison["unique_findings"].get(tool, {})
        total = sum(len(v) for v in per_cloud.values())
        lines.append(f"- **{tool}**: {total} unique findings across {len(per_cloud)} clouds")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Directory of reports")
    parser.add_argument("--output", type=Path, required=True, help="Output directory")
    args = parser.parse_args()

    reports = _load_reports(args.input)
    if not reports:
        print(f"ERROR: no gl-sast-report-*.json files found under {args.input}")
        return 1

    comparison = build_comparison(reports)
    args.output.mkdir(parents=True, exist_ok=True)

    (args.output / "comparison.json").write_text(json.dumps(comparison, indent=2, default=list))
    (args.output / "summary.md").write_text(render_summary_md(comparison))

    print(
        f"Aggregated {len(reports)} reports → {args.output}/comparison.json "
        f"({len(comparison['tools'])} tools, {len(comparison['clouds'])} clouds)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
