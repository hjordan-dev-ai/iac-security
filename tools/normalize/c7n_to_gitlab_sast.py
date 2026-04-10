#!/usr/bin/env python3
"""Convert c7n-left JSON output → GitLab SAST JSON.

c7n-left `--output json` emits a newline-delimited JSON stream (one object per
finding). Each object looks like:

    {
      "policy": {"name": "sg-ssh-open", "resource": "terraform.aws_security_group", ...},
      "resource": {"id": "aws_security_group.app", "__tfmeta": {"filename": "compute.tf", "line_start": 10, "line_end": 49}},
      "file_path": "compute.tf",
      "file_line_start": 10,
      "file_line_end": 49,
      "code_block": [...],
      "severity": "critical"
    }

The exact shape varies across c7n-left versions. This script handles the
fields robustly, falling back to defaults for anything missing.

Usage:
    python c7n_to_gitlab_sast.py <input.json> <output.json>
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from normalize.schema import (  # noqa: E402
    Analyzer,
    GitLabSASTReport,
    Identifier,
    Location,
    Scan,
    Scanner,
    Vendor,
    Vulnerability,
)


SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def _stable_id(policy_name: str, file: str, line: int) -> str:
    return hashlib.sha256(f"c7n-left|{policy_name}|{file}|{line}".encode()).hexdigest()


def _parse_ndjson(text: str) -> list[dict]:
    """Parse newline-delimited JSON. Some c7n-left versions wrap results in
    an array; others emit one JSON object per line."""
    text = text.strip()
    if not text:
        return []
    # Try parsing as a single JSON array first.
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Might be a wrapper with a "results" key.
            if "results" in data:
                return data["results"]
            return [data]
    except json.JSONDecodeError:
        pass
    # Fall back to newline-delimited.
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def convert(findings: list[dict], started: str, ended: str) -> GitLabSASTReport:
    scanner = Scanner(
        id="c7n-left",
        name="Cloud Custodian (c7n-left)",
        version="unknown",
        vendor=Vendor(name="Cloud Custodian / Stacklet"),
    )
    analyzer = Analyzer(
        id="c7n-left",
        name="Cloud Custodian (c7n-left)",
        version="unknown",
        vendor=Vendor(name="Cloud Custodian / Stacklet"),
    )
    scan = Scan(
        scanner=scanner,
        analyzer=analyzer,
        start_time=started,
        end_time=ended,
        status="success",
    )

    vulns: list[Vulnerability] = []
    for finding in findings:
        policy = finding.get("policy") or {}
        resource = finding.get("resource") or {}
        tfmeta = resource.get("__tfmeta") or {}

        policy_name = policy.get("name") or "unknown"
        description = policy.get("description") or policy_name

        # File and line info — c7n-left puts these in multiple places.
        file = (
            finding.get("file_path")
            or tfmeta.get("filename")
            or resource.get("filename")
            or "unknown"
        )
        start_line = int(
            finding.get("file_line_start")
            or tfmeta.get("line_start")
            or 1
        )
        end_line_raw = (
            finding.get("file_line_end")
            or tfmeta.get("line_end")
        )
        end_line = int(end_line_raw) if end_line_raw else None

        severity_raw = (
            finding.get("severity")
            or policy.get("metadata", {}).get("severity")
            or "medium"
        )
        severity = SEVERITY_MAP.get(severity_raw.lower(), "Medium")

        vulns.append(
            Vulnerability(
                id=_stable_id(policy_name, file, start_line),
                category="sast",
                name=policy_name,
                message=description,
                description=description,
                severity=severity,
                scanner=scanner,
                location=Location(
                    file=file,
                    start_line=start_line,
                    end_line=end_line,
                ),
                identifiers=[
                    Identifier(
                        type="c7n_left_policy",
                        name=policy_name,
                        value=policy_name,
                    )
                ],
            )
        )

    return GitLabSASTReport(scan=scan, vulnerabilities=vulns)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="c7n-left JSON output")
    parser.add_argument("output", type=Path, help="GitLab SAST JSON output")
    parser.add_argument("--start-time", default=_now())
    parser.add_argument("--end-time", default=_now())
    args = parser.parse_args()

    findings = _parse_ndjson(args.input.read_text())
    report = convert(findings, started=args.start_time, ended=args.end_time)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report.to_dict(), indent=2))
    print(
        f"Wrote {len(report.vulnerabilities)} vulnerabilities to {args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
