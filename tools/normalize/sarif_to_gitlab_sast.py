#!/usr/bin/env python3
"""Convert SARIF (Trivy / Snyk IaC) → GitLab SAST JSON.

Usage:
    python sarif_to_gitlab_sast.py <input.sarif> <output.json> \
        --scanner-id trivy --scanner-name Trivy --vendor Aqua

The output is suitable for upload as a GitLab CI `sast` report artifact.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

# Make the package importable when run as a script.
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


# SARIF level → GitLab severity. SARIF only has 4 levels; we lean conservative
# (treat "error" as Critical because IaC scanners reserve it for hard fails).
SARIF_LEVEL_TO_SEVERITY = {
    "error": "Critical",
    "warning": "Medium",
    "note": "Low",
    "none": "Info",
}

# Some scanners (Trivy) attach a `properties.security-severity` numeric score
# (CVSS-style). Use it when present for a finer-grained mapping.
def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def _stable_id(scanner_id: str, rule_id: str, file: str, line: int) -> str:
    payload = f"{scanner_id}|{rule_id}|{file}|{line}".encode()
    return hashlib.sha256(payload).hexdigest()


def _extract_rules(run: dict) -> dict[str, dict]:
    """Build ruleId → rule-metadata map from the SARIF tool driver."""
    driver = run.get("tool", {}).get("driver", {})
    rules = driver.get("rules") or []
    by_id: dict[str, dict] = {}
    for rule in rules:
        rid = rule.get("id")
        if rid:
            by_id[rid] = rule
    return by_id


def _normalize_path(uri: str) -> str:
    if uri.startswith("file://"):
        uri = uri[len("file://") :]
    return uri.lstrip("./")


def convert(
    sarif: dict,
    scanner_id: str,
    scanner_name: str,
    vendor: str,
    started: str,
    ended: str,
) -> GitLabSASTReport:
    scanner = Scanner(
        id=scanner_id,
        name=scanner_name,
        version=_driver_version(sarif),
        vendor=Vendor(name=vendor),
    )
    analyzer = Analyzer(
        id=scanner_id,
        name=scanner_name,
        version=scanner.version,
        vendor=Vendor(name=vendor),
    )
    scan = Scan(
        scanner=scanner,
        analyzer=analyzer,
        start_time=started,
        end_time=ended,
        status="success",
    )

    vulnerabilities: list[Vulnerability] = []
    for run in sarif.get("runs", []):
        rules = _extract_rules(run)
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or "unknown"
            rule_meta = rules.get(rule_id, {})

            # Severity: prefer security-severity score, fall back to level.
            sec_score = (
                result.get("properties", {}).get("security-severity")
                or rule_meta.get("properties", {}).get("security-severity")
            )
            if sec_score:
                try:
                    severity = _severity_from_score(float(sec_score))
                except (TypeError, ValueError):
                    severity = SARIF_LEVEL_TO_SEVERITY.get(
                        result.get("level", "warning"), "Medium"
                    )
            else:
                severity = SARIF_LEVEL_TO_SEVERITY.get(
                    result.get("level", "warning"), "Medium"
                )

            # Location.
            loc_obj = (result.get("locations") or [{}])[0]
            phys = loc_obj.get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "unknown")
            region = phys.get("region", {}) or {}
            start_line = int(region.get("startLine", 1))
            end_line = region.get("endLine")
            location = Location(
                file=_normalize_path(uri),
                start_line=start_line,
                end_line=int(end_line) if end_line else None,
            )

            # Message + description.
            msg = (result.get("message") or {}).get("text") or rule_id
            description = (
                rule_meta.get("fullDescription", {}).get("text")
                or rule_meta.get("shortDescription", {}).get("text")
                or msg
            )
            name = rule_meta.get("name") or rule_meta.get("shortDescription", {}).get(
                "text"
            ) or rule_id

            identifiers = [
                Identifier(
                    type=f"{scanner_id}_rule_id",
                    name=rule_id,
                    value=rule_id,
                    url=(rule_meta.get("helpUri") or None),
                )
            ]

            vulnerabilities.append(
                Vulnerability(
                    id=_stable_id(scanner_id, rule_id, location.file, start_line),
                    category="sast",
                    name=name,
                    message=msg,
                    description=description,
                    severity=severity,
                    scanner=scanner,
                    location=location,
                    identifiers=identifiers,
                )
            )

    return GitLabSASTReport(scan=scan, vulnerabilities=vulnerabilities)


def _driver_version(sarif: dict) -> str:
    runs = sarif.get("runs") or []
    if not runs:
        return "unknown"
    return runs[0].get("tool", {}).get("driver", {}).get("version", "unknown")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Input SARIF file")
    parser.add_argument("output", type=Path, help="Output GitLab SAST JSON file")
    parser.add_argument("--scanner-id", required=True)
    parser.add_argument("--scanner-name", required=True)
    parser.add_argument("--vendor", required=True)
    parser.add_argument("--start-time", default=_now())
    parser.add_argument("--end-time", default=_now())
    args = parser.parse_args()

    sarif = json.loads(args.input.read_text())
    report = convert(
        sarif,
        scanner_id=args.scanner_id,
        scanner_name=args.scanner_name,
        vendor=args.vendor,
        started=args.start_time,
        ended=args.end_time,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report.to_dict(), indent=2))
    print(
        f"Wrote {len(report.vulnerabilities)} vulnerabilities to {args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
