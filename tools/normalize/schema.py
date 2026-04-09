"""GitLab SAST report schema models.

Mirrors the structure documented at
https://gitlab.com/gitlab-org/security-products/security-report-schemas
(sast-report-format.json). Kept dependency-free (stdlib dataclasses) so the
normalize/aggregate tools can run inside any minimal CI image.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SCHEMA_VERSION = "15.0.7"

# GitLab severity vocabulary. Anything else is coerced to "Unknown".
ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info", "Unknown"}


@dataclass
class Vendor:
    name: str


@dataclass
class Scanner:
    id: str
    name: str
    version: str = "unknown"
    vendor: Vendor = field(default_factory=lambda: Vendor(name="unknown"))


@dataclass
class Analyzer:
    id: str
    name: str
    version: str = "unknown"
    vendor: Vendor = field(default_factory=lambda: Vendor(name="unknown"))


@dataclass
class Scan:
    scanner: Scanner
    analyzer: Analyzer
    start_time: str
    end_time: str
    status: str  # "success" | "failure"
    type: str = "sast"


@dataclass
class Identifier:
    type: str
    name: str
    value: str
    url: str | None = None


@dataclass
class Location:
    file: str
    start_line: int
    end_line: int | None = None


@dataclass
class Vulnerability:
    id: str
    category: str
    name: str
    message: str
    description: str
    severity: str
    scanner: Scanner
    location: Location
    identifiers: list[Identifier]
    cve: str = ""

    def __post_init__(self) -> None:
        if self.severity not in ALLOWED_SEVERITIES:
            self.severity = "Unknown"


@dataclass
class GitLabSASTReport:
    scan: Scan
    vulnerabilities: list[Vulnerability]
    version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return _strip_none(asdict(self))


def _strip_none(value: Any) -> Any:
    """Drop None values so the emitted JSON validates against the schema."""
    if isinstance(value, dict):
        return {k: _strip_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_none(v) for v in value]
    return value
