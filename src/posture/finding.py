"""The finding record and its deterministic ordering."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


_SEVERITY_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


@dataclass(frozen=True)
class Finding:
    """A single posture finding.

    Every field is stable for a given input. Nothing here carries a
    timestamp, a duration, or a generated identifier, because findings are
    compared byte for byte to prove the tool is deterministic.
    """

    check_id: str
    resource_id: str
    rule_key: str
    severity: Severity
    title: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "resource_id": self.resource_id,
            "rule_key": self.rule_key,
            "severity": self.severity.value,
            "title": self.title,
            "evidence": self.evidence,
        }

    @property
    def sort_key(self) -> tuple:
        return (
            _SEVERITY_RANK[self.severity],
            self.check_id,
            self.resource_id,
            self.rule_key,
        )


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Worst first, then stable keys. Independent of input order."""
    return sorted(findings, key=lambda finding: finding.sort_key)
