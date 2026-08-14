"""Serialization of findings.

findings_json is the surface the determinism test compares. It excludes run
metadata on purpose, because metadata legitimately varies between runs while
findings must not.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from posture.finding import Finding

_JSON_ARGS = {"indent": 2, "sort_keys": True, "separators": (",", ": ")}


def findings_json(findings: Iterable[Finding]) -> str:
    return json.dumps([finding.to_dict() for finding in findings], **_JSON_ARGS) + "\n"


def to_json(findings: Iterable[Finding], metadata: dict) -> str:
    payload = {
        "metadata": metadata,
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, **_JSON_ARGS) + "\n"


def to_table(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    if not findings:
        return "No findings.\n"

    lines = []
    for finding in findings:
        lines.append(f"{finding.severity.value:<6}  {finding.check_id}  {finding.resource_id}")
        lines.append(f"        {finding.title}")
        lines.append(f"        {finding.evidence}")
        lines.append("")
    return "\n".join(lines)
