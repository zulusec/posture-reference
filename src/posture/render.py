"""Serialization of findings.

findings_json is the surface the determinism test compares. It excludes run
metadata on purpose, because metadata legitimately varies between runs while
findings must not.

Anything the run could not read is reported alongside the findings in both
formats. A reader must never be able to mistake a short list for a clean
account.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from posture.finding import Finding
from posture.result import ScanError

_JSON_ARGS = {"indent": 2, "sort_keys": True, "separators": (",", ": ")}


def findings_json(findings: Iterable[Finding]) -> str:
    return json.dumps([finding.to_dict() for finding in findings], **_JSON_ARGS) + "\n"


def to_json(findings: Iterable[Finding], metadata: dict, errors: Iterable[ScanError] = ()) -> str:
    payload = {
        "metadata": dict(metadata, errors=[error.to_dict() for error in errors]),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, **_JSON_ARGS) + "\n"


def to_table(findings: Iterable[Finding], errors: Iterable[ScanError] = ()) -> str:
    findings = list(findings)
    errors = list(errors)

    blocks = []
    if errors:
        blocks.append(_incomplete_block(errors))
    blocks.append(_findings_block(findings, incomplete=bool(errors)))
    return "\n".join(blocks)


def _incomplete_block(errors: list[ScanError]) -> str:
    # Reads, not resources. Isolation is per call, so one denied bucket costs
    # two reads, and a headline counting errors while saying "resources" would
    # print six above three named buckets. Being wrong about coverage in the
    # block whose whole job is coverage is the one mistake it cannot make.
    noun = "read" if len(errors) == 1 else "reads"
    lines = [
        f"INCOMPLETE RUN: {len(errors)} {noun} could not be completed.",
        "The findings below do not cover them. This is not a clean result",
        "for the resources listed here.",
        "",
    ]
    for error in errors:
        lines.append(
            f"        {error.check_id}  {error.resource_id}  "
            f"{error.operation}: {error.detail}"
        )
    lines.append("")
    return "\n".join(lines)


def _findings_block(findings: list[Finding], incomplete: bool) -> str:
    if not findings:
        if incomplete:
            return "No findings in what could be read.\n"
        return "No findings.\n"

    lines = []
    for finding in findings:
        lines.append(f"{finding.severity.value:<6}  {finding.check_id}  {finding.resource_id}")
        lines.append(f"        {finding.title}")
        lines.append(f"        {finding.evidence}")
        lines.append("")
    return "\n".join(lines)
