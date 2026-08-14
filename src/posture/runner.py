"""Run every check and return one sorted list of findings."""

from __future__ import annotations

from posture.checks import open_security_groups, public_buckets
from posture.finding import Finding, sort_findings


def run_all(s3, ec2, s3control, account_id: str | None) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(public_buckets.run(s3, s3control, account_id))
    findings.extend(open_security_groups.run(ec2))
    return sort_findings(findings)
