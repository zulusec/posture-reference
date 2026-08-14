"""Run every check and merge the results into one sorted answer.

The checks are independent, and the runner is the last place that can keep
them that way. A denied S3 listing must not cost the reader the EC2 answer,
so a check that fails outright is recorded as a gap and the other one still
runs.
"""

from __future__ import annotations

from posture.checks import open_security_groups, public_buckets
from posture.finding import Finding, sort_findings
from posture.result import ACCOUNT_SCOPE, ScanError, ScanResult, describe_error, sort_errors


def run_all(s3, ec2, s3control, account_id: str | None) -> ScanResult:
    findings: list[Finding] = []
    errors: list[ScanError] = []

    checks = (
        (public_buckets.CHECK_ID, lambda: public_buckets.run(s3, s3control, account_id)),
        (open_security_groups.CHECK_ID, lambda: open_security_groups.run(ec2)),
    )
    for check_id, invoke in checks:
        try:
            result = invoke()
        except Exception as error:  # noqa: BLE001
            # Deliberately broad: this is the boundary that keeps one check's
            # failure, including a bug in the check itself, from deciding
            # whether the other check gets to report. The failure is recorded
            # and printed, never swallowed.
            errors.append(
                ScanError(
                    check_id=check_id,
                    resource_id=ACCOUNT_SCOPE,
                    operation="run",
                    detail=describe_error(error),
                )
            )
        else:
            findings.extend(result.findings)
            errors.extend(result.errors)

    return ScanResult(sort_findings(findings), sort_errors(errors))
