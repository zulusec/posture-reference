"""Check: S3 buckets reachable by the public internet."""

from __future__ import annotations

from botocore.exceptions import ClientError

from posture.finding import Finding, Severity

CHECK_ID = "S3.PUBLIC_ACCESS"

_BPA_SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

_NO_CONFIG_CODES = frozenset({"NoSuchPublicAccessBlockConfiguration"})
_NO_POLICY_CODES = frozenset({"NoSuchBucketPolicy", "NoSuchBucketPolicyStatus"})


def run(s3) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        findings.extend(_check_bucket(s3, bucket["Name"]))
    return findings


def _check_bucket(s3, name: str) -> list[Finding]:
    findings: list[Finding] = []

    config = _public_access_block(s3, name)
    disabled = sorted(
        setting for setting in _BPA_SETTINGS if not config.get(setting, False)
    )
    if disabled:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                resource_id=name,
                rule_key="block-public-access",
                severity=Severity.HIGH,
                title="Block Public Access is not fully enabled",
                evidence="disabled settings: " + ", ".join(disabled),
            )
        )

    if _policy_is_public(s3, name):
        findings.append(
            Finding(
                check_id=CHECK_ID,
                resource_id=name,
                rule_key="policy-public",
                severity=Severity.HIGH,
                title="Bucket policy grants access to everyone",
                evidence="get_bucket_policy_status reports PolicyStatus.IsPublic true",
            )
        )

    return findings


def _public_access_block(s3, name: str) -> dict:
    """Absent configuration means nothing is blocked, so return an empty mapping."""
    try:
        response = s3.get_public_access_block(Bucket=name)
    except ClientError as error:
        if error.response["Error"]["Code"] in _NO_CONFIG_CODES:
            return {}
        raise
    return response.get("PublicAccessBlockConfiguration", {})


def _policy_is_public(s3, name: str) -> bool:
    try:
        response = s3.get_bucket_policy_status(Bucket=name)
    except ClientError as error:
        if error.response["Error"]["Code"] in _NO_POLICY_CODES:
            return False
        raise
    return bool(response.get("PolicyStatus", {}).get("IsPublic", False))
