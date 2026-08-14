"""Check: S3 buckets reachable by the public internet.

Block Public Access exists at two levels, the bucket and the account, and
the effective setting is the union of the two: a setting is enabled if the
bucket enables it or the account does. An account with account-level Block
Public Access fully on and no per-bucket configuration at all is a normal
and in fact preferred posture, so a check that reads only the bucket level
reports every bucket in such an account as exposed.
"""

from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

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

_BOTH_LEVELS = "bucket or account level"
_BUCKET_LEVEL_ONLY = "bucket level"


def run(s3, s3control, account_id: str | None) -> list[Finding]:
    """Check every bucket. Pass s3control and account_id to read account-level
    Block Public Access; pass None for either to skip it, which narrows the
    conclusion to the bucket level and says so in the evidence."""
    account_config, account_known = _account_public_access_block(s3control, account_id)
    findings: list[Finding] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        findings.extend(_check_bucket(s3, bucket["Name"], account_config, account_known))
    return findings


def _check_bucket(s3, name: str, account_config: dict, account_known: bool) -> list[Finding]:
    findings: list[Finding] = []

    config, configured = _public_access_block(s3, name)
    not_enabled = sorted(
        setting
        for setting in _BPA_SETTINGS
        if not (config.get(setting, False) or account_config.get(setting, False))
    )
    if not_enabled:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                resource_id=name,
                rule_key="block-public-access",
                severity=Severity.HIGH,
                title="Block Public Access is not fully enabled",
                evidence=_bpa_evidence(configured, account_known, not_enabled),
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


def _bpa_evidence(configured: bool, account_known: bool, not_enabled: list[str]) -> str:
    """Absent and partial are different facts about the client's account.

    Reporting "these four settings were set to false" for a bucket that
    carries no configuration at all is a claim the client can disprove by
    looking, which costs the whole report its credibility even where the
    conclusion was right.
    """
    subject = (
        "Block Public Access is configured on this bucket"
        if configured
        else "no Block Public Access configuration exists on this bucket"
    )
    scope = _BOTH_LEVELS if account_known else _BUCKET_LEVEL_ONLY
    return f"{subject}; not enabled at {scope}: " + ", ".join(not_enabled)


def _public_access_block(s3, name: str) -> tuple[dict, bool]:
    """Returns the bucket configuration and whether one exists at all."""
    try:
        response = s3.get_public_access_block(Bucket=name)
    except ClientError as error:
        if error.response["Error"]["Code"] in _NO_CONFIG_CODES:
            return {}, False
        raise
    return response.get("PublicAccessBlockConfiguration", {}), True


def _policy_is_public(s3, name: str) -> bool:
    try:
        response = s3.get_bucket_policy_status(Bucket=name)
    except ClientError as error:
        if error.response["Error"]["Code"] in _NO_POLICY_CODES:
            return False
        raise
    return bool(response.get("PolicyStatus", {}).get("IsPublic", False))


def _account_public_access_block(s3control, account_id: str | None) -> tuple[dict, bool]:
    """Returns the account configuration and whether we actually learned it.

    A missing account-level configuration is knowledge: nothing is enabled
    there. A denied or failed call is not, and the caller must narrow its
    claim rather than report bucket-level coverage as if it were both.
    """
    if s3control is None or account_id is None:
        return {}, False
    try:
        response = s3control.get_public_access_block(AccountId=account_id)
    except ClientError as error:
        if error.response["Error"]["Code"] in _NO_CONFIG_CODES:
            return {}, True
        return {}, False
    except BotoCoreError:
        return {}, False
    return response.get("PublicAccessBlockConfiguration", {}), True
