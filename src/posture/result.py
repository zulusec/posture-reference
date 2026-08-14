"""What a check produces: findings, plus the resources it could not read.

An assessor role gets told no. A bucket policy denies GetBucketPolicyStatus,
an SCP blocks a region, a listing throttles halfway through. There are two
honest responses and they are not the same one. Aborting the whole run on
the first denial throws away the other 199 buckets and the entirely
independent EC2 check. Swallowing the denial is worse, because a shorter
list of findings is indistinguishable from a cleaner account, and a tool
that reports clean when it is not does more damage than no tool at all.

So every unreadable resource is recorded and both output formats say so
plainly. An incomplete run must be obviously incomplete.

resource_id is the resource that could not be read, or ACCOUNT_SCOPE when
the failure was the listing or an account-wide call rather than one
resource.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from posture.finding import Finding

ACCOUNT_SCOPE = "account"


def describe_error(error: Exception) -> str:
    """A short, stable description of why a call failed.

    The AWS error code, not the botocore message: messages carry request ids
    that differ between runs, and output that changes between runs is what
    this tool exists to argue against.
    """
    if isinstance(error, ClientError):
        return error.response.get("Error", {}).get("Code") or "ClientError"
    return type(error).__name__


@dataclass(frozen=True)
class ScanError:
    """One thing the run could not read."""

    check_id: str
    resource_id: str
    operation: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "detail": self.detail,
        }

    @property
    def sort_key(self) -> tuple:
        return (self.check_id, self.resource_id, self.operation, self.detail)


def sort_errors(errors: Iterable[ScanError]) -> list[ScanError]:
    return sorted(errors, key=lambda error: error.sort_key)


@dataclass(frozen=True)
class ScanResult:
    """The result of one check, or of the whole run once they are merged."""

    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.errors
