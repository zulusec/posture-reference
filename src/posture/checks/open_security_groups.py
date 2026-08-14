"""Check: security groups accepting inbound traffic from anywhere.

DescribeSecurityGroups returns at most 1000 groups per page and the default
quota is 2500 per VPC, so the listing is paginated. Reading one page would
report a multi-VPC account clean while its exposed group sat on page two.
"""

from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from posture.finding import Finding, Severity
from posture.paging import paginate
from posture.result import ACCOUNT_SCOPE, ScanError, ScanResult, describe_error

CHECK_ID = "EC2.OPEN_SECURITY_GROUP"

_OPEN_IPV4 = "0.0.0.0/0"
_OPEN_IPV6 = "::/0"
_ALL_PROTOCOLS = "-1"

# Ports where exposure to the whole internet is materially worse: remote
# administration and database engines.
_SENSITIVE_PORTS = (22, 3389, 1433, 3306, 5432, 6379, 27017)


def run(ec2) -> ScanResult:
    findings: list[Finding] = []
    errors: list[ScanError] = []
    try:
        for group in paginate(ec2.describe_security_groups, "NextToken", "SecurityGroups"):
            group_id = group["GroupId"]
            for permission in group.get("IpPermissions", []):
                for cidr in _open_sources(permission):
                    findings.append(_build_finding(group_id, permission, cidr))
    except (ClientError, BotoCoreError) as error:
        # Findings from the pages already read are still true. The recorded
        # error is what stops the shorter list reading as a cleaner account.
        errors.append(
            ScanError(
                check_id=CHECK_ID,
                resource_id=ACCOUNT_SCOPE,
                operation="DescribeSecurityGroups",
                detail=describe_error(error),
            )
        )
    return ScanResult(findings, errors)


def _open_sources(permission: dict) -> list[str]:
    sources = []
    for entry in permission.get("IpRanges", []):
        if entry.get("CidrIp") == _OPEN_IPV4:
            sources.append(_OPEN_IPV4)
    for entry in permission.get("Ipv6Ranges", []):
        if entry.get("CidrIpv6") == _OPEN_IPV6:
            sources.append(_OPEN_IPV6)
    return sources


def _port_range(permission: dict) -> tuple[int, int]:
    if permission.get("IpProtocol", _ALL_PROTOCOLS) == _ALL_PROTOCOLS:
        return (0, 65535)
    return (permission.get("FromPort", 0), permission.get("ToPort", 0))


def _covers_sensitive_port(low: int, high: int) -> bool:
    return any(low <= port <= high for port in _SENSITIVE_PORTS)


def _build_finding(group_id: str, permission: dict, cidr: str) -> Finding:
    low, high = _port_range(permission)
    protocol = permission.get("IpProtocol", _ALL_PROTOCOLS)
    label = "all" if protocol == _ALL_PROTOCOLS else protocol
    sensitive = _covers_sensitive_port(low, high)
    return Finding(
        check_id=CHECK_ID,
        resource_id=group_id,
        rule_key=f"{label}:{low}-{high}:{cidr}",
        severity=Severity.HIGH if sensitive else Severity.MEDIUM,
        title="Security group allows inbound access from anywhere",
        evidence=f"protocol {label}, ports {low} to {high}, source {cidr}",
    )
