"""Check: security groups accepting inbound traffic from anywhere.

DescribeSecurityGroups returns at most 1000 groups per page and the default
quota is 2500 per VPC, so the listing is paginated. Reading one page would
report a multi-VPC account clean while its exposed group sat on page two.

"From anywhere" is arithmetic on the ranges, not a match on the string
0.0.0.0/0. A rule listing 0.0.0.0/1 and 128.0.0.0/1 is the whole internet
written in two lines, and a string comparison calls that group restricted.
The same pair exists on the v6 side as ::/1 and 8000::/1.

Two other kinds of source are deliberately not read, and the README says so
rather than leaving a reader to work it out. A managed prefix list can
contain 0.0.0.0/0, and resolving one needs ec2:GetManagedPrefixListEntries,
which is not in the minimal policy this tool documents. A peer security
group is a source but never the internet, so it sits outside this check's
subject rather than being missed by it.
"""

from __future__ import annotations

import ipaddress
from typing import NamedTuple

from botocore.exceptions import BotoCoreError, ClientError

from posture.finding import Finding, Severity
from posture.paging import paginate
from posture.result import ACCOUNT_SCOPE, ScanError, ScanResult, describe_error

CHECK_ID = "EC2.OPEN_SECURITY_GROUP"

_ALL_PROTOCOLS = "-1"

# Every address in a family, with the response key and field that carries
# that family's ranges. A finding names the whole space as its source
# whichever way the rule spelled it, so the rule_key a client tracks between
# runs does not move when the same exposure is rewritten.
_FAMILIES = (
    ("IpRanges", "CidrIp", ipaddress.IPv4Network("0.0.0.0/0")),
    ("Ipv6Ranges", "CidrIpv6", ipaddress.IPv6Network("::/0")),
)

# Ports where exposure to the whole internet is materially worse: remote
# administration and database engines.
_SENSITIVE_PORTS = (22, 3389, 1433, 3306, 5432, 6379, 27017)


class _OpenSource(NamedTuple):
    """One family a permission opens completely, and how it was written."""

    everything: str
    ranges: list[str]


def run(ec2) -> ScanResult:
    findings: list[Finding] = []
    errors: list[ScanError] = []
    try:
        for group in paginate(ec2.describe_security_groups, "NextToken", "SecurityGroups"):
            group_id = group["GroupId"]
            for permission in group.get("IpPermissions", []):
                sources, unreadable = _open_sources(permission)
                for source in sources:
                    findings.append(_build_finding(group_id, permission, source))
                for value in unreadable:
                    # A range that could not be parsed is a range nobody
                    # assessed. Dropping it quietly would let the group come
                    # back clean on a source no one looked at.
                    errors.append(
                        ScanError(
                            check_id=CHECK_ID,
                            resource_id=group_id,
                            operation="DescribeSecurityGroups",
                            detail=f"unreadable CIDR {value}",
                        )
                    )
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


def _open_sources(permission: dict) -> tuple[list[_OpenSource], list[str]]:
    """The families this permission opens completely, and the ranges it could
    not read. Ranges are unioned per family before the comparison."""
    sources: list[_OpenSource] = []
    unreadable: list[str] = []
    for key, field, everything in _FAMILIES:
        networks = []
        for entry in permission.get(key, []):
            value = entry.get(field)
            if value is None:
                continue
            try:
                # The family-specific constructor, so a v6 range filed under
                # the v4 key is reported as unread rather than silently
                # dropped out of the union it belongs to.
                networks.append(type(everything)(value, strict=False))
            except ValueError:
                unreadable.append(value)
        covering = _covers_everything(networks, everything)
        if covering is not None:
            sources.append(_OpenSource(str(everything), covering))
    return sources, unreadable


def _covers_everything(networks: list, everything) -> list[str] | None:
    """The ranges that together cover the whole address space, or None.

    collapse_addresses merges adjacent and overlapping ranges, so the two
    halves of the internet come back as one entry equal to everything, and a
    range listed twice collapses to one finding rather than two identical
    ones.
    """
    if not networks:
        return None
    if list(ipaddress.collapse_addresses(networks)) != [everything]:
        return None
    ordered = sorted(
        set(networks), key=lambda network: (network.network_address, network.prefixlen)
    )
    return [str(network) for network in ordered]


def _port_range(permission: dict) -> tuple[int, int]:
    if permission.get("IpProtocol", _ALL_PROTOCOLS) == _ALL_PROTOCOLS:
        return (0, 65535)
    return (permission.get("FromPort", 0), permission.get("ToPort", 0))


def _covers_sensitive_port(low: int, high: int) -> bool:
    return any(low <= port <= high for port in _SENSITIVE_PORTS)


def _source_text(source: _OpenSource) -> str:
    """One range is reported as itself. Several are reported as themselves
    and as what they add up to, because "source 0.0.0.0/1" reads as half the
    internet and the finding is about the whole of it."""
    if source.ranges == [source.everything]:
        return source.everything
    return ", ".join(source.ranges) + f", together covering {source.everything}"


def _build_finding(group_id: str, permission: dict, source: _OpenSource) -> Finding:
    low, high = _port_range(permission)
    protocol = permission.get("IpProtocol", _ALL_PROTOCOLS)
    label = "all" if protocol == _ALL_PROTOCOLS else protocol
    sensitive = _covers_sensitive_port(low, high)
    return Finding(
        check_id=CHECK_ID,
        resource_id=group_id,
        rule_key=f"{label}:{low}-{high}:{source.everything}",
        severity=Severity.HIGH if sensitive else Severity.MEDIUM,
        title="Security group allows inbound access from anywhere",
        evidence=f"protocol {label}, ports {low} to {high}, source {_source_text(source)}",
    )
