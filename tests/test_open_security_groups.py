from botocore.exceptions import ClientError

from posture.checks import open_security_groups
from posture.finding import Severity


class FakeEc2:
    """Serves one group per page, the way DescribeSecurityGroups pages a real
    account. The check must follow NextToken to see the last group."""

    def __init__(self, groups, fail_after=None):
        self._groups = groups
        self._fail_after = fail_after
        self.calls = 0

    def describe_security_groups(self, NextToken=None):
        self.calls += 1
        start = int(NextToken) if NextToken else 0
        if self._fail_after is not None and start >= self._fail_after:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Describe")
        response = {"SecurityGroups": self._groups[start:start + 1]}
        if start + 1 < len(self._groups):
            response["NextToken"] = str(start + 1)
        return response


def _run(ec2):
    return open_security_groups.run(ec2).findings


def _group(group_id="sg-1", permissions=None):
    return {"GroupId": group_id, "IpPermissions": permissions or []}


def _tcp(from_port, to_port, cidr="0.0.0.0/0"):
    return {
        "IpProtocol": "tcp",
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": [{"CidrIp": cidr}],
    }


def test_restricted_source_produces_no_findings():
    ec2 = FakeEc2([_group(permissions=[_tcp(22, 22, cidr="203.0.113.0/24")])])
    assert _run(ec2) == []


def test_open_ssh_is_high():
    ec2 = FakeEc2([_group(permissions=[_tcp(22, 22)])])
    findings = _run(ec2)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].resource_id == "sg-1"
    assert findings[0].rule_key == "tcp:22-22:0.0.0.0/0"


def test_open_non_sensitive_port_is_medium():
    ec2 = FakeEc2([_group(permissions=[_tcp(8080, 8080)])])
    assert _run(ec2)[0].severity == Severity.MEDIUM


def test_range_covering_a_sensitive_port_is_high():
    ec2 = FakeEc2([_group(permissions=[_tcp(3000, 3400)])])
    assert _run(ec2)[0].severity == Severity.HIGH


def test_all_protocols_is_high_and_spans_every_port():
    permission = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    findings = _run(FakeEc2([_group(permissions=[permission])]))
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_key == "all:0-65535:0.0.0.0/0"


def test_open_ipv6_is_reported():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
    findings = _run(FakeEc2([_group(permissions=[permission])]))
    assert findings[0].rule_key == "tcp:22-22:::/0"


def test_both_ip_versions_produce_separate_findings():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
    findings = _run(FakeEc2([_group(permissions=[permission])]))
    assert len(findings) == 2


def test_findings_carry_the_check_id():
    ec2 = FakeEc2([_group(permissions=[_tcp(22, 22)])])
    findings = _run(ec2)
    assert findings
    assert {f.check_id for f in findings} == {"EC2.OPEN_SECURITY_GROUP"}


def test_a_group_on_a_later_page_is_still_found():
    """The unpaginated version reported this account clean. DescribeSecurityGroups
    caps at 1000 per page against a default quota of 2500 per VPC, so the one
    exposed group sitting past the first page is an ordinary account, not a
    contrived one."""
    groups = [
        _group("sg-quiet-1", [_tcp(22, 22, cidr="203.0.113.0/24")]),
        _group("sg-quiet-2", [_tcp(443, 443, cidr="203.0.113.0/24")]),
        _group("sg-exposed", [_tcp(3389, 3389)]),
    ]
    ec2 = FakeEc2(groups)
    findings = _run(ec2)
    assert ec2.calls == 3
    assert [f.resource_id for f in findings] == ["sg-exposed"]


def test_a_failure_partway_through_the_listing_is_recorded_not_raised():
    groups = [_group("sg-exposed", [_tcp(22, 22)]), _group("sg-unread", [_tcp(22, 22)])]
    result = open_security_groups.run(FakeEc2(groups, fail_after=1))
    assert [f.resource_id for f in result.findings] == ["sg-exposed"]
    assert len(result.errors) == 1
    assert result.errors[0].operation == "DescribeSecurityGroups"
    assert result.errors[0].detail == "AccessDenied"
