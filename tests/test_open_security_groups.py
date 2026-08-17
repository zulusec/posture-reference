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


def _ranges(from_port, to_port, *cidrs):
    return {
        "IpProtocol": "tcp",
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": [{"CidrIp": cidr} for cidr in cidrs],
    }


def test_two_halves_of_the_internet_are_the_whole_internet():
    """0.0.0.0/1 and 128.0.0.0/1 on one rule is 0.0.0.0/0 written in two
    lines. A string comparison against "0.0.0.0/0" reports that group clean."""
    permission = _ranges(22, 22, "0.0.0.0/1", "128.0.0.0/1")
    findings = _run(FakeEc2([_group(permissions=[permission])]))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_key == "tcp:22-22:0.0.0.0/0"
    assert findings[0].evidence == (
        "protocol tcp, ports 22 to 22, source 0.0.0.0/1, 128.0.0.0/1, "
        "together covering 0.0.0.0/0"
    )


def test_the_two_halves_are_reported_whatever_order_they_arrive_in():
    permission = _ranges(22, 22, "128.0.0.0/1", "0.0.0.0/1")
    findings = _run(FakeEc2([_group(permissions=[permission])]))
    assert len(findings) == 1
    assert findings[0].rule_key == "tcp:22-22:0.0.0.0/0"
    assert "0.0.0.0/1, 128.0.0.0/1" in findings[0].evidence


def test_many_ranges_that_add_up_to_everything_are_reported():
    permission = _ranges(22, 22, "0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1")
    findings = _run(FakeEc2([_group(permissions=[permission])]))
    assert len(findings) == 1
    assert findings[0].rule_key == "tcp:22-22:0.0.0.0/0"


def test_half_the_internet_on_its_own_is_not_reported():
    """The finding says "from anywhere" and the claim is meant to be provable
    rather than estimated. A wide range that leaves addresses out is a
    different finding this tool does not make."""
    permission = _ranges(22, 22, "0.0.0.0/1")
    assert _run(FakeEc2([_group(permissions=[permission])])) == []


def test_two_halves_of_the_ipv6_internet_are_reported():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "Ipv6Ranges": [{"CidrIpv6": "::/1"}, {"CidrIpv6": "8000::/1"}],
    }
    findings = _run(FakeEc2([_group(permissions=[permission])]))
    assert len(findings) == 1
    assert findings[0].rule_key == "tcp:22-22:::/0"
    assert "together covering ::/0" in findings[0].evidence


def test_the_same_open_range_listed_twice_is_one_finding():
    permission = _ranges(22, 22, "0.0.0.0/0", "0.0.0.0/0")
    findings = _run(FakeEc2([_group(permissions=[permission])]))
    assert len(findings) == 1
    assert findings[0].rule_key == "tcp:22-22:0.0.0.0/0"


def test_an_unreadable_cidr_is_recorded_rather_than_dropped():
    """A source this check cannot parse is a source it did not assess.
    Skipping it quietly would let a group come back clean on a range nobody
    looked at, which is the one result this tool must not produce."""
    permission = _ranges(22, 22, "10.0.0/8")
    result = open_security_groups.run(FakeEc2([_group(permissions=[permission])]))
    assert result.findings == []
    assert len(result.errors) == 1
    assert result.errors[0].resource_id == "sg-1"
    assert result.errors[0].detail == "unreadable CIDR 10.0.0/8"
    assert not result.complete


def test_an_unreadable_cidr_does_not_cost_the_other_ranges():
    permission = _ranges(22, 22, "0.0.0.0/0", "not-a-cidr")
    result = open_security_groups.run(FakeEc2([_group(permissions=[permission])]))
    assert [f.rule_key for f in result.findings] == ["tcp:22-22:0.0.0.0/0"]
    assert len(result.errors) == 1


def test_an_ipv6_range_filed_under_the_ipv4_key_is_recorded():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "::/0"}],
    }
    result = open_security_groups.run(FakeEc2([_group(permissions=[permission])]))
    assert result.findings == []
    assert [e.detail for e in result.errors] == ["unreadable CIDR ::/0"]


def test_a_peer_security_group_source_is_not_a_finding():
    """UserIdGroupPairs name another security group. That is a source, but it
    is never the internet, so it is outside this check rather than missed."""
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "UserIdGroupPairs": [{"GroupId": "sg-peer"}],
    }
    result = open_security_groups.run(FakeEc2([_group(permissions=[permission])]))
    assert result.findings == []
    assert result.errors == []


def test_a_prefix_list_source_is_not_examined():
    """Executable form of the limitation the README states. A managed prefix
    list can contain 0.0.0.0/0 and reading one needs a permission the minimal
    policy does not grant, so this run is not a statement about it."""
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "PrefixListIds": [{"PrefixListId": "pl-0123456789abcdef0"}],
    }
    result = open_security_groups.run(FakeEc2([_group(permissions=[permission])]))
    assert result.findings == []
    assert result.errors == []
