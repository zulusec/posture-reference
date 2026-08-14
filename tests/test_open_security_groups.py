from posture.checks import open_security_groups
from posture.finding import Severity


class FakeEc2:
    def __init__(self, groups):
        self._groups = groups

    def describe_security_groups(self):
        return {"SecurityGroups": self._groups}


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
    assert open_security_groups.run(ec2) == []


def test_open_ssh_is_high():
    ec2 = FakeEc2([_group(permissions=[_tcp(22, 22)])])
    findings = open_security_groups.run(ec2)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].resource_id == "sg-1"
    assert findings[0].rule_key == "tcp:22-22:0.0.0.0/0"


def test_open_non_sensitive_port_is_medium():
    ec2 = FakeEc2([_group(permissions=[_tcp(8080, 8080)])])
    assert open_security_groups.run(ec2)[0].severity == Severity.MEDIUM


def test_range_covering_a_sensitive_port_is_high():
    ec2 = FakeEc2([_group(permissions=[_tcp(3000, 3400)])])
    assert open_security_groups.run(ec2)[0].severity == Severity.HIGH


def test_all_protocols_is_high_and_spans_every_port():
    permission = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    findings = open_security_groups.run(FakeEc2([_group(permissions=[permission])]))
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_key == "all:0-65535:0.0.0.0/0"


def test_open_ipv6_is_reported():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
    findings = open_security_groups.run(FakeEc2([_group(permissions=[permission])]))
    assert findings[0].rule_key == "tcp:22-22:::/0"


def test_both_ip_versions_produce_separate_findings():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
    findings = open_security_groups.run(FakeEc2([_group(permissions=[permission])]))
    assert len(findings) == 2
