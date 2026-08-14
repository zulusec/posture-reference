"""Determinism is the product claim, so it is asserted mechanically.

If any of these fail, the tool is no longer safe to put in front of an
assessor, because a finding that cannot be reproduced cannot be evidence.
"""

import json
from pathlib import Path

from posture import cli, render
from posture.demo.loader import DemoEc2, DemoS3
from posture.runner import run_all

_FIXTURES = Path(__file__).resolve().parents[1] / "src" / "posture" / "demo" / "fixtures"


def _fixture(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _demo_findings_json() -> str:
    return render.findings_json(run_all(DemoS3(), DemoEc2()))


def test_repeated_runs_are_byte_identical():
    assert _demo_findings_json() == _demo_findings_json()


def test_output_is_independent_of_bucket_order():
    data = _fixture("s3.json")
    data["list_buckets"] = {"Buckets": list(reversed(data["list_buckets"]["Buckets"]))}
    shuffled = render.findings_json(run_all(DemoS3(data), DemoEc2()))
    assert shuffled == _demo_findings_json()


def test_output_is_independent_of_security_group_order():
    data = _fixture("ec2.json")
    groups = data["describe_security_groups"]["SecurityGroups"]
    data["describe_security_groups"] = {"SecurityGroups": list(reversed(groups))}
    shuffled = render.findings_json(run_all(DemoS3(), DemoEc2(data)))
    assert shuffled == _demo_findings_json()


def test_cli_demo_json_is_byte_identical_across_runs(capsys):
    cli.main(["--demo", "--json"])
    first = capsys.readouterr().out
    cli.main(["--demo", "--json"])
    second = capsys.readouterr().out
    assert first == second


def test_findings_carry_no_volatile_fields():
    findings = run_all(DemoS3(), DemoEc2())
    assert findings, "fixtures must produce findings for this test to mean anything"
    volatile = {"timestamp", "generated_at", "duration", "id", "uuid"}
    for finding in findings:
        assert not volatile & set(finding.to_dict())
