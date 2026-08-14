"""Determinism is the product claim, so it is asserted mechanically.

If any of these fail, the tool is no longer safe to put in front of an
assessor, because a finding that cannot be reproduced cannot be evidence.

The in-process checks below prove determinism within a single interpreter,
but they cannot catch a value that is constant for the life of one process
yet varies between invocations (an import-time UUID or timestamp, for
example). The cross-process checks close that gap by shelling out to the
installed console script twice, the way a reader running the README's
example actually would.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

from posture import cli, render
from posture.demo.loader import DEMO_ACCOUNT_ID, DemoEc2, DemoS3, DemoS3Control
from posture.runner import run_all

_FIXTURES = Path(__file__).resolve().parents[1] / "src" / "posture" / "demo" / "fixtures"


def _fixture(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _posture_command() -> list[str]:
    script = shutil.which("posture")
    if script is None:
        candidate = Path(sys.executable).parent / "posture"
        if candidate.exists():
            script = str(candidate)
    assert script, "posture console script not found; install with `pip install -e .`"
    return [script]


def _run_posture(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(_posture_command() + list(args), capture_output=True, check=False)


def _demo_run(s3=None, ec2=None):
    """The same client set the CLI builds for --demo, so these tests exercise
    the path a reader running the README's example actually takes."""
    return run_all(s3 or DemoS3(), ec2 or DemoEc2(), DemoS3Control(), DEMO_ACCOUNT_ID)


def _demo_findings_json(**kwargs) -> str:
    return render.findings_json(_demo_run(**kwargs).findings)


def test_repeated_runs_are_byte_identical():
    assert _demo_findings_json() == _demo_findings_json()


def test_the_demo_run_reads_everything_it_claims_to():
    """A demo that quietly started recording gaps would still print findings,
    and those findings would no longer be a complete answer for the fixture."""
    assert _demo_run().errors == []


def test_output_is_independent_of_bucket_order():
    data = _fixture("s3.json")
    data["list_buckets"] = {"Buckets": list(reversed(data["list_buckets"]["Buckets"]))}
    shuffled = _demo_findings_json(s3=DemoS3(data))
    assert shuffled == _demo_findings_json()


def test_output_is_independent_of_security_group_order():
    data = _fixture("ec2.json")
    groups = data["describe_security_groups"]["SecurityGroups"]
    data["describe_security_groups"] = {"SecurityGroups": list(reversed(groups))}
    shuffled = _demo_findings_json(ec2=DemoEc2(data))
    assert shuffled == _demo_findings_json()


def test_cli_demo_json_is_byte_identical_across_runs(capsys):
    cli.main(["--demo", "--json"])
    first = capsys.readouterr().out
    cli.main(["--demo", "--json"])
    second = capsys.readouterr().out
    assert first == second


def test_findings_carry_no_volatile_fields():
    findings = _demo_run().findings
    assert findings, "fixtures must produce findings for this test to mean anything"
    expected_keys = {"check_id", "resource_id", "rule_key", "severity", "title", "evidence"}
    for finding in findings:
        assert set(finding.to_dict()) == expected_keys


def test_cli_json_output_is_byte_identical_across_processes():
    first = _run_posture("--demo", "--json")
    second = _run_posture("--demo", "--json")
    assert first.returncode == 0
    assert second.returncode == 0
    assert first.stdout
    assert first.stdout == second.stdout


def test_cli_table_output_is_byte_identical_across_processes():
    first = _run_posture("--demo")
    second = _run_posture("--demo")
    assert first.returncode == 0
    assert second.returncode == 0
    assert first.stdout
    assert first.stdout == second.stdout
