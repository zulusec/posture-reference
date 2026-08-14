import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

from posture import cli


def test_demo_json_is_valid_and_has_findings(capsys):
    assert cli.main(["--demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["metadata"]["mode"] == "demo"
    assert len(payload["findings"]) > 0


def test_demo_metadata_carries_no_timestamp(capsys):
    cli.main(["--demo", "--json"])
    metadata = json.loads(capsys.readouterr().out)["metadata"]
    assert "generated_at" not in metadata


def test_demo_table_output_is_human_readable(capsys):
    assert cli.main(["--demo"]) == 0
    out = capsys.readouterr().out
    assert "HIGH" in out
    assert "example-corp-customer-exports" in out


def test_demo_finds_the_seeded_public_bucket(capsys):
    cli.main(["--demo", "--json"])
    findings = json.loads(capsys.readouterr().out)["findings"]
    resources = {f["resource_id"] for f in findings}
    assert "example-corp-customer-exports" in resources
    assert "example-corp-audit-logs" not in resources


def test_demo_ranks_open_ssh_above_open_http_alt(capsys):
    cli.main(["--demo", "--json"])
    findings = json.loads(capsys.readouterr().out)["findings"]
    severities = [f["severity"] for f in findings]
    assert severities == sorted(severities, key=["HIGH", "MEDIUM", "LOW"].index)


def _raise(error):
    def fail(_region):
        raise error

    return fail


def test_missing_credentials_produce_one_line_and_a_nonzero_exit(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_live_clients", _raise(NoCredentialsError()))
    assert cli.main(["--region", "us-east-1"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "posture: no AWS credentials found. Configure credentials, or run with --demo.\n"
    )


def test_a_refused_api_call_produces_one_line_and_a_nonzero_exit(capsys, monkeypatch):
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCallerIdentity")
    monkeypatch.setattr(cli, "_live_clients", _raise(error))
    assert cli.main(["--region", "us-east-1"]) == 1
    captured = capsys.readouterr()
    assert captured.err.count("\n") == 1
    assert "AccessDenied" in captured.err


def test_an_unreachable_endpoint_produces_one_line_and_a_nonzero_exit(capsys, monkeypatch):
    error = EndpointConnectionError(endpoint_url="https://sts.us-east-1.amazonaws.com")
    monkeypatch.setattr(cli, "_live_clients", _raise(error))
    assert cli.main(["--region", "us-east-1"]) == 1
    captured = capsys.readouterr()
    assert captured.err.count("\n") == 1
    assert "us-east-1" in captured.err


def test_an_incomplete_run_exits_nonzero(capsys, monkeypatch):
    """Exit 0 is a claim that the account was assessed. A pipeline that reads
    it must not get that claim from a run that could not read three buckets."""
    original = cli._demo_clients

    def with_a_denied_bucket():
        s3, ec2, s3control, account, metadata = original()
        s3.list_buckets = _denied
        return s3, ec2, s3control, account, metadata

    def _denied(ContinuationToken=None):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListBuckets")

    monkeypatch.setattr(cli, "_demo_clients", with_a_denied_bucket)
    assert cli.main(["--demo"]) == 2
    assert "INCOMPLETE RUN" in capsys.readouterr().out


def test_the_live_path_without_credentials_prints_no_traceback():
    """The first live command the README offers, run by someone who has not
    configured credentials yet. Runs the installed console script, because a
    monkeypatched exception cannot prove botocore is not printing a stack."""
    script = shutil.which("posture") or str(Path(sys.executable).parent / "posture")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AWS_")
    }
    environment.update(
        AWS_CONFIG_FILE=os.devnull,
        AWS_SHARED_CREDENTIALS_FILE=os.devnull,
        AWS_EC2_METADATA_DISABLED="true",
    )
    completed = subprocess.run(
        [script, "--region", "us-east-1"],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "Traceback" not in completed.stderr
    assert completed.stderr.count("\n") == 1
    assert completed.stderr.startswith("posture: ")
