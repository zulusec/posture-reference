import json

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
