import json

from posture import render
from posture.finding import Finding, Severity


def _finding(check_id="A", resource_id="r", severity=Severity.HIGH):
    return Finding(
        check_id=check_id,
        resource_id=resource_id,
        rule_key="k",
        severity=severity,
        title="A title",
        evidence="Some evidence",
    )


def test_findings_json_excludes_metadata():
    output = render.findings_json([_finding()])
    parsed = json.loads(output)
    assert isinstance(parsed, list)
    assert parsed[0]["check_id"] == "A"


def test_findings_json_ends_with_newline():
    assert render.findings_json([_finding()]).endswith("\n")


def test_findings_json_sorts_keys():
    output = render.findings_json([_finding()])
    keys = list(json.loads(output)[0].keys())
    assert keys == sorted(keys)


def test_to_json_separates_metadata_from_findings():
    output = render.to_json([_finding()], {"mode": "demo"})
    parsed = json.loads(output)
    assert parsed["metadata"] == {"mode": "demo"}
    assert len(parsed["findings"]) == 1


def test_empty_table_states_no_findings():
    assert render.to_table([]) == "No findings.\n"


def test_table_includes_severity_and_resource():
    output = render.to_table([_finding()])
    assert "HIGH" in output
    assert "r" in output
    assert "Some evidence" in output
