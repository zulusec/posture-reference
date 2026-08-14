import json

from posture import render
from posture.finding import Finding, Severity
from posture.result import ScanError


def _error(resource_id="locked", operation="GetBucketPolicyStatus", detail="AccessDenied"):
    return ScanError(
        check_id="S3.PUBLIC_ACCESS",
        resource_id=resource_id,
        operation=operation,
        detail=detail,
    )


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
    assert parsed["metadata"] == {"mode": "demo", "errors": []}
    assert len(parsed["findings"]) == 1


def test_empty_table_states_no_findings():
    assert render.to_table([]) == "No findings.\n"


def test_table_includes_severity_and_resource():
    output = render.to_table([_finding()])
    assert "HIGH" in output
    assert "r" in output
    assert "Some evidence" in output


def test_json_metadata_carries_an_empty_errors_block_on_a_complete_run():
    """Always present, so a consumer checks one key rather than inferring
    completeness from the absence of one."""
    parsed = json.loads(render.to_json([_finding()], {"mode": "demo"}))
    assert parsed["metadata"]["errors"] == []


def test_json_records_every_unreadable_resource():
    parsed = json.loads(render.to_json([], {"mode": "live"}, [_error()]))
    assert parsed["metadata"]["errors"] == [
        {
            "check_id": "S3.PUBLIC_ACCESS",
            "resource_id": "locked",
            "operation": "GetBucketPolicyStatus",
            "detail": "AccessDenied",
        }
    ]


def test_to_json_does_not_mutate_the_metadata_it_was_given():
    metadata = {"mode": "demo"}
    render.to_json([], metadata, [_error()])
    assert metadata == {"mode": "demo"}


def test_table_says_a_partial_run_is_partial():
    output = render.to_table([_finding()], [_error()])
    assert output.startswith("INCOMPLETE RUN: 1 resource could not be read.")
    assert "locked" in output
    assert "AccessDenied" in output
    assert "HIGH" in output


def test_table_counts_unreadable_resources():
    output = render.to_table([], [_error(), _error(resource_id="other")])
    assert "INCOMPLETE RUN: 2 resources could not be read." in output


def test_table_never_reports_a_partial_run_as_simply_clean():
    """"No findings." over a run that could not read three buckets is the
    silent degradation this whole errors block exists to prevent."""
    output = render.to_table([], [_error()])
    assert "No findings.\n" not in output
    assert "No findings in what could be read." in output
