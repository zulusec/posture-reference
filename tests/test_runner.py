"""The runner is the last boundary that keeps the two checks independent."""

from botocore.exceptions import ClientError

from posture.demo.loader import DEMO_ACCOUNT_ID, DemoEc2, DemoS3, DemoS3Control
from posture.runner import run_all


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Op")


class DeadS3(DemoS3):
    def list_buckets(self, ContinuationToken=None):
        raise _client_error("AccessDenied")


class ExplodingEc2(DemoEc2):
    def describe_security_groups(self, NextToken=None):
        raise RuntimeError("a bug in the check, not an AWS error")


def _run(s3=None, ec2=None):
    return run_all(s3 or DemoS3(), ec2 or DemoEc2(), DemoS3Control(), DEMO_ACCOUNT_ID)


def test_a_complete_run_records_no_errors():
    result = _run()
    assert result.findings
    assert result.errors == []
    assert result.complete


def test_a_denied_s3_listing_does_not_cost_the_reader_the_ec2_answer():
    result = _run(s3=DeadS3())
    assert [f.check_id for f in result.findings] == [
        "EC2.OPEN_SECURITY_GROUP",
        "EC2.OPEN_SECURITY_GROUP",
    ]
    assert [(e.check_id, e.operation) for e in result.errors] == [
        ("S3.PUBLIC_ACCESS", "ListBuckets")
    ]
    assert not result.complete


def test_an_unexpected_failure_inside_a_check_is_recorded_not_propagated():
    """Including a bug in the check itself. One check must not get to decide
    whether the other one reports."""
    result = _run(ec2=ExplodingEc2())
    assert {f.check_id for f in result.findings} == {"S3.PUBLIC_ACCESS"}
    assert [(e.check_id, e.detail) for e in result.errors] == [
        ("EC2.OPEN_SECURITY_GROUP", "RuntimeError")
    ]


def test_errors_are_sorted_so_the_output_stays_stable():
    result = run_all(DeadS3(), ExplodingEc2(), DemoS3Control(), DEMO_ACCOUNT_ID)
    assert [e.check_id for e in result.errors] == [
        "EC2.OPEN_SECURITY_GROUP",
        "S3.PUBLIC_ACCESS",
    ]
