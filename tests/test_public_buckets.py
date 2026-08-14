import pytest
from botocore.exceptions import ClientError

from posture.checks import public_buckets
from posture.finding import Severity


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Op")


class FakeS3:
    def __init__(self, buckets, pab=None, policy_status=None):
        self._buckets = buckets
        self._pab = pab or {}
        self._policy_status = policy_status or {}
        self.pab_calls = 0

    def list_buckets(self):
        return {"Buckets": [{"Name": name} for name in self._buckets]}

    def get_public_access_block(self, Bucket):
        self.pab_calls += 1
        if Bucket not in self._pab:
            raise _client_error("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": self._pab[Bucket]}

    def get_bucket_policy_status(self, Bucket):
        if Bucket not in self._policy_status:
            raise _client_error("NoSuchBucketPolicy")
        return {"PolicyStatus": {"IsPublic": self._policy_status[Bucket]}}


ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def test_fully_blocked_bucket_produces_no_findings():
    s3 = FakeS3(["safe"], pab={"safe": ALL_ON}, policy_status={"safe": False})
    assert public_buckets.run(s3) == []


def test_partially_disabled_block_public_access_is_high():
    pab = dict(ALL_ON, BlockPublicPolicy=False)
    s3 = FakeS3(["leaky"], pab={"leaky": pab}, policy_status={"leaky": False})
    findings = public_buckets.run(s3)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_key == "block-public-access"
    assert findings[0].resource_id == "leaky"
    assert "BlockPublicPolicy" in findings[0].evidence


def test_missing_configuration_is_treated_as_disabled():
    s3 = FakeS3(["none"], pab={}, policy_status={"none": False})
    findings = public_buckets.run(s3)
    assert len(findings) == 1
    assert findings[0].rule_key == "block-public-access"


def test_public_policy_is_reported_separately():
    s3 = FakeS3(["open"], pab={"open": ALL_ON}, policy_status={"open": True})
    findings = public_buckets.run(s3)
    assert [f.rule_key for f in findings] == ["policy-public"]
    assert findings[0].severity == Severity.HIGH


def test_evidence_lists_disabled_settings_in_sorted_order():
    pab = dict(ALL_ON, BlockPublicAcls=False, RestrictPublicBuckets=False)
    s3 = FakeS3(["b"], pab={"b": pab}, policy_status={"b": False})
    evidence = public_buckets.run(s3)[0].evidence
    assert evidence == "disabled settings: BlockPublicAcls, RestrictPublicBuckets"


def test_unexpected_client_error_is_not_swallowed():
    class Broken(FakeS3):
        def get_public_access_block(self, Bucket):
            raise _client_error("AccessDenied")

    with pytest.raises(ClientError):
        public_buckets.run(Broken(["b"]))


def test_public_access_block_is_fetched_once_per_bucket():
    s3 = FakeS3(["a", "b"], pab={"a": ALL_ON, "b": ALL_ON},
                policy_status={"a": False, "b": False})
    public_buckets.run(s3)
    assert s3.pab_calls == 2


def test_findings_carry_the_check_id():
    s3 = FakeS3(["b"], pab={}, policy_status={"b": True})
    findings = public_buckets.run(s3)
    assert findings
    assert {f.check_id for f in findings} == {"S3.PUBLIC_ACCESS"}
