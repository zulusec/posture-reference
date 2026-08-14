from botocore.exceptions import ClientError, EndpointConnectionError

from posture.checks import public_buckets
from posture.finding import Severity


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Op")


class FakeS3:
    """Serves one bucket per page, the way ListBuckets pages a real account."""

    def __init__(self, buckets, pab=None, policy_status=None, denied=()):
        self._buckets = buckets
        self._pab = pab or {}
        self._policy_status = policy_status or {}
        self._denied = set(denied)
        self.pab_calls = 0
        self.list_calls = 0

    def list_buckets(self, ContinuationToken=None):
        self.list_calls += 1
        start = int(ContinuationToken) if ContinuationToken else 0
        names = self._buckets[start:start + 1]
        response = {"Buckets": [{"Name": name} for name in names]}
        if start + 1 < len(self._buckets):
            response["ContinuationToken"] = str(start + 1)
        return response

    def get_public_access_block(self, Bucket):
        self.pab_calls += 1
        if Bucket in self._denied:
            raise _client_error("AccessDenied")
        if Bucket not in self._pab:
            raise _client_error("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": self._pab[Bucket]}

    def get_bucket_policy_status(self, Bucket):
        if Bucket in self._denied:
            raise _client_error("AccessDenied")
        if Bucket not in self._policy_status:
            raise _client_error("NoSuchBucketPolicy")
        return {"PolicyStatus": {"IsPublic": self._policy_status[Bucket]}}


class FakeS3Control:
    """Account-level Block Public Access. Pass config=None for an account that
    has none, or an exception to model the call being denied or unreachable."""

    ACCOUNT = "000000000000"

    def __init__(self, config=None, error=None):
        self._config = config
        self._error = error
        self.calls = 0

    def get_public_access_block(self, AccountId):
        self.calls += 1
        if self._error is not None:
            raise self._error
        if self._config is None:
            raise _client_error("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": self._config}


ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

ALL_OFF = dict.fromkeys(ALL_ON, False)


def _result(s3, s3control=None, account_id=FakeS3Control.ACCOUNT):
    return public_buckets.run(s3, s3control, account_id)


def _run(s3, s3control=None, account_id=FakeS3Control.ACCOUNT):
    return _result(s3, s3control, account_id).findings


def test_fully_blocked_bucket_produces_no_findings():
    s3 = FakeS3(["safe"], pab={"safe": ALL_ON}, policy_status={"safe": False})
    assert _run(s3) == []


def test_partially_disabled_block_public_access_is_high():
    pab = dict(ALL_ON, BlockPublicPolicy=False)
    s3 = FakeS3(["leaky"], pab={"leaky": pab}, policy_status={"leaky": False})
    findings = _run(s3)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_key == "block-public-access"
    assert findings[0].resource_id == "leaky"
    assert "BlockPublicPolicy" in findings[0].evidence


def test_missing_configuration_is_still_a_finding():
    s3 = FakeS3(["none"], pab={}, policy_status={"none": False})
    findings = _run(s3)
    assert len(findings) == 1
    assert findings[0].rule_key == "block-public-access"


def test_public_policy_is_reported_separately():
    s3 = FakeS3(["open"], pab={"open": ALL_ON}, policy_status={"open": True})
    findings = _run(s3)
    assert [f.rule_key for f in findings] == ["policy-public"]
    assert findings[0].severity == Severity.HIGH


def test_evidence_lists_settings_in_sorted_order():
    pab = dict(ALL_ON, BlockPublicAcls=False, RestrictPublicBuckets=False)
    s3 = FakeS3(["b"], pab={"b": pab}, policy_status={"b": False})
    evidence = _run(s3)[0].evidence
    assert evidence == (
        "Block Public Access is configured on this bucket; "
        "not enabled at bucket level: BlockPublicAcls, RestrictPublicBuckets"
    )


def test_absent_configuration_does_not_claim_the_settings_were_set_false():
    """"No configuration exists" and "all four were set to false" are different
    facts about the client's account, and only the first one is ours to state."""
    s3 = FakeS3(["none"], pab={}, policy_status={"none": False})
    evidence = _run(s3)[0].evidence
    assert evidence.startswith("no Block Public Access configuration exists on this bucket")
    assert "disabled settings" not in evidence


def test_public_access_block_is_fetched_once_per_bucket():
    s3 = FakeS3(["a", "b"], pab={"a": ALL_ON, "b": ALL_ON},
                policy_status={"a": False, "b": False})
    _run(s3)
    assert s3.pab_calls == 2


def test_findings_carry_the_check_id():
    s3 = FakeS3(["b"], pab={}, policy_status={"b": True})
    findings = _run(s3)
    assert findings
    assert {f.check_id for f in findings} == {"S3.PUBLIC_ACCESS"}


def test_account_level_block_public_access_clears_an_unconfigured_bucket():
    """The preferred posture: account-level BPA fully on, no bucket-level
    configuration anywhere. Reading only the bucket level raises HIGH on every
    bucket in such an account."""
    s3 = FakeS3(["a", "b"], pab={}, policy_status={"a": False, "b": False})
    assert _run(s3, FakeS3Control(ALL_ON)) == []


def test_effective_setting_is_the_union_of_both_levels():
    bucket = dict(ALL_OFF, BlockPublicAcls=True, IgnorePublicAcls=True)
    account = dict(ALL_OFF, BlockPublicPolicy=True, RestrictPublicBuckets=True)
    s3 = FakeS3(["b"], pab={"b": bucket}, policy_status={"b": False})
    assert _run(s3, FakeS3Control(account)) == []


def test_account_level_gap_is_reported_with_both_levels_named():
    account = dict(ALL_OFF, BlockPublicAcls=True, IgnorePublicAcls=True)
    s3 = FakeS3(["b"], pab={}, policy_status={"b": False})
    evidence = _run(s3, FakeS3Control(account))[0].evidence
    assert evidence == (
        "no Block Public Access configuration exists on this bucket; "
        "not enabled at bucket or account level: BlockPublicPolicy, RestrictPublicBuckets"
    )


def test_absent_account_configuration_still_counts_as_read():
    """No account-level configuration is an answer, not a failure to get one."""
    s3 = FakeS3(["b"], pab={"b": ALL_OFF}, policy_status={"b": False})
    evidence = _run(s3, FakeS3Control(config=None))[0].evidence
    assert "not enabled at bucket or account level" in evidence


def test_account_lookup_is_made_once_for_the_whole_run():
    s3 = FakeS3(["a", "b", "c"], pab={}, policy_status={})
    control = FakeS3Control(ALL_ON)
    _run(s3, control)
    assert control.calls == 1


def test_denied_account_lookup_degrades_to_the_bucket_level():
    s3 = FakeS3(["b"], pab={"b": ALL_OFF}, policy_status={"b": False})
    control = FakeS3Control(error=_client_error("AccessDenied"))
    result = _result(s3, control)
    assert len(result.findings) == 1
    assert "not enabled at bucket level" in result.findings[0].evidence
    assert "account" not in result.findings[0].evidence
    # Named apart from the bucket-level call, because the permission to grant
    # after reading this line is s3:GetAccountPublicAccessBlock.
    assert [(e.resource_id, e.operation) for e in result.errors] == [
        ("account", "GetAccountPublicAccessBlock")
    ]


def test_unreachable_account_lookup_degrades_to_the_bucket_level():
    s3 = FakeS3(["b"], pab={"b": ALL_OFF}, policy_status={"b": False})
    control = FakeS3Control(
        error=EndpointConnectionError(endpoint_url="https://s3-control.example")
    )
    result = _result(s3, control)
    assert "not enabled at bucket level" in result.findings[0].evidence
    assert result.errors[0].detail == "EndpointConnectionError"


def test_omitting_the_account_client_narrows_the_claim_rather_than_widening_it():
    s3 = FakeS3(["b"], pab={"b": ALL_OFF}, policy_status={"b": False})
    assert "not enabled at bucket level" in _run(s3, None)[0].evidence
    assert "not enabled at bucket level" in _run(s3, FakeS3Control(ALL_ON), None)[0].evidence


def test_a_bucket_on_a_later_page_is_still_checked():
    s3 = FakeS3(["a", "b", "exposed"], pab={"a": ALL_ON, "b": ALL_ON},
                policy_status={"a": False, "b": False, "exposed": True})
    findings = _run(s3, FakeS3Control(ALL_ON))
    assert s3.list_calls == 3
    assert [f.resource_id for f in findings] == ["exposed"]


def test_one_denied_bucket_does_not_stop_the_others():
    """A bucket policy that denies the assessor role is common in exactly the
    environments worth assessing. It must cost the run that one answer."""
    s3 = FakeS3(
        ["locked", "exposed"],
        pab={"exposed": ALL_OFF},
        policy_status={"exposed": False},
        denied=["locked"],
    )
    result = _result(s3)
    assert [f.resource_id for f in result.findings] == ["exposed"]
    assert {(e.resource_id, e.operation, e.detail) for e in result.errors} == {
        ("locked", "GetPublicAccessBlock", "AccessDenied"),
        ("locked", "GetBucketPolicyStatus", "AccessDenied"),
    }


def test_a_denied_policy_read_still_yields_the_block_public_access_answer():
    class HalfDenied(FakeS3):
        def get_bucket_policy_status(self, Bucket):
            raise _client_error("AccessDenied")

    s3 = HalfDenied(["b"], pab={"b": ALL_OFF})
    result = _result(s3)
    assert [f.rule_key for f in result.findings] == ["block-public-access"]
    assert [e.operation for e in result.errors] == ["GetBucketPolicyStatus"]


def test_a_denied_listing_is_recorded_rather_than_raised():
    class NoListing(FakeS3):
        def list_buckets(self, ContinuationToken=None):
            raise _client_error("AccessDenied")

    result = _result(NoListing(["b"]))
    assert result.findings == []
    assert [(e.resource_id, e.operation) for e in result.errors] == [("account", "ListBuckets")]
