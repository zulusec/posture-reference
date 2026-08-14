"""Fixture-backed stand-ins for the AWS clients.

These expose exactly the methods the checks call, so demo mode exercises the
real check code rather than a parallel implementation. The listings paginate
for the same reason: the real APIs do, and a stand-in that returned
everything in one page would let the demo pass while the paging loop the
live run depends on went untested.
"""

from __future__ import annotations

import json
from importlib.resources import files

from botocore.exceptions import ClientError

DEMO_ACCOUNT_ID = "000000000000"

# One resource per page, so every demo run crosses a page boundary in both
# listings rather than only in whichever fixture happens to be large enough.
_PAGE_SIZE = 1


def _load(name: str) -> dict:
    resource = files("posture.demo").joinpath("fixtures", name)
    return json.loads(resource.read_text(encoding="utf-8"))


def _missing(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


def _page(items: list, token: str | None) -> tuple[list, str | None]:
    start = int(token) if token else 0
    end = start + _PAGE_SIZE
    return items[start:end], str(end) if end < len(items) else None


class DemoS3:
    def __init__(self, data: dict | None = None):
        self._data = data if data is not None else _load("s3.json")

    def list_buckets(self, ContinuationToken: str | None = None) -> dict:
        buckets, token = _page(self._data["list_buckets"]["Buckets"], ContinuationToken)
        response = {"Buckets": buckets}
        if token:
            response["ContinuationToken"] = token
        return response

    def get_public_access_block(self, Bucket: str) -> dict:
        config = self._data["get_public_access_block"].get(Bucket)
        if config is None:
            raise _missing("NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock")
        return {"PublicAccessBlockConfiguration": config}

    def get_bucket_policy_status(self, Bucket: str) -> dict:
        status = self._data["get_bucket_policy_status"].get(Bucket)
        if status is None:
            raise _missing("NoSuchBucketPolicy", "GetBucketPolicyStatus")
        return {"PolicyStatus": {"IsPublic": status}}


class DemoS3Control:
    """Account-level Block Public Access, which the real check unions with the
    bucket-level setting. The fixture leaves two of the four off so the demo
    shows the union doing work rather than hiding it."""

    def __init__(self, data: dict | None = None):
        self._data = data if data is not None else _load("s3control.json")

    def get_public_access_block(self, AccountId: str) -> dict:
        config = self._data["get_public_access_block"].get(AccountId)
        if config is None:
            raise _missing("NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock")
        return {"PublicAccessBlockConfiguration": config}


class DemoEc2:
    def __init__(self, data: dict | None = None):
        self._data = data if data is not None else _load("ec2.json")

    def describe_security_groups(self, NextToken: str | None = None) -> dict:
        groups = self._data["describe_security_groups"]["SecurityGroups"]
        page, token = _page(groups, NextToken)
        response = {"SecurityGroups": page}
        if token:
            response["NextToken"] = token
        return response
