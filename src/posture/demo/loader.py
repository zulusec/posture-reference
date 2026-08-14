"""Fixture-backed stand-ins for the AWS clients.

These expose exactly the methods the checks call, so demo mode exercises the
real check code rather than a parallel implementation.
"""

from __future__ import annotations

import json
from importlib.resources import files

from botocore.exceptions import ClientError

DEMO_ACCOUNT_ID = "000000000000"


def _load(name: str) -> dict:
    resource = files("posture.demo").joinpath("fixtures", name)
    return json.loads(resource.read_text(encoding="utf-8"))


def _missing(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


class DemoS3:
    def __init__(self, data: dict | None = None):
        self._data = data if data is not None else _load("s3.json")

    def list_buckets(self) -> dict:
        return self._data["list_buckets"]

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

    def describe_security_groups(self) -> dict:
        return self._data["describe_security_groups"]
