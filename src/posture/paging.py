"""Token loop over paginated AWS list and describe operations.

Every listing AWS offers is paginated, and reading only the first page is
the most damaging bug a posture tool can have: DescribeSecurityGroups
returns at most 1000 groups per page against a default quota of 2500 per
VPC, so an account whose one exposed group is number 1001 comes back clean.

boto3 ships get_paginator, but the checks take duck-typed clients so they
can be driven from bundled fixtures and from hand-written fakes in the
tests. A token loop works against all three, which keeps demo mode and the
tests on the same code path the live client takes rather than on a parallel
one that could pass while the real path is broken.

Both operations this tool calls use one name for the token in the request
and the response: ContinuationToken for s3:ListBuckets, NextToken for
ec2:DescribeSecurityGroups.
"""

from __future__ import annotations

from collections.abc import Iterator


class PaginationError(RuntimeError):
    """A listing returned a token that does not advance it."""


def paginate(operation, token_key: str, result_key: str) -> Iterator[dict]:
    """Yield every item under result_key, following tokens to the last page."""
    params: dict = {}
    while True:
        response = operation(**params)
        yield from response.get(result_key, [])
        token = response.get(token_key)
        if not token:
            return
        if token == params.get(token_key):
            # botocore's own PageIterator carries this guard. A server that
            # hands back the same token twice, which is likelier from an
            # S3-compatible endpoint or a proxy than from AWS itself, would
            # otherwise loop forever, and a tool that hangs is worse than one
            # that stops and says why. The runner records this as a gap.
            raise PaginationError(f"{token_key} repeated, so the listing did not advance")
        params[token_key] = token
