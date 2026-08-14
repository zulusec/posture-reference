"""The token loop the checks use in place of boto3's get_paginator."""

import pytest

from posture.paging import PaginationError, paginate


class Listing:
    """One item per page, the way the real listings page an account."""

    def __init__(self, items, repeat_token=False):
        self._items = items
        self._repeat_token = repeat_token
        self.calls = 0

    def __call__(self, NextToken=None):
        self.calls += 1
        start = int(NextToken) if NextToken and not self._repeat_token else 0
        response = {"Things": self._items[start:start + 1]}
        if self._repeat_token:
            response["NextToken"] = "stuck"
        elif start + 1 < len(self._items):
            response["NextToken"] = str(start + 1)
        return response


def test_every_page_is_read():
    listing = Listing(["a", "b", "c"])
    assert list(paginate(listing, "NextToken", "Things")) == ["a", "b", "c"]
    assert listing.calls == 3


def test_a_single_page_makes_one_call():
    listing = Listing(["only"])
    assert list(paginate(listing, "NextToken", "Things")) == ["only"]
    assert listing.calls == 1


def test_a_missing_result_key_is_an_empty_page_not_a_crash():
    assert list(paginate(dict, "NextToken", "Things")) == []


def test_a_token_that_does_not_advance_stops_the_loop():
    """Reimplementing the loop means reimplementing botocore's guard. Without
    it an endpoint that repeats a token hangs the tool, and a tool that hangs
    is worse than one that stops and says why."""
    listing = Listing(["a", "b"], repeat_token=True)
    with pytest.raises(PaginationError):
        list(paginate(listing, "NextToken", "Things"))
    assert listing.calls == 2
