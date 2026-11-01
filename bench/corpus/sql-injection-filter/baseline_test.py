"""Baseline for the product search case: ordinary filters keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps answering plain filters while stopping
injected statements.
"""

from app import create_app


def test_plain_filter_matches():
    response = create_app().handle_request("POST", "/search", {"q": "widget"})
    assert response["status"] == 200
    assert [row["name"] for row in response["body"]["products"]] == ["widget"]


def test_filter_without_match_is_empty():
    response = create_app().handle_request("POST", "/search", {"q": "no-such-thing"})
    assert response["status"] == 200
    assert response["body"]["products"] == []


def test_unknown_route_is_not_found():
    response = create_app().handle_request("GET", "/nope", {})
    assert response["status"] == 404
