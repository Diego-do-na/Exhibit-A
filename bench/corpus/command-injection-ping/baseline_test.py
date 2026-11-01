"""Baseline for the connectivity check case: ordinary hosts keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps checking plain hosts while stopping shell
metacharacters.
"""

from app import create_app


def test_plain_host_returns_a_string():
    assert isinstance(create_app("base").handle_request("POST", "localhost"), str)


def test_a_missing_host_is_rejected():
    try:
        create_app("base").handle_request("POST", None)
    except (TypeError, ValueError):
        return
    raise AssertionError("a missing host should be rejected")


def test_non_post_requests_are_rejected():
    assert create_app("base").handle_request("GET", "a") == "method not allowed"
