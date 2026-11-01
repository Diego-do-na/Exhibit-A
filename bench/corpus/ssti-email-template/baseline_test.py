"""Baseline for the notification template case: ordinary subjects work.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps rendering plain subjects while stopping
template code from running.
"""

from app import create_app


def test_plain_subject_renders():
    message = create_app("base").handle_request("POST", "Hello {{ name }}", {"name": "Ada"})
    assert message == "Order update: Hello Ada"


def test_subject_without_placeholders_renders():
    message = create_app("base").handle_request("POST", "shipped", {})
    assert message == "Order update: shipped"


def test_non_post_requests_are_rejected():
    assert create_app("base").handle_request("GET", "shipped", {}) == "method not allowed"
