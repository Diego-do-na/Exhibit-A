"""Baseline for the webhook delivery case: ordinary targets keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps refusing unreachable subscribers without
hanging the delivery.
"""

from app import create_app


def test_unreachable_subscriber_is_an_error():
    try:
        create_app().handle_request("http://127.0.0.1:9/unreachable")
    except Exception:
        return
    raise AssertionError("an unreachable subscriber should be an error")


def test_non_string_subscriber_is_rejected():
    try:
        create_app().handle_request(None)
    except (TypeError, ValueError):
        return
    raise AssertionError("a non-string subscriber should be rejected")


def test_unsupported_scheme_is_rejected():
    try:
        create_app().handle_request("gopher://example.com/x")
    except ValueError:
        return
    raise AssertionError("an unsupported scheme should be rejected")
