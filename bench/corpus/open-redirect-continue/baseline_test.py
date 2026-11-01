"""Baseline for the continue-page case: ordinary targets keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps answering the page while dropping the
caller-controlled refresh.
"""

from app import create_app


def test_continue_page_answers():
    response = create_app().handle_request("https://shop.example.com/home")
    assert response["status"] == 200
    assert "text/html" in response["headers"]["Content-Type"]


def test_continue_page_keeps_working_for_paths():
    response = create_app().handle_request("https://shop.example.com/a/b?c=d")
    assert response["status"] == 200


def test_a_non_string_target_is_rejected():
    try:
        create_app().handle_request(None)
    except (TypeError, AttributeError, ValueError):
        return
    raise AssertionError("a non-string target should be rejected")
