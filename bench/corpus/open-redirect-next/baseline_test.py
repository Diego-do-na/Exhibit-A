"""Baseline for the sign-in redirect case: ordinary targets keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps same-site targets redirecting while
refusing off-site ones.
"""

from app import create_app


def test_same_site_target_redirects():
    response = create_app().handle_request("https://shop.example.com/home")
    assert response[0] == 302
    assert response[1]["Location"] == "https://shop.example.com/home"


def test_relative_target_redirects():
    response = create_app().handle_request("https://shop.example.com/a/b?c=d")
    assert response[1]["Location"].endswith("/a/b?c=d")


def test_a_non_string_target_is_rejected():
    try:
        create_app().handle_request(None)
    except (TypeError, AttributeError, ValueError):
        return
    raise AssertionError("a non-string target should be rejected")
