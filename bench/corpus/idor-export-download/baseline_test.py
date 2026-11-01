"""Baseline for the report export case: ordinary exports keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps owners exporting their own reports while
refusing everyone else.
"""

from app import create_app


def test_owner_exports_their_own_report():
    response = create_app().handle_request("analyst.zoe", "samples/personal")
    assert response["status"] == 200
    assert "Personal" in response["body"]["report"]


def test_a_missing_report_is_an_error():
    try:
        create_app().handle_request("analyst.zoe", "no-such-report")
    except KeyError:
        return
    raise AssertionError("a missing report should be an error")


def test_trailing_slash_exports_the_same_report():
    first = create_app().handle_request("analyst.zoe", "samples/personal")
    second = create_app().handle_request("analyst.zoe", "samples/personal/")
    assert first["body"]["report"] == second["body"]["report"]
