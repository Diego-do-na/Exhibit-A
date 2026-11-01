"""Baseline for the log viewer case: ordinary log names keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps showing logs inside the directory while
stopping escapes.
"""

import os

from app import create_app


def test_public_log_is_shown(tmp_path):
    app = create_app(str(tmp_path))
    (tmp_path / "app.log").write_text("started\n", encoding="utf-8")
    reply = app.handle_request("GET", "app.log")
    assert reply["text"] == "started\n"


def test_a_missing_log_is_an_error(tmp_path):
    try:
        create_app(str(tmp_path)).handle_request("GET", "no-such.log")
    except OSError:
        return
    raise AssertionError("a missing log should be an error")


def test_non_get_requests_are_rejected(tmp_path):
    assert create_app(str(tmp_path)).handle_request("POST", "app.log") == "method not allowed"
