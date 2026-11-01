"""Baseline for the analysis export case: ordinary exports keep working.

Run against each tree with that tree on the path. It must pass before and
after the fix: a real fix keeps storing plain names while stopping
escapes.
"""

import os

from app import create_app


def test_plain_name_is_stored(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("POST", "q3.txt", b"data") == "q3.txt"
    assert (tmp_path / "q3.txt").read_bytes() == b"data"


def test_non_post_requests_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "q3.txt", b"data") == "method not allowed"


def test_plain_name_round_trips(tmp_path):
    app = create_app(str(tmp_path))
    app.handle_request("POST", "notes.txt", b"hi")
    assert (tmp_path / "notes.txt").read_bytes() == b"hi"
