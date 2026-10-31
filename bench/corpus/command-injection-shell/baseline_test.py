"""Baseline for the command-injection case: listing behaviour kept on every tree.

Run against each tree with that tree on the path, e.g.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py

It must pass before and after the fix: a real fix keeps the ordinary listing
working while stopping names from reaching a shell.
"""

from app import create_app


def test_lists_a_file_inside_the_base(tmp_path):
    (tmp_path / "hello.txt").write_text("hello", encoding="utf-8")
    app = create_app(str(tmp_path))
    assert "hello.txt" in app.handle_request("POST", "hello.txt")


def test_a_missing_name_lists_nothing(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("POST", "no-such-file.txt") == ""


def test_non_post_requests_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "hello.txt") == "method not allowed"
