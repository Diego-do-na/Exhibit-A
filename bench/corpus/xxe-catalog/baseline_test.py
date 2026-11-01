"""Baseline for the catalog-import case: behaviour kept on every tree.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py
"""

from app import create_app

CATALOG = "<catalog><item>widget</item></catalog>"


def test_imports_a_plain_catalog(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("POST", CATALOG) == "widget"


def test_nested_entries_are_concatenated(tmp_path):
    app = create_app(str(tmp_path))
    body = "<catalog><a>one</a><b>two</b></catalog>"
    assert app.handle_request("POST", body) == "onetwo"


def test_non_post_requests_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", CATALOG) == "method not allowed"
