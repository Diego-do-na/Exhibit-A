"""Baseline for the greeting-preview case: behaviour kept on every tree."""

from app import create_app


def test_renders_a_plain_greeting(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("POST", "Hello {{ name }}", {"name": "Ada"}) == "Hello Ada"


def test_missing_value_renders_empty(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("POST", "Hello {{ name }}", {}) == "Hello "


def test_non_post_requests_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "Hello {{ name }}", {"name": "Ada"}) == "method not allowed"
