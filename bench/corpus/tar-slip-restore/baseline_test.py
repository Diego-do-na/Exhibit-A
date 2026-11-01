"""Baseline for the backup-restore case: behaviour kept on every tree."""

from app import create_app, pack


def test_restores_a_member_inside_the_destination(tmp_path):
    app = create_app(str(tmp_path))
    app.handle_request("POST", pack([("docs/readme.txt", "hello")]))
    assert (tmp_path / "docs" / "readme.txt").read_text(encoding="utf-8") == "hello"


def test_restores_multiple_members(tmp_path):
    app = create_app(str(tmp_path))
    app.handle_request("POST", pack([("a.txt", "A"), ("b/c.txt", "C")]))
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "A"
    assert (tmp_path / "b" / "c.txt").read_text(encoding="utf-8") == "C"


def test_non_post_requests_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", pack([("a.txt", "A")])) == "method not allowed"
