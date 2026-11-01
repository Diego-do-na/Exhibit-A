"""Baseline for the avatar-upload case: behaviour kept on every tree."""

from app import create_app


def test_stores_a_file_inside_the_directory(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("POST", "ada.png", b"PNG") == "ada.png"
    assert (tmp_path / "ada.png").read_bytes() == b"PNG"


def test_stores_a_nested_name(tmp_path):
    app = create_app(str(tmp_path))
    stored = app.handle_request("POST", "team/ada.png", b"PNG")
    assert stored in ("team/ada.png", "ada.png")
    found = list(tmp_path.rglob("ada.png"))
    assert found and found[0].read_bytes() == b"PNG"


def test_non_post_requests_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "ada.png", b"PNG") == "method not allowed"
