"""Baseline for the archive-extraction case: behaviour the extractor must keep, fixed or not.

The engine runs this against each tree with that tree on the path, e.g.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py

It must pass before and after the fix: a real fix confines unsafe members without breaking the
ordinary, in-bounds extraction the app exists to do.
"""

from archive import create_app, pack, unpack


def test_extracts_a_safe_member_inside_the_destination(tmp_path):
    app = create_app(str(tmp_path))
    app.handle_request("POST", pack([("docs/readme.txt", "hello")]))
    assert (tmp_path / "docs" / "readme.txt").read_text(encoding="utf-8") == "hello"


def test_extracts_multiple_members(tmp_path):
    app = create_app(str(tmp_path))
    app.handle_request("POST", pack([("a.txt", "A"), ("b/c.txt", "C")]))
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "A"
    assert (tmp_path / "b" / "c.txt").read_text(encoding="utf-8") == "C"


def test_non_post_requests_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", pack([("a.txt", "A")])) == "method not allowed"


def test_pack_round_trips():
    members = unpack(pack([("x/y.txt", "data"), ("z.txt", "")]))
    assert [(m.name, m.data) for m in members] == [("x/y.txt", "data"), ("z.txt", "")]
