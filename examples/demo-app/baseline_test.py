"""Baseline for the demo-app fixture: behaviour the importer must keep, safe or not.

Run it against either tree with that tree on the path, e.g.

    PYTHONPATH=examples/demo-app/base python -m pytest examples/demo-app/baseline_test.py
    PYTHONPATH=examples/demo-app/pr   python -m pytest examples/demo-app/baseline_test.py

It must pass before and after the fix: a real fix confines unsafe entries
without breaking the ordinary, in-bounds installs the app exists to do.
"""

from importer import create_app, make_pack


def test_installs_a_safe_entry_inside_the_skins_dir(tmp_path):
    app = create_app(str(tmp_path))
    app.handle_request("POST", make_pack([("dark/theme.css", "body {}")]))
    assert (tmp_path / "dark" / "theme.css").read_text(encoding="utf-8") == "body {}"


def test_installs_multiple_entries(tmp_path):
    app = create_app(str(tmp_path))
    app.handle_request("POST", make_pack([("a.css", "A"), ("b/c.css", "C")]))
    assert (tmp_path / "a.css").read_text(encoding="utf-8") == "A"
    assert (tmp_path / "b" / "c.css").read_text(encoding="utf-8") == "C"


def test_non_post_requests_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", make_pack([("a.css", "A")])) == "method not allowed"


def test_malformed_packs_are_rejected(tmp_path):
    from importer import SkinPackError

    app = create_app(str(tmp_path))
    for blob in (b"not json", b'{"entries": [{"path": 1}]}', b'{"nope": []}'):
        try:
            app.handle_request("POST", blob)
        except SkinPackError:
            continue
        raise AssertionError(f"malformed pack accepted: {blob!r}")
