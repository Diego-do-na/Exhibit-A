"""Baseline for the static-route case: serving behaviour kept on every tree.

Run against each tree with that tree on the path, e.g.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py

It must pass before and after a fix: ordinary files, indexes, validators and links
inside the served directory keep working.
"""

from staticsrv import create_app


def site(tmp_path):
    root = tmp_path / "site"
    (root / "css").mkdir(parents=True)
    (root / "index.html").write_text("<h1>home</h1>", encoding="utf-8")
    (root / "css" / "main.css").write_text("body { margin: 0 }", encoding="utf-8")
    (root / "hello.txt").write_text("hello", encoding="utf-8")
    return root


def test_serves_a_file_with_its_content_type(tmp_path):
    app = create_app(str(site(tmp_path)))
    reply = app.handle_request("GET", "/static/css/main.css")
    assert reply.status == 200
    assert reply.text == "body { margin: 0 }"
    assert reply.headers["content-type"].startswith("text/css")
    assert reply.headers["content-length"] == str(len(reply.body))


def test_a_directory_is_answered_with_its_index(tmp_path):
    app = create_app(str(site(tmp_path)))
    assert app.handle_request("GET", "/static/").text == "<h1>home</h1>"


def test_a_missing_file_is_a_404(tmp_path):
    app = create_app(str(site(tmp_path)))
    assert app.handle_request("GET", "/static/none.txt").status == 404
    assert app.handle_request("GET", "/other/hello.txt").status == 404


def test_head_has_headers_and_no_body(tmp_path):
    app = create_app(str(site(tmp_path)))
    reply = app.handle_request("HEAD", "/static/hello.txt")
    assert (reply.status, reply.body) == (200, b"")
    assert reply.headers["content-length"] == "5"


def test_a_matching_validator_gives_a_304(tmp_path):
    app = create_app(str(site(tmp_path)))
    etag = app.handle_request("GET", "/static/hello.txt").headers["etag"]
    assert app.handle_request("GET", "/static/hello.txt", {"if-none-match": etag}).status == 304


def test_other_methods_are_refused(tmp_path):
    app = create_app(str(site(tmp_path)))
    assert app.handle_request("POST", "/static/hello.txt").status == 405


def test_a_percent_encoded_name_is_decoded(tmp_path):
    root = site(tmp_path)
    (root / "a b.txt").write_text("spaced", encoding="utf-8")
    app = create_app(str(root))
    assert app.handle_request("GET", "/static/a%20b.txt").text == "spaced"


def test_a_link_to_a_shared_directory_is_followed_only_where_configured(tmp_path):
    root = site(tmp_path)
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "data.txt").write_text("shared data", encoding="utf-8")
    (root / "linked.txt").symlink_to(shared / "data.txt")
    app = create_app(str(root))
    assert app.handle_request("GET", "/static/linked.txt").text == "shared data"
    assert app.handle_request("GET", "/assets/linked.txt").status == 404
