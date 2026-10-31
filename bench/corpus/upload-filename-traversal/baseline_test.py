"""Baseline for the upload case: storing behaviour kept on every tree.

Run against each tree with that tree on the path, e.g.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py

It must pass before and after a fix: ordinary uploads are stored, clashing names get a
suffix, and malformed requests are refused.
"""

from uploadsvc import create_app
from uploadsvc.multipart import encode

BOUNDARY = "xBoundary7"
HEADERS = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}


def upload(app, *files):
    body = encode(BOUNDARY, [("file", name, data) for name, data in files])
    return app.handle_request("POST", "/upload", HEADERS, body)


def test_an_upload_is_stored_under_its_name(tmp_path):
    app = create_app(str(tmp_path))
    status, payload = upload(app, ("notes.txt", b"hello"))
    assert (status, payload) == (201, {"stored": ["notes.txt"]})
    assert (tmp_path / "notes.txt").read_bytes() == b"hello"


def test_several_files_in_one_request_are_all_stored(tmp_path):
    app = create_app(str(tmp_path))
    status, payload = upload(app, ("a.txt", b"1"), ("b.txt", b"2"))
    assert status == 201 and payload["stored"] == ["a.txt", "b.txt"]
    assert app.handle_request("GET", "/files") == (200, {"files": ["a.txt", "b.txt"]})


def test_a_clashing_name_gets_a_suffix(tmp_path):
    app = create_app(str(tmp_path))
    upload(app, ("report.csv", b"one"))
    status, payload = upload(app, ("report.csv", b"two"))
    assert payload == {"stored": ["report_1.csv"]}
    assert (tmp_path / "report.csv").read_bytes() == b"one"
    assert (tmp_path / "report_1.csv").read_bytes() == b"two"


def test_a_client_side_windows_path_is_reduced_to_the_file_name(tmp_path):
    app = create_app(str(tmp_path))
    status, payload = upload(app, ("C:\\Users\\ana\\photo.png", b"png"))
    assert (status, payload) == (201, {"stored": ["photo.png"]})


def test_an_empty_file_name_is_refused(tmp_path):
    app = create_app(str(tmp_path))
    status, _ = upload(app, ("", b"x"))
    assert status == 400
    assert app.handle_request("GET", "/files") == (200, {"files": []})


def test_a_request_that_is_not_multipart_is_refused(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("POST", "/upload", {"Content-Type": "text/plain"}, b"x")[0] == 400
    assert app.handle_request("POST", "/upload", HEADERS, b"garbage")[0] == 400


def test_a_request_without_files_is_refused(tmp_path):
    app = create_app(str(tmp_path))
    body = encode(BOUNDARY, [("comment", None, b"hi")])
    assert app.handle_request("POST", "/upload", HEADERS, body)[0] == 400


def test_unknown_routes_are_404(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "/nope")[0] == 404
