"""Baseline for the large command-injection case: behaviour kept on every tree.

Run against each tree with that tree on the path, e.g.

    PYTHONPATH=vulnerable python -m pytest baseline_test.py
    PYTHONPATH=fixed      python -m pytest baseline_test.py

It must pass before and after a fix: logins, documents, versions, pins, search, exports,
delivery, notifications, usage reports, backups and ordinary cleanups keep working, while
unknown scopes are refused and non-admin accounts cannot clean up.
"""

import json

from docsuite import create_app

ADMIN = {"Authorization": "Bearer tok-ana"}
EDITOR = {"Authorization": "Bearer tok-ben"}
VIEWER = {"Authorization": "Bearer tok-cara"}


def request_body(data):
    return json.dumps(data).encode()


def test_login_accepts_a_known_account_and_refuses_an_unknown_token(tmp_path):
    app = create_app(str(tmp_path))
    status, payload = app.handle_request(
        "POST", "/accounts/login", {},
        request_body({"name": "Ana Ruiz", "token": "tok-ana"}))
    assert status == 200 and payload["session"].startswith("acc-1.")
    status, _ = app.handle_request(
        "POST", "/accounts/login", {},
        request_body({"name": "Ana Ruiz", "token": "nope"}))
    assert status == 401


def test_requests_without_credentials_are_refused(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "/accounts/me", {})[0] == 401


def test_documents_are_created_listed_shown_and_updated(tmp_path):
    app = create_app(str(tmp_path))
    status, payload = app.handle_request(
        "POST", "/documents", EDITOR,
        request_body({"title": "Guide", "body": "read this", "tags": ["news"]}))
    assert status == 201
    doc_id = payload["document"]["id"]
    assert app.handle_request("GET", "/documents", VIEWER)[1]["total"] == 1
    shown = app.handle_request("GET", f"/documents/{doc_id}", VIEWER)
    assert shown[0] == 200 and shown[1]["document"]["title"] == "Guide"
    updated = app.handle_request(
        "PUT", f"/documents/{doc_id}", EDITOR,
        request_body({"body": "read this twice"}))
    assert updated[0] == 200
    versions = app.handle_request("GET", f"/documents/{doc_id}/versions", VIEWER)
    assert versions[0] == 200 and len(versions[1]["versions"]) == 1


def test_viewers_cannot_write_documents(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request(
        "POST", "/documents", VIEWER,
        request_body({"title": "Hi", "body": "x"}))[0] == 403


def test_related_pins_and_search(tmp_path):
    app = create_app(str(tmp_path))
    first = app.handle_request(
        "POST", "/documents", EDITOR,
        request_body({"title": "One", "body": "shared words", "tags": ["news"]}))
    second = app.handle_request(
        "POST", "/documents", EDITOR,
        request_body({"title": "Two", "body": "more shared words", "tags": ["news"]}))
    doc_id = first[1]["document"]["id"]
    related = app.handle_request("GET", f"/documents/{doc_id}/related", VIEWER)
    assert [doc["id"] for doc in related[1]["documents"]] == [second[1]["document"]["id"]]
    assert app.handle_request("POST", f"/documents/{doc_id}/pin", VIEWER)[1] == {"pinned": True}
    assert [doc["id"] for doc in app.handle_request("GET", "/pins", VIEWER)[1]["pins"]] == [doc_id]
    assert app.handle_request("DELETE", f"/documents/{doc_id}/pin", VIEWER)[1] == {"unpinned": True}
    found = app.handle_request("GET", "/search", VIEWER, b"", {"q": "shared"})
    assert found[0] == 200 and found[1]["documents"]


def test_exports_are_rendered_and_delivered(tmp_path):
    app = create_app(str(tmp_path))
    created = app.handle_request(
        "POST", "/documents", EDITOR,
        request_body({"title": "Memo", "body": "contents", "tags": []}))
    doc_id = created[1]["document"]["id"]
    job = app.handle_request(
        "POST", "/exports", VIEWER,
        request_body({"document": doc_id, "format": "txt"}))
    assert job[0] == 201
    job_id = job[1]["job"]["id"]
    shown = app.handle_request("GET", f"/exports/{job_id}", VIEWER)
    assert shown[1]["job"]["state"] == "done"
    delivered = app.handle_request("POST", f"/exports/{job_id}/deliver", VIEWER)
    assert delivered[0] == 200 and delivered[1]["message"].startswith("msg-")
    bundle = app.handle_request(
        "POST", "/exports", VIEWER,
        request_body({"document": doc_id, "format": "bundle"}))
    assert bundle[0] == 201


def test_notifications_digest_preferences_and_flush(tmp_path):
    app = create_app(str(tmp_path))
    digest = app.handle_request("GET", "/notifications/digest", VIEWER)
    assert digest[0] == 200
    queued = digest[1]["message"]
    updated = app.handle_request(
        "PUT", "/notifications/preferences", VIEWER,
        request_body({"mute": ["digest"]}))
    assert updated[1]["muted"] == ["digest"]
    restored = app.handle_request(
        "PUT", "/notifications/preferences", VIEWER,
        request_body({"unmute": ["digest"]}))
    assert restored[1]["muted"] == []
    assert app.handle_request("POST", "/notifications/flush", VIEWER)[1]["sent"] == [queued]


def test_usage_report_carries_the_new_sections(tmp_path):
    app = create_app(str(tmp_path))
    _, report = app.handle_request("GET", "/admin/usage", ADMIN)
    for key in ("accounts", "documents", "scopes", "trends", "health",
                "manifest", "logins", "summary"):
        assert key in report, key
    assert report["health"]["overall"] == "ok"
    assert report["summary"]


def test_backup_copies_a_scope(tmp_path):
    app = create_app(str(tmp_path))
    (tmp_path / "exports" / "note.txt").write_text("note", encoding="utf-8")
    status, payload = app.handle_request(
        "POST", "/admin/backup", ADMIN, request_body({"scope": "exports"}))
    assert status == 201
    assert payload["backup"]["copied"] == ["note.txt"]
    assert payload["backups"]


def test_ordinary_cleanup_removes_only_temporary_files(tmp_path):
    app = create_app(str(tmp_path))
    (tmp_path / "exports" / "stale.tmp").write_text("old", encoding="utf-8")
    (tmp_path / "exports" / "keep.txt").write_text("keep", encoding="utf-8")
    status, payload = app.handle_request(
        "POST", "/admin/cleanup", ADMIN,
        request_body({"scope": "exports", "target": "."}))
    assert status == 200
    assert payload["removed"] == ["stale.tmp"]
    assert payload["readiness"]["ready"] is True
    assert (tmp_path / "exports" / "keep.txt").is_file()


def test_unknown_scopes_are_refused_and_viewers_cannot_clean_up(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request(
        "POST", "/admin/cleanup", ADMIN,
        request_body({"scope": "nope", "target": "."}))[0] == 400
    assert app.handle_request(
        "POST", "/admin/cleanup", VIEWER,
        request_body({"scope": "exports", "target": "."}))[0] == 403


def test_unknown_routes_and_methods_are_rejected(tmp_path):
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "/nope", ADMIN)[0] == 404
    assert app.handle_request("GET", "/admin/cleanup", ADMIN)[0] == 405
