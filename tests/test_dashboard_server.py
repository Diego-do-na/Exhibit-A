"""Dashboard server: token and Host enforcement, headers, routing, pagination, replay ordering."""

from __future__ import annotations

import json
import socket

import pytest

from exhibit_a.dashboard import server as server_mod
from exhibit_a.dashboard.server import CSP, create_server, main
from exhibit_a.dashboard.sources import LocalRunsSource
from exhibit_a.live.replay import parse_sse
from test_dashboard_support import (
    FIXTURES,
    HOST,
    PORT,
    api,
    cookie_for,
    local_state,
    make_samples,
    request,
)


@pytest.fixture()
def state(tmp_path):
    return local_state(make_samples(tmp_path))


# -- Host header ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [None, "", "evil.example", f"evil.example:{PORT}", "127.0.0.1", f"127.0.0.1:{PORT + 1}",
     f"localhost.evil.example:{PORT}", f"127.0.0.1:{PORT}.evil.example", f"0.0.0.0:{PORT}"],
)
def test_wrong_host_is_refused_everywhere(state, host):
    for target in ("/", "/app.js", f"/auth?token={state.token}", "/api/runs"):
        status, headers, _ = request(state, target, host=host, headers=cookie_for(state))
        assert status == 421, (host, target)
        assert headers["content-security-policy"] == [CSP]
    assert state.token_used is False  # a rebinding page cannot burn the token


@pytest.mark.parametrize("host", [f"127.0.0.1:{PORT}", f"localhost:{PORT}"])
def test_loopback_hosts_are_accepted(state, host):
    status, _, _ = request(state, "/api/info", host=host, headers=cookie_for(state))
    assert status == 200


# -- token / session -------------------------------------------------------------------------


def test_api_requires_the_session_cookie(state):
    for headers in ({}, {"Cookie": "exhibit_a_dashboard=wrong"}, {"Cookie": f"other={state.session}"},
                    {"Authorization": f"Bearer {state.token}"}, {"Cookie": f"exhibit_a_dashboard={state.token}"}):
        for target in ("/api/info", "/api/runs", "/api/trends", "/api/runs/synthetic-01-starlette-proven",
                       "/api/runs/synthetic-01-starlette-proven/events", "/api/runs/synthetic-01-starlette-proven/replay"):
            status, _, body = request(state, target, headers=headers)
            assert status == 401, (headers, target)
            assert b"synthetic" not in body


def test_bootstrap_token_sets_a_strict_cookie_once(state):
    status, headers, _ = request(state, "/auth?token=wrong")
    assert status == 403 and "set-cookie" not in headers
    status, headers, _ = request(state, f"/auth?token={state.token}")
    assert status == 303 and headers["location"] == ["/"]
    [cookie] = headers["set-cookie"]
    assert cookie.startswith(f"exhibit_a_dashboard={state.session};")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    assert state.token not in cookie
    status, headers, _ = request(state, f"/auth?token={state.token}")
    assert status == 403 and "set-cookie" not in headers  # one-time
    status, _, _ = api(state, "/api/info")
    assert status == 200


def test_bootstrap_refuses_cross_site_navigation(state):
    status, _, _ = request(state, f"/auth?token={state.token}", headers={"Sec-Fetch-Site": "cross-site"})
    assert status == 403 and state.token_used is False


@pytest.mark.parametrize(
    "headers",
    [{"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}, {"Origin": "http://evil.example"},
     {"Origin": "null"}, {"Origin": f"http://127.0.0.1:{PORT + 1}"}],
)
def test_api_refuses_cross_site_reads_even_with_the_cookie(state, headers):
    status, _, _ = api(state, "/api/runs", headers=headers)
    assert status == 403


def test_same_origin_fetch_metadata_is_accepted(state):
    status, _, _ = api(state, "/api/runs", headers={"Sec-Fetch-Site": "same-origin", "Origin": f"http://{HOST}"})
    assert status == 200


def test_tokens_never_reach_the_log(state, capsys):
    request(state, f"/auth?token={state.token}", verbose=True)
    request(state, f"/auth?token={state.token}", verbose=True)
    request(state, "/api/runs?x=1", headers=cookie_for(state), verbose=True)
    err = capsys.readouterr().err
    assert "/auth 303" in err and "/api/runs 200" in err
    assert state.token not in err and state.session not in err and "token=" not in err


# -- headers and methods ------------------------------------------------------------------------


def test_every_response_carries_the_security_headers_and_no_cors(state):
    targets = ["/", "/app.js", "/style.css", "/nope", "/api/runs", "/api/runs/does-not-exist", "/auth?token=x"]
    for target in targets:
        status, headers, _ = request(state, target, headers={**cookie_for(state), "Origin": f"http://{HOST}"})
        assert headers["content-security-policy"] == [CSP], target
        assert headers["x-content-type-options"] == ["nosniff"]
        assert headers["referrer-policy"] == ["no-referrer"]
        assert headers["x-frame-options"] == ["DENY"]
        assert headers["cache-control"] == ["no-store"]
        assert not any(name.startswith("access-control-") for name in headers), target
    assert "default-src 'self'" in CSP and "frame-ancestors 'none'" in CSP and "unsafe" not in CSP


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def test_only_get_is_allowed(state, method):
    status, headers, _ = request(state, "/api/runs", method=method, headers=cookie_for(state))
    assert status == 405 and headers["allow"] == ["GET"]
    assert not any(name.startswith("access-control-") for name in headers)


def test_static_files_are_whitelisted(state):
    assert request(state, "/")[0] == 200
    status, headers, _ = request(state, "/app.js")
    assert status == 200 and headers["content-type"][0].startswith("text/javascript")
    for target in ("/../sources.py", "/%2e%2e/README.md", "/sample-ledger.jsonl", "/web/dashboard/app.js", "/index.html/"):
        assert request(state, target)[0] == 404, target


def test_long_request_targets_are_refused(state):
    assert request(state, "/" + "a" * 3000)[0] == 414


# -- API routes ------------------------------------------------------------------------------------


def test_runs_are_newest_first_and_paginated(state):
    status, _, data = api(state, "/api/runs?per_page=4")
    assert status == 200 and data["total"] == 10 and data["pages"] == 3
    assert [r["run_id"] for r in data["runs"]][:2] == ["synthetic-10-starlette-pr55", "synthetic-09-starlette-pr52"]
    _, _, last = api(state, "/api/runs?per_page=4&page=3")
    assert [r["run_id"] for r in last["runs"]] == ["synthetic-02-starlette-fixed", "synthetic-01-starlette-proven"]
    _, _, beyond = api(state, "/api/runs?per_page=4&page=9")
    assert beyond["runs"] == []
    _, _, capped = api(state, "/api/runs?per_page=100000")
    assert capped["per_page"] == server_mod.MAX_PER_PAGE


@pytest.mark.parametrize("query", ["page=0", "page=-1", "page=abc", "per_page=0", "per_page=1e3", "page=99999999999"])
def test_bad_pagination_is_a_400(state, query):
    assert api(state, f"/api/runs?{query}")[0] == 400


def test_too_many_query_fields_is_a_400(state):
    assert api(state, "/api/runs?" + "&".join(f"a{i}=1" for i in range(40)))[0] == 400


def test_run_detail_and_events(state):
    status, _, detail = api(state, "/api/runs/synthetic-03-archive-proven")
    assert status == 200 and detail["proven"][0]["evidence"]["effect"]["type"] == "canary_write"
    _, _, page = api(state, "/api/runs/synthetic-03-archive-proven/events?from=2&limit=3")
    assert [e["seq"] for e in page["events"]] == [2, 3, 4] and page["total"] == detail["run"]["event_count"]
    _, _, capped = api(state, "/api/runs/synthetic-03-archive-proven/events?limit=99999")
    assert capped["count"] == min(capped["total"], server_mod.MAX_EVENTS_PAGE)


@pytest.mark.parametrize("target", ["/api/runs/missing", "/api/runs/..%2f..%2fetc", "/api/runs/a/b/c", "/api/other", "/api/runs/%0a"])
def test_unknown_routes_and_runs_are_404(state, target):
    assert api(state, target)[0] == 404


def test_trends(state):
    _, _, data = api(state, "/api/trends?limit=3")
    assert len(data["points"]) == 3
    assert [p["started_at"] for p in data["points"]] == sorted(p["started_at"] for p in data["points"])


def test_unreadable_run_shows_no_events(tmp_path):
    folder = tmp_path / "broken"
    folder.mkdir()
    (folder / "ledger.jsonl").write_text('{"ts": "t", "run_id": "r", "type": "nope"}\n')
    st = local_state(tmp_path)
    _, _, detail = api(st, "/api/runs/broken")
    assert detail["run"]["status"] == "unreadable" and detail["proven"] == []
    assert api(st, "/api/runs/broken/events")[0] == 422
    assert api(st, "/api/runs/broken/replay")[0] == 422


# -- replay ------------------------------------------------------------------------------------------


def test_replay_streams_the_ledger_in_order(state, monkeypatch):
    monkeypatch.setattr(server_mod.time, "sleep", lambda _s: None)
    run = "synthetic-01-starlette-proven"
    _, _, events = api(state, f"/api/runs/{run}/events?limit=500")
    status, headers, body = api(state, f"/api/runs/{run}/replay?speed=4")
    assert status == 200 and headers["content-type"][0].startswith("text/event-stream")
    assert headers["content-security-policy"] == [CSP]
    frames = parse_sse(body.decode())
    steps = [f for f in frames if f["event"] == "step"]
    assert [int(f["id"]) for f in steps] == list(range(events["total"]))
    assert [json.loads(f["data"])["summary"] for f in steps] == [e["summary"] for e in events["events"]]
    assert frames[-1]["event"] == "done" and json.loads(frames[-1]["data"]) == {"count": events["total"]}


def test_replay_resumes_from_an_offset_and_paces_by_speed(state, monkeypatch):
    sleeps = []
    monkeypatch.setattr(server_mod.time, "sleep", sleeps.append)
    _, _, body = api(state, "/api/runs/synthetic-02-starlette-fixed/replay?from=5&speed=1000")
    steps = [f for f in parse_sse(body.decode()) if f["event"] == "step"]
    assert int(steps[0]["id"]) == 5 and json.loads(steps[0]["data"])["seq"] == 5
    assert sleeps and all(s == pytest.approx(0.25 / server_mod.MAX_SPEED) for s in sleeps)  # speed clamped


@pytest.mark.parametrize("speed", ["0", "-1", "nan", "inf", "fast"])
def test_replay_rejects_bad_speeds(state, speed):
    assert api(state, f"/api/runs/synthetic-02-starlette-fixed/replay?speed={speed}")[0] == 400


# -- entry point and binding ----------------------------------------------------------------------------


def test_main_rejects_bad_sources(capsys):
    assert main(["--source", "github:not a repo"]) == 2
    assert main(["--source", "ftp:x"]) == 2
    assert main(["--source", "local:/nonexistent/for/sure", "--port", "1"]) == 2
    assert main(["--source", "local:.", "--port", "70000"]) == 2
    assert "dashboard:" in capsys.readouterr().err


def test_parser_has_no_host_option():
    help_text = server_mod.build_parser().format_help()
    assert "--host" not in help_text and "--source" in help_text and "--port" in help_text


def test_create_server_binds_loopback_only():
    try:
        srv = create_server(LocalRunsSource(FIXTURES / "hostile"), port=0)
    except PermissionError as exc:  # some sandboxes forbid listening sockets
        pytest.skip(f"cannot bind a socket here: {exc}")
    try:
        host, port = srv.server_address[:2]
        assert host == "127.0.0.1" and srv.state.port == port != 0
        assert srv.state.allowed_hosts == {f"127.0.0.1:{port}", f"localhost:{port}"}
        assert srv.state.bootstrap_url() == f"http://127.0.0.1:{port}/auth?token={srv.state.token}"
        assert srv.socket.family == socket.AF_INET
    finally:
        srv.server_close()
