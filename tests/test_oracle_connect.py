"""The canary_connect effect: SSRF proven on the host path and in the Docker sandbox.

A loopback HTTP listener serves the run's token at one unguessable path. A vulnerable app
reached through its entry point requests that URL and is proven; a fixed one (allow-list,
scheme and host checks, no redirects) is not; every cheat is refused, with the static
guard on and, because it is only a tripwire, with it off. Design and limits:
docs/oracle/oracle-provenance.md, section 3.11.
"""

import json
import os
import textwrap
from pathlib import Path

import pytest

from exhibit_a.cli.parser import build_parser
from exhibit_a.graph.catalog import match_sink
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.oracle import run_oracle
from exhibit_a.oracle.guard import connect_problem
from exhibit_a.oracle.plugin import ENV_CONNECT
from exhibit_a.oracle.oracle import (
    _judge,
    canary_connect_url,
    parse_canary_url,
    pick_connect_port,
    read_connect_log,
)
from exhibit_a.oracle.provenance import AppTree

ENTRY_POINTS = {"App.handle_request"}
PROVEN = ("failed", True, True)

URL_LINE = 'URL = os.environ["EXHIBIT_A_CANARY_URL"]'
TOKEN_LINE = 'TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]'

# -- applications ------------------------------------------------------------------------------

DIRECT_APP = '''\
import urllib.request


class App:
    def handle_request(self, url):
        """Entry point: fetch the caller's URL unchecked (the bug)."""
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode()
'''

HOST_APP = '''\
import urllib.request


class App:
    def handle_request(self, host, resource=""):
        """Entry point: build the URL from the caller's host (the bug)."""
        with urllib.request.urlopen("http://" + host + "/" + resource, timeout=5) as resp:
            return resp.read().decode()
'''

ALLOWLIST_APP = '''\
import urllib.parse
import urllib.request

ALLOWED = {"api.example.com"}


class App:
    def handle_request(self, url):
        """Entry point: fetch only allow-listed hosts (the fix)."""
        host = urllib.parse.urlsplit(url).hostname or ""
        if host not in ALLOWED:
            raise ValueError("host not allowed: " + host)
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode()
'''

SCHEME_HOST_APP = '''\
import urllib.parse
import urllib.request


class App:
    def handle_request(self, url):
        """Entry point: fetch only https URLs on the expected host (the fix)."""
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname != "api.example.com":
            raise ValueError("refused: " + url)
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode()
'''

NOREDIRECT_APP = '''\
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class App:
    def handle_request(self, url):
        """Entry point: fetch without following redirects (the fix)."""
        with _OPENER.open(url, timeout=5) as resp:
            return resp.read().decode()
'''

ECHO_APP = '''\
class App:
    def handle_request(self, data):
        """Entry point: repeat the input, fetch nothing (safe)."""
        return {"echo": data}
'''

HELPER_APP = '''\
import urllib.request

SAFE = "http://example.com/"


def fetch(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read().decode()


class App:
    def handle_request(self, name):
        """Entry point: fetch a fixed page (safe)."""
        return fetch(SAFE + name)
'''

# Safe by construction, and it says where to fetch in module bindings the test could swap:
# the "R5" shape of section 3.11.
R5_APP = '''\
import urllib.request

SCHEME = "http"
HOST = "api.example.com"


class App:
    def handle_request(self, path):
        """Entry point: fetch a fixed host (safe)."""
        with urllib.request.urlopen(SCHEME + "://" + HOST + "/" + path, timeout=5) as resp:
            return resp.read().decode()
'''

# -- exploits ----------------------------------------------------------------------------------

PRELUDE = '''\
import os
from app import App

URL = os.environ["EXHIBIT_A_CANARY_URL"]
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
'''


def exploit(body):
    """A test that sends one payload and fails if the token came back in the response."""
    return PRELUDE + "\ndef test_exploit():\n" + textwrap.indent(textwrap.dedent(body), "    ")


DIRECT_EXPLOIT = exploit('''\
try:
    body = App().handle_request(URL)
except Exception:
    return
assert TOKEN not in body
''')

HOST_EXPLOIT = exploit('''\
import urllib.parse
parts = urllib.parse.urlsplit(URL)
try:
    body = App().handle_request(parts.netloc, parts.path.lstrip("/"))
except Exception:
    return
assert TOKEN not in body
''')

REDIRECT_EXPLOIT = PRELUDE + '''\
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", URL)
        self.end_headers()

    def log_message(self, *args):
        pass


def test_exploit():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            body = App().handle_request(f"http://127.0.0.1:{port}/start")
        except Exception:
            return
        assert TOKEN not in body
    finally:
        server.shutdown()
        thread.join(timeout=10)
'''

TRUE_CASES = [
    ("direct_fetch", DIRECT_APP, DIRECT_EXPLOIT),
    ("host_injection", HOST_APP, HOST_EXPLOIT),
    ("redirect_follow", DIRECT_APP, REDIRECT_EXPLOIT),
]

FIXED_CASES = [
    ("allow_list", ALLOWLIST_APP, DIRECT_EXPLOIT),
    ("scheme_and_host", SCHEME_HOST_APP, DIRECT_EXPLOIT),
    ("no_redirects", NOREDIRECT_APP, REDIRECT_EXPLOIT),
]


def cheat(body, header=""):
    """A test that works around the app, then fails by its own doing."""
    return (PRELUDE + header + "\ndef test_exploit():\n" + textwrap.indent(textwrap.dedent(body), "    "))


CHEATS = {
    "test_connects_itself": (DIRECT_APP, cheat(
        "import socket\n"
        "host, _, rest = URL.split('/')[2].partition(':')\n"
        "port = int(rest.split('/')[0]) if rest else 80\n"
        "sock = socket.create_connection((host, port), timeout=5)\n"
        "sock.close()\n"
        "assert False\n")),
    "test_requests_the_url_itself": (DIRECT_APP, cheat(
        "import urllib.request\n"
        "with urllib.request.urlopen(URL, timeout=5) as resp:\n"
        "    body = resp.read().decode()\n"
        "assert False, body[:10]\n")),
    "test_resolves_the_canary_host": (DIRECT_APP, cheat(
        "import socket\n"
        "host = URL.split('/')[2].split(':')[0]\n"
        "socket.getaddrinfo(host, 80)\n"
        "assert False\n")),
    "test_reads_the_listeners_log": (DIRECT_APP, cheat(
        "data = open('/oracle/connect.jsonl', encoding='utf-8').read()\n"
        "assert False, data[:10]\n")),
    "test_uses_a_raw_socket": (DIRECT_APP, cheat(
        "import socket\n"
        "import urllib.parse\n"
        "parts = urllib.parse.urlsplit(URL)\n"
        "sock = socket.create_connection((parts.hostname, parts.port), timeout=5)\n"
        "sock.sendall(('GET ' + parts.path + ' HTTP/1.0\\r\\n\\r\\n').encode())\n"
        "body = sock.recv(4096).decode()\n"
        "sock.close()\n"
        "assert False, body[:10]\n")),
    "test_feeds_the_token_back_through_an_echo_app": (ECHO_APP, cheat(
        "assert TOKEN not in str(App().handle_request(TOKEN))\n")),
    "test_calls_an_internal_helper_directly": (HELPER_APP, cheat(
        "import app\n"
        "assert TOKEN not in app.fetch(URL)\n", "")),
    "test_runs_the_request_in_a_thread": (HELPER_APP, cheat(
        "import threading\n"
        "import app\n"
        "out = []\n"
        "thread = threading.Thread(target=lambda: out.append(app.fetch(URL)))\n"
        "thread.start()\n"
        "thread.join(timeout=30)\n"
        "assert TOKEN not in str(out)\n", "")),
}


@pytest.fixture
def unguarded(monkeypatch):
    """The guard is bypassable by obfuscation, so what is under it must hold alone."""
    monkeypatch.setattr("exhibit_a.oracle.oracle.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.oracle.oracle.connect_problem", lambda path: None)


@pytest.fixture
def unguarded_sandbox(monkeypatch):
    monkeypatch.setattr("exhibit_a.loop.runner.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.loop.runner.connect_problem", lambda path: None)


def layout(tmp_path, source, test_source):
    root, tests = tmp_path / "app", tmp_path / "tests"
    root.mkdir()
    tests.mkdir()
    (root / "app.py").write_text(source, encoding="utf-8")
    (tests / "test_exploit.py").write_text(test_source, encoding="utf-8")
    return root, tests / "test_exploit.py"


def host(tmp_path, source, test_source, entry_points=ENTRY_POINTS):
    root, test = layout(tmp_path, source, test_source)
    return run_oracle(root, test, entry_points, effect="canary_connect", timeout=60.0)


def sandbox(tmp_path, source, test_source, entry_points=ENTRY_POINTS):
    root, test = layout(tmp_path, source, test_source)
    return SandboxRunner().run_exploit(root, test, entry_points, timeout=120.0, effect="canary_connect")


def shape(j):
    return j.test_outcome, j.observed_effect, j.provenance_ok


# -- host path ---------------------------------------------------------------------------------


@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []


def test_the_proof_records_the_connection_and_the_request(tmp_path):
    j = host(tmp_path, DIRECT_APP, DIRECT_EXPLOIT)
    assert shape(j) == PROVEN, j.reason
    ops = [e.op for e in j.events]
    assert "connect" in ops and "request" in ops
    [request] = [e for e in j.events if e.op == "request" and e.mode == "urllib.Request"]
    assert request.url is not None and request.url.startswith("http://127.0.0.1:")
    admitted = [f.qualname for e in j.events for f in e.stack if f.admitted]
    assert "App.handle_request" in admitted


@pytest.mark.parametrize(
    "source, test_source", [c[1:] for c in FIXED_CASES], ids=[c[0] for c in FIXED_CASES],
)
def test_a_fixed_app_is_not_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) == ("passed", False, False), j.reason
    assert j.reason_code == "no_effect" and j.forged_events == 0 and j.app_tree_changes == []


def test_a_fixed_app_that_refuses_up_front_opens_no_connection(tmp_path):
    j = host(tmp_path, ALLOWLIST_APP, DIRECT_EXPLOIT)
    assert shape(j) == ("passed", False, False), j.reason
    assert not [e for e in j.events if e.op in ("connect", "request")]


def test_a_vulnerable_app_whose_test_never_sends_the_url_is_not_proven(tmp_path):
    test_source = exploit('''\
try:
    App().handle_request("http://127.0.0.1:9/nothing-here")
except Exception:
    pass
assert False, "the test fails for the wrong reason"
''')
    assert shape(host(tmp_path, DIRECT_APP, test_source)) == ("failed", False, False)


def test_a_request_of_the_canary_that_does_not_fail_the_test_is_not_proven(tmp_path):
    test_source = exploit('''\
try:
    body = App().handle_request(URL)
except Exception:
    return
assert True
''')
    j = host(tmp_path, DIRECT_APP, test_source)
    assert shape(j) == ("passed", True, True) and j.reason_code == "no_effect"


@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_guard_on(tmp_path, name):
    source, test_source = CHEATS[name]
    j = host(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_guard_off(tmp_path, unguarded, name):
    source, test_source = CHEATS[name]
    j = host(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.parametrize("name, code", [
    ("test_connects_itself", "connect_from_test"),
    ("test_requests_the_url_itself", "connect_from_test"),
    ("test_resolves_the_canary_host", "connect_from_test"),
    ("test_reads_the_listeners_log", "no_effect"),
    ("test_uses_a_raw_socket", "connect_from_test"),
    ("test_feeds_the_token_back_through_an_echo_app", "no_effect"),
    ("test_calls_an_internal_helper_directly", "provenance"),
    ("test_runs_the_request_in_a_thread", "provenance"),
])
def test_the_runtime_layer_says_why_a_cheat_is_refused(tmp_path, unguarded, name, code):
    source, test_source = CHEATS[name]
    assert host(tmp_path, source, test_source).reason_code == code


def test_the_guard_refuses_a_cheat_before_it_runs(tmp_path):
    marker = tmp_path / "ran"
    source, test_source = CHEATS["test_connects_itself"]
    test_source = test_source + f"\nopen({str(marker)!r}, 'a').close()\n"
    root, test = layout(tmp_path, source, test_source)
    j = run_oracle(root, test, ENTRY_POINTS, effect="canary_connect", timeout=60.0)
    assert j.reason_code == "channel_tripwire" and j.test_outcome == "error"
    assert not marker.exists()


def test_a_test_that_touches_the_url_but_never_the_network_is_allowed(tmp_path):
    source = PRELUDE + '''\
import urllib.parse


def test_exploit():
    parts = urllib.parse.urlsplit(URL)
    assert parts.port and TOKEN
'''
    assert connect_problem(layout(tmp_path, DIRECT_APP, source)[1]) is None


# -- residual limits, pinned -------------------------------------------------------------------

# R1: with computed names the test finds the plugin's signer in its own process and signs
# the connection and the request an app would have produced. On the host path the
# listener's log stops it: the test cannot learn the log's path, so nothing it signs
# matches a recorded request. This test pins that the signed events alone prove nothing.
FORGE_CONNECT_EVENTS = '''
import sys


def test_exploit():
    module = sys.modules["ap" + "p"]
    caller = {"file": __file__, "function": "test_exploit", "qualname": "test_exploit", "line": 4}
    frame = {"file": module.__file__, "function": "handle_request",
             "qualname": "App.handle_request",
             "line": getattr(getattr(module.App.handle_request, "__co" + "de__"),
                             "co_first" + "lineno"),
             "admitted": True}
    collector = __import__("g" + "c")
    emit = [o for o in getattr(collector, "get_" + "objects")()
            if getattr(o, "__name__", "") == "emit"
            and getattr(o, "__module__", "").endswith("plugin")][0]
    host, _, rest = URL.split("/")[2].partition(":")
    port = int(rest.split("/")[0])
    base = {"path": URL, "flags": None, "access": "unknown", "requested": None,
            "via_symlink": False, "stack": [caller, frame], "host": host, "port": port, "url": None}
    emit({**base, "mode": "socket.connect", "op": "connect"})
    emit({**base, "mode": "urllib.Request", "op": "request", "url": URL})
    assert False
'''


def test_forged_signed_events_without_a_listener_record_prove_nothing(tmp_path):
    """R1 on the host path: stolen-key events alone are not a proof without the log."""
    assert shape(host(tmp_path, ALLOWLIST_APP, PRELUDE + FORGE_CONNECT_EVENTS)) == ("failed", False, False)


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R5 (docs/oracle/oracle-provenance.md 7.5 and 3.11): an app's own binding replaced by computed names",
)
def test_r5_a_replaced_app_binding_proves_a_safe_app(tmp_path):
    test_source = PRELUDE + '''\
import sys


def test_exploit():
    netloc = URL.split("/")[2]
    secret = URL.rsplit("/", 1)[1]
    setattr(sys.modules["ap" + "p"], "HO" + "ST", netloc + "/" + secret)
    try:
        body = App().handle_request("anything")
    except Exception:
        return
    assert TOKEN not in body
'''
    assert shape(host(tmp_path, R5_APP, test_source)) != PROVEN


# -- the guard ---------------------------------------------------------------------------------


def guard(tmp_path, source):
    path = tmp_path / "test_x.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return connect_problem(path)


@pytest.mark.parametrize("line", [
    "import socket",
    "import socket as s",
    "from socket import create_connection",
    "from urllib.request import urlopen",
    "import urllib.request",
    "import http.client",
    "from http.client import HTTPConnection",
    "import requests",
    "import httpx",
    "import aiohttp",
    "import urllib3",
    "sock = socket.create_connection(('h', 1))",
    "urllib.request.urlopen('http://x/')",
    "http.client.HTTPConnection('h')",
    "open('/oracle/connect.jsonl').read()",
    "x = 'canary_server.py'",
])
def test_the_guard_refuses_a_test_that_connects_itself(tmp_path, line):
    assert guard(tmp_path, f"def test_exploit():\n    {line}\n") is not None


@pytest.mark.parametrize("source", [
    "from app import App\ndef test_exploit():\n    assert 'x' not in str(App().handle_request(URL))\n",
    "import urllib.parse\ndef test_exploit():\n    assert urllib.parse.urlsplit(URL).port\n",
    "import os\ndef test_exploit():\n    assert os.environ['EXHIBIT_A_CANARY_URL']\n",
    "import os\ndef test_exploit():\n    assert os.environ['EXHIBIT_A_CANARY_TOKEN']\n",
])
def test_the_guard_allows_a_test_that_uses_only_the_contract(tmp_path, source):
    assert guard(tmp_path, source) is None


def test_the_guard_checks_a_shipped_conftest(tmp_path):
    (tmp_path / "conftest.py").write_text("import socket\n")
    path = tmp_path / "test_x.py"
    path.write_text("def test_exploit():\n    pass\n")
    assert "conftest.py" in connect_problem(path)


# -- plumbing ----------------------------------------------------------------------------------


def test_cli_accepts_the_effect():
    args = build_parser().parse_args(["run", "--effect", "canary_connect", "--pr-diff", "a..b"])
    assert args.effect == "canary_connect"


def test_the_contract_names_the_url_and_the_token_but_never_the_network():
    from exhibit_a.loop import prompts

    text = prompts.test_contract("canary_connect", ["pkg==1"])
    assert "EXHIBIT_A_CANARY_URL" in text and "EXHIBIT_A_CANARY_TOKEN" in text and "pkg==1" in text
    assert "EXHIBIT_A_CANARY_SQL" not in text and "EXHIBIT_A_CANARY=" not in text
    assert "never open a socket" in text.lower()


@pytest.mark.parametrize("name", ["urllib.request.urlopen", "http.client.HTTPSConnection",
                                  "requests.get", "httpx.Client.post"])
def test_the_catalog_maps_request_sinks_to_the_effect(name):
    rule = match_sink(name)
    assert (rule.vuln_class, rule.effect) == ("ssrf", "canary_connect")


def test_the_catalog_maps_a_variable_connection_target_to_the_effect():
    rule = match_sink("socket.create_connection")
    assert (rule.vuln_class, rule.effect) == ("ssrf", "canary_connect")


def test_canary_url_helpers_round_trip():
    url = canary_connect_url(23456, "abc")
    assert url == "http://127.0.0.1:23456/abc"
    assert parse_canary_url(url) == ("127.0.0.1", 23456, "/abc")
    assert parse_canary_url("http://127.0.0.1:23456/abc") == ("127.0.0.1", 23456, "/abc")
    for bad in ["http://127.0.0.1/abc", "http://127.0.0.1:80/", "https://127.0.0.1:1/a",
                "http://example.com:1/a", "http://127.0.0.1:1", None, 42, ""]:
        assert parse_canary_url(bad) is None
    assert all(20000 <= pick_connect_port() <= 59999 for _ in range(10))


def test_read_connect_log_keeps_only_records(tmp_path):
    log = tmp_path / "connect.jsonl"
    log.write_text('{"kind": "request", "target": "/s"}\nnot json\n{"kind": "connection"}\n[1, 2]\n')
    records = read_connect_log(log)
    assert [r["kind"] for r in records] == ["request", "connection"]
    assert read_connect_log(tmp_path / "missing.jsonl") == []


# -- what the judge refuses --------------------------------------------------------------------


def _connect_event(**fields):
    from exhibit_a.oracle import OracleEvent

    stack = [
        {"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
        {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
         "line": 5, "admitted": True},
    ]
    base = {"path": "http://127.0.0.1:23456/secret", "mode": "socket.connect", "op": "connect",
            "access": "unknown", "host": "127.0.0.1", "port": 23456, "url": None, "stack": stack}
    return OracleEvent.model_validate({**base, **fields})


def _request_event(mode="urllib.Request", url="http://127.0.0.1:23456/secret", **fields):
    return _connect_event(op="request", mode=mode, host=None, port=None, url=url, **fields)


@pytest.fixture
def tree(tmp_path):
    import hashlib

    source = "class App:\n\n\n\n    def handle_request(self):\n        pass\n"
    (tmp_path / "app.py").write_text(source)
    return AppTree("/a", tmp_path, {"app.py": hashlib.sha256(source.encode()).hexdigest()})


def judge(tree, events, log=None, url="http://127.0.0.1:23456/secret", outcome="failed"):
    return _judge(outcome, events, Path("/a"), Path("/t/test_exploit.py"), ENTRY_POINTS,
                  effect="canary_connect", app_tree=tree, canary_url=url,
                  connect_log=[{"target": "/secret"}] if log is None else log)


def test_the_judge_proves_only_when_everything_holds(tree):
    j = judge(tree, [_connect_event(), _request_event()])
    assert shape(j) == PROVEN and j.reason_code == ""


def test_a_send_target_plus_a_connection_is_a_proof(tree):
    send = _request_event(mode="http.client.send", url="/secret")
    assert shape(judge(tree, [_connect_event(), send])) == PROVEN


def test_no_listener_record_is_not_a_proof(tree):
    j = judge(tree, [_connect_event(), _request_event()], log=[])
    assert shape(j) == ("failed", False, False) and j.reason_code == "no_effect"


def test_a_listener_record_for_another_path_is_not_a_proof(tree):
    j = judge(tree, [_connect_event(), _request_event()], log=[{"target": "/other"}])
    assert shape(j) == ("failed", False, False) and j.reason_code == "no_effect"


def test_no_matching_request_is_not_a_proof(tree):
    j = judge(tree, [_connect_event()])
    assert shape(j) == ("failed", True, False) and j.reason_code == "provenance"


def test_no_matching_connection_is_not_a_proof(tree):
    j = judge(tree, [_request_event()])
    assert shape(j) == ("failed", True, False) and j.reason_code == "provenance"


def test_a_connection_to_another_port_is_not_a_match(tree):
    event = _connect_event(port=9999)
    j = judge(tree, [event, _request_event()], log=[{"target": "/secret"}])
    assert shape(j) == ("failed", True, False) and j.reason_code == "provenance"


def test_a_request_to_another_host_is_not_a_match(tree):
    event = _request_event(url="http://example.com:23456/secret")
    j = judge(tree, [_connect_event(), event])
    assert shape(j) == ("failed", True, False) and j.reason_code == "provenance"


def test_a_test_frame_connection_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1}]
    j = judge(tree, [_connect_event(stack=stack), _connect_event(), _request_event()])
    assert j.reason_code == "connect_from_test"


def test_a_lookup_from_a_test_frame_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1}]
    lookup = _connect_event(mode="socket.getaddrinfo", stack=stack)
    j = judge(tree, [lookup, _connect_event(), _request_event()])
    assert j.reason_code == "connect_from_test"


def test_an_unadmitted_frame_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
             {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
              "line": 5, "admitted": False, "admission": "code object differs"}]
    j = judge(tree, [_connect_event(stack=stack), _request_event(stack=stack)])
    assert j.reason_code == "frame_not_admitted"


def test_a_request_not_reached_through_the_entry_point_is_not_a_proof(tree):
    # The host re-check rejects the frame first: the staged source has no App.other, so the
    # frame is not admitted. The entry-point miss itself is pinned by
    # test_calls_an_internal_helper_directly on the host path, with real admitted frames.
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
             {"file": "/a/app.py", "function": "other", "qualname": "App.other", "line": 5, "admitted": True}]
    j = judge(tree, [_connect_event(stack=stack), _request_event(stack=stack)])
    assert shape(j) == ("failed", True, False) and j.reason_code in ("provenance", "frame_not_admitted")


def test_a_passing_test_is_not_a_proof(tree):
    j = judge(tree, [_connect_event(), _request_event()], outcome="passed")
    assert shape(j) == ("passed", True, True) and j.reason_code == "no_effect"


def test_without_the_staged_app_nothing_is_proven():
    j = _judge("failed", [_connect_event(), _request_event()], Path("/a"), Path("/t/test_exploit.py"),
               ENTRY_POINTS, effect="canary_connect", app_tree=None,
               canary_url="http://127.0.0.1:23456/secret", connect_log=[{"target": "/secret"}])
    assert shape(j) != PROVEN


def test_without_the_canary_url_nothing_matches(tree):
    j = judge(tree, [_connect_event(), _request_event()], url=None)
    assert shape(j) != PROVEN and j.reason_code == "no_effect"


# -- fixture trees -----------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures" / "connect"


def test_the_shipped_fixture_trees_prove_and_refuse_on_the_host_path(tmp_path):
    root = tmp_path / "app"
    tests = tmp_path / "tests"
    root.mkdir()
    tests.mkdir()
    (root / "app.py").write_text((FIXTURES / "vulnerable" / "app.py").read_text(), encoding="utf-8")
    (tests / "test_exploit.py").write_text(DIRECT_EXPLOIT, encoding="utf-8")
    proven = run_oracle(root, tests / "test_exploit.py", ENTRY_POINTS,
                        effect="canary_connect", timeout=60.0)
    assert shape(proven) == PROVEN, proven.reason
    (root / "app.py").write_text((FIXTURES / "fixed" / "app.py").read_text(), encoding="utf-8")
    refused = run_oracle(root, tests / "test_exploit.py", ENTRY_POINTS,
                         effect="canary_connect", timeout=60.0)
    assert shape(refused) == ("passed", False, False), refused.reason


# -- sandbox plumbing (no container) -----------------------------------------------------------

CONNECT_URL = "http://127.0.0.1:23456/abcdef"


def _fake_docker(monkeypatch, tmp_path, on_run):
    """A fake `docker run`: records the argv, lets ``on_run`` act for the container."""
    import subprocess as real

    from exhibit_a.sandbox import runner

    calls = []

    def fake(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            on_run(cmd)
            return real.CompletedProcess(cmd, 1, b"", b"")
        return real.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(runner.subprocess, "run", fake)
    monkeypatch.setattr(runner, "_check_docker_available", lambda: True)
    monkeypatch.setattr(runner, "build_image", lambda reqs: "image:test")
    monkeypatch.setenv("HOME", str(tmp_path))
    return calls


def _connect_run_kwargs(tmp_path, env_extra=None):
    env = {"EXHIBIT_A_CANARY_TOKEN": "CANARY-x", ENV_CONNECT: CONNECT_URL}
    env.update(env_extra or {})
    events = tmp_path / "events.jsonl"
    events.write_text("")
    return {"image": "i", "effect": "canary_connect", "events_path": str(events), "env": env}


def test_the_sandbox_refuses_a_connect_run_it_could_not_set_up(tmp_path, monkeypatch):
    from exhibit_a.sandbox.runner import ENV_CONNECT as CONNECT_ENV
    from exhibit_a.sandbox.runner import run

    _fake_docker(monkeypatch, tmp_path, lambda cmd: None)
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "test_x.py").write_text("")
    base = _connect_run_kwargs(tmp_path)
    no_url = dict(base, env={"EXHIBIT_A_CANARY_TOKEN": "CANARY-x"})
    bad_url = _connect_run_kwargs(tmp_path, {"EXHIBIT_A_CANARY_URL": "http://example.com/"})
    with_canary = dict(base, canary_path=str(clone / "test_x.py"))
    tokenless = {k: v for k, v in base["env"].items() if k != "EXHIBIT_A_CANARY_TOKEN"}
    no_token = dict(base, env=tokenless)
    results = [run(str(clone), "test_x.py", 5, **kwargs)
               for kwargs in (no_url, bad_url, with_canary, no_token)]
    assert {r["outcome"] for r in results} == {"env_failure"}
    assert CONNECT_ENV == "EXHIBIT_A_CANARY_URL"


def test_the_sandbox_starts_the_listener_and_collects_its_log(tmp_path, monkeypatch):
    from exhibit_a.sandbox import runner

    def on_run(cmd):
        # The container serves the URL from the read-only server copy and logs to the
        # writable log mount; the network stays off.
        assert any(part.endswith(":/opt/exhibit_a_plugin/canary_server.py:ro") for part in cmd)
        assert any(part.endswith(":/oracle/connect.jsonl:rw") for part in cmd)
        assert f"{runner._CONNECT_ENV}={CONNECT_URL}" in " ".join(cmd)
        assert "--network" in cmd and "none" in cmd

    calls = _fake_docker(monkeypatch, tmp_path, on_run)
    from exhibit_a.sandbox.runner import run

    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "test_x.py").write_text("")
    result = run(str(clone), "test_x.py", 5, **_connect_run_kwargs(tmp_path))
    assert result["outcome"] == "failed"  # the fake container exits 1
    assert result["connect_log"] == []
    assert result["oracle_forged_events"] == 0
    assert any(cmd[:2] == ["docker", "run"] for cmd in calls)


def test_the_loop_runner_hands_the_url_and_the_log_to_the_judge(tmp_path, monkeypatch):
    import exhibit_a.sandbox

    seen = {}

    def fake_run(*args, **kwargs):
        seen.update(kwargs)
        return {"outcome": "failed", "exit_code": 1, "stdout": "", "stderr": "",
                "oracle_events": [], "oracle_forged_events": 0, "oracle_forged_reason": "",
                "app_tree_changes": [], "connect_log": [{"target": "/s"}]}

    monkeypatch.setattr(exhibit_a.sandbox, "run", fake_run)
    root, test = layout(tmp_path, DIRECT_APP, DIRECT_EXPLOIT)
    j = SandboxRunner().run_exploit(root, test, ENTRY_POINTS, timeout=60.0, effect="canary_connect")
    assert seen["effect"] == "canary_connect"
    assert seen["env"]["EXHIBIT_A_CANARY_URL"].startswith("http://127.0.0.1:")
    assert seen["canary_path"] is None
    assert j.reason_code == "no_effect"  # no events and a foreign log record: nothing proven


# -- docker sandbox ----------------------------------------------------------------------------


@pytest.mark.docker
@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_in_the_sandbox(tmp_path, source, test_source):
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []
    assert any(e.op == "request" and (e.url or "").startswith("http://127.0.0.1:") for e in j.events)


@pytest.mark.docker
@pytest.mark.parametrize(
    "source, test_source", [c[1:] for c in FIXED_CASES], ids=[c[0] for c in FIXED_CASES],
)
def test_a_fixed_app_is_not_proven_in_the_sandbox(tmp_path, source, test_source):
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) == ("passed", False, False), j.reason


@pytest.mark.docker
@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_in_the_sandbox_guard_on(tmp_path, name):
    source, test_source = CHEATS[name]
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.docker
@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_in_the_sandbox_guard_off(tmp_path, unguarded_sandbox, name):
    source, test_source = CHEATS[name]
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.docker
def test_a_forged_listener_record_without_a_signed_request_proves_nothing(tmp_path, unguarded_sandbox):
    test_source = PRELUDE + '''\
import json


def test_exploit():
    base = URL.rsplit("/", 1)[0] + "/"
    try:
        App().handle_request(base)
    except Exception:
        pass
    secret = URL.rsplit("/", 1)[1]
    with open("/oracle/connect.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"kind": "request", "target": "/" + secret}) + "\\n")
    assert False
'''
    j = sandbox(tmp_path, DIRECT_APP, test_source)
    assert shape(j) != PROVEN and j.test_outcome == "failed", j.reason


@pytest.mark.docker
@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R1 (docs/oracle/oracle-provenance.md 7.1 and 3.11): in the sandbox the log path is "
           "fixed, so a test that steals the key can forge both the signed events and the log",
)
def test_r1_key_theft_and_log_forgery_forge_a_proof_in_the_sandbox(tmp_path, unguarded_sandbox):
    test_source = PRELUDE + '''\
import json
import sys


def test_exploit():
    module = sys.modules["ap" + "p"]
    caller = {"file": __file__, "function": "test_exploit", "qualname": "test_exploit", "line": 4}
    frame = {"file": module.__file__, "function": "handle_request",
             "qualname": "App.handle_request",
             "line": getattr(getattr(module.App.handle_request, "__co" + "de__"),
                             "co_first" + "lineno"),
             "admitted": True}
    collector = __import__("g" + "c")
    emit = [o for o in getattr(collector, "get_" + "objects")()
            if getattr(o, "__name__", "") == "emit"
            and getattr(o, "__module__", "").endswith("plugin")][0]
    host, _, rest = URL.split("/")[2].partition(":")
    port = int(rest.split("/")[0])
    base = {"path": URL, "flags": None, "access": "unknown", "requested": None,
            "via_symlink": False, "stack": [caller, frame], "host": host, "port": port, "url": None}
    emit({**base, "mode": "socket.connect", "op": "connect"})
    emit({**base, "mode": "urllib.Request", "op": "request", "url": URL})
    secret = URL.rsplit("/", 1)[1]
    with open("/oracle/connect.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"kind": "request", "target": "/" + secret}) + "\\n")
    assert False
'''
    j = sandbox(tmp_path, ALLOWLIST_APP, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.docker
def test_the_sandbox_keeps_its_limits_for_the_connect_effect(tmp_path, monkeypatch):
    from exhibit_a.sandbox import runner as sandbox_runner

    seen = []
    real_run = sandbox_runner.subprocess.run

    def spy(cmd, *args, **kwargs):
        if isinstance(cmd, list) and cmd[:2] == ["docker", "run"]:
            seen.append(list(cmd))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(sandbox_runner.subprocess, "run", spy)
    assert shape(sandbox(tmp_path, DIRECT_APP, DIRECT_EXPLOIT)) == PROVEN
    assert seen, "the sandbox never ran a container"
    joined = " ".join(seen[-1])
    for flag in ("--network none", "--cap-drop ALL", "no-new-privileges", "--pids-limit", "--memory"):
        assert flag in joined, joined
    assert ":/opt/exhibit_a_plugin/canary_server.py:ro" in joined
    assert ":/oracle/connect.jsonl:rw" in joined


@pytest.mark.docker
def test_the_container_has_no_network_interface_besides_loopback():
    """The sandbox keeps --network none: only lo exists, and the outside is unreachable."""
    from exhibit_a.sandbox import probe_isolation

    result = probe_isolation()
    assert result["ok"], result.get("error")
    assert result["probe"]["network"]["interfaces"] == ["lo"]
    assert result["probe"]["network"]["external_connect_blocked"] is True



