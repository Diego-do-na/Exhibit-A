"""The canary_redirect effect: open redirect proven on the host path and in the Docker sandbox.

The runner hands the test a per-run canary URL and calls the entry point itself through
the ``redirect_probe`` fixture, signing the observed response. A vulnerable app that
redirects to the canary host through its entry point is proven; a fixed one (allow-listed
redirect targets) is not; every cheat is refused, with the static guard on and, because
it is only a tripwire, with it off. Design and limits:
docs/oracle/oracle-provenance.md, section 3.13.
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
from exhibit_a.oracle.guard import redirect_problem
from exhibit_a.oracle.oracle import (
    _judge,
    _meta_refresh_host,
    parse_redirect_host,
    redirect_canary_host,
    redirect_canary_url,
)
from exhibit_a.oracle.plugin import ENV_REDIRECT
from exhibit_a.oracle.provenance import AppTree

ENTRY_POINTS = {"App.handle_request"}
PROVEN = ("failed", True, True)

URL_LINE = 'URL = os.environ["EXHIBIT_A_CANARY_REDIRECT"]'
TOKEN_LINE = 'TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]'

# -- applications ------------------------------------------------------------------------------

DIRECT_APP = '''\
class App:
    def handle_request(self, target):
        """Entry point: redirect to the caller's URL unchecked (the bug)."""
        return (302, {"Location": target}, "Found")
'''

HOST_APP = '''\
import urllib.parse


class App:
    def handle_request(self, host, resource=""):
        """Entry point: build the redirect from the caller's host (the bug)."""
        target = "https://" + host + "/" + resource
        return {"status": 302, "headers": {"Location": target}, "body": "Found"}
'''

META_APP = """\
class App:
    def handle_request(self, target):
        \"\"\"Entry point: answer with a meta refresh to the caller's URL (the bug).\"\"\"
        return {"status": 200, "headers": {"Content-Type": "text/html"},
                "body": "<html><head><meta http-equiv='refresh' content='0;url=" + target + "'></head></html>"}
"""

ALLOWLIST_APP = '''\
import urllib.parse

ALLOWED = {"shop.example.com"}


class App:
    def handle_request(self, target):
        """Entry point: redirect only to allow-listed hosts (the fix)."""
        host = urllib.parse.urlsplit(target).hostname or ""
        if host not in ALLOWED:
            raise ValueError("refusing an off-site redirect")
        return (302, {"Location": target}, "Found")
'''

ALLOWLIST_HOST_APP = '''\
import urllib.parse

ALLOWED = {"shop.example.com"}


class App:
    def handle_request(self, host, resource=""):
        """Entry point: redirect only to allow-listed hosts (the fix)."""
        if host not in ALLOWED:
            raise ValueError("refusing an off-site redirect")
        return {"status": 302, "headers": {"Location": "https://" + host + "/" + resource},
                "body": "Found"}
'''

NO_META_APP = '''\
class App:
    def handle_request(self, target):
        """Entry point: answer with a plain page, never a refresh (the fix)."""
        return {"status": 200, "headers": {"Content-Type": "text/html"},
                "body": "<html><head><title>gone</title></head></html>"}
'''

ECHO_APP = '''\
class App:
    def handle_request(self, data):
        """Entry point: repeat the input, redirect nowhere (safe)."""
        return {"status": 200, "headers": {}, "body": data}
'''

HELPER_APP = '''\
SAFE = "https://shop.example.com/home"


def redirect_to(target):
    return (302, {"Location": target}, "Found")


class App:
    def handle_request(self, name):
        """Entry point: redirect to a fixed page (safe)."""
        return redirect_to(SAFE + name)
'''

# Safe by construction, and it says where to redirect in a module binding the test could swap:
# the "R5" shape of section 3.13.
R5_APP = '''\
import urllib.parse

ALLOWED = "shop.example.com"


class App:
    def handle_request(self, target):
        """Entry point: redirect only to the configured host (safe)."""
        host = urllib.parse.urlsplit(target).hostname or ""
        if host != ALLOWED:
            raise ValueError("refusing an off-site redirect")
        return (302, {"Location": target}, "Found")
'''

# -- exploits ----------------------------------------------------------------------------------

PRELUDE = '''\
import os

URL = os.environ["EXHIBIT_A_CANARY_REDIRECT"]
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
'''


def exploit(body):
    """A test that sends one target and fails if the app redirected to the canary."""
    return "import os\nfrom app import App\n\n" + URL_LINE + "\n" + TOKEN_LINE + "\n\ndef test_exploit(redirect_probe):\n" + textwrap.indent(textwrap.dedent(body), "    ")


DIRECT_EXPLOIT = exploit('''\
try:
    resp = redirect_probe(App().handle_request, URL)
except Exception:
    return
assert resp["location"] != URL, resp
''')

HOST_EXPLOIT = exploit('''\
import urllib.parse
parts = urllib.parse.urlsplit(URL)
try:
    resp = redirect_probe(App().handle_request, parts.netloc, parts.path.lstrip("/"))
except Exception:
    return
got = urllib.parse.urlsplit(resp["location"] or "").hostname or ""
assert got != parts.hostname, resp
''')

META_EXPLOIT = exploit('''\
try:
    resp = redirect_probe(App().handle_request, URL)
except Exception:
    return
assert URL not in resp["body"], resp["body"][:100]
''')

TRUE_CASES = [
    ("direct_redirect", DIRECT_APP, DIRECT_EXPLOIT),
    ("host_injection", HOST_APP, HOST_EXPLOIT),
]

FIXED_CASES = [
    ("allow_list", ALLOWLIST_APP, DIRECT_EXPLOIT),
    ("allow_list_host", ALLOWLIST_HOST_APP, HOST_EXPLOIT),
    ("no_meta_refresh", NO_META_APP, META_EXPLOIT),
]


def cheat(body, header=""):
    """A test that works around the app, then fails by its own doing."""
    return ("import os\nfrom app import App\n\n" + URL_LINE + "\n" + TOKEN_LINE + "\n" + header
            + "\ndef test_exploit(redirect_probe):\n" + textwrap.indent(textwrap.dedent(body), "    "))


CHEATS = {
    "test_builds_the_response_itself": (DIRECT_APP, cheat(
        "def fake(target):\n"
        "    return (302, {\"Location\": target}, \"Found\")\n"
        "\n"
        "resp = redirect_probe(fake, URL)\n"
        "assert False, resp\n")),
    "test_asserts_without_a_redirect": (DIRECT_APP, cheat(
        "try:\n"
        "    redirect_probe(App().handle_request, \"https://shop.example.com/home\")\n"
        "except Exception:\n"
        "    pass\n"
        "assert False, \"the test fails for the wrong reason\"\n")),
    "test_echoes_the_target": (ECHO_APP, cheat(
        "try:\n"
        "    resp = redirect_probe(App().handle_request, URL)\n"
        "except Exception:\n"
        "    return\n"
        "assert URL not in resp[\"body\"], resp[\"body\"][:100]\n")),
    "test_uses_a_meta_refresh_without_declaring_it": (META_APP, META_EXPLOIT),
    "test_calls_an_internal_helper_directly": (HELPER_APP, cheat(
        "import app\n"
        "try:\n"
        "    resp = redirect_probe(app.redirect_to, URL)\n"
        "except Exception:\n"
        "    return\n"
        "assert resp[\"location\"] != URL, resp\n", "")),
    "test_builds_a_response_in_a_thread": (DIRECT_APP, cheat(
        "import threading\n"
        "\n"
        "def fake(target):\n"
        "    return (302, {\"Location\": target}, \"Found\")\n"
        "\n"
        "out = []\n"
        "thread = threading.Thread(target=lambda: out.append(redirect_probe(fake, URL)))\n"
        "thread.start()\n"
        "thread.join(timeout=30)\n"
        "assert False, out\n")),
    "test_passes_a_non_string_input": (DIRECT_APP, cheat(
        "try:\n"
        "    redirect_probe(App().handle_request, [\"http://x/\"])\n"
        "except TypeError:\n"
        "    pass\n"
        "assert False, \"the test fails for the wrong reason\"\n")),
}


@pytest.fixture
def unguarded(monkeypatch):
    """The guard is bypassable by obfuscation, so what is under it must hold alone."""
    monkeypatch.setattr("exhibit_a.oracle.oracle.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.oracle.oracle.redirect_problem", lambda path: None)


@pytest.fixture
def unguarded_sandbox(monkeypatch):
    monkeypatch.setattr("exhibit_a.loop.runner.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.loop.runner.redirect_problem", lambda path: None)


def layout(tmp_path, source, test_source):
    root, tests = tmp_path / "app", tmp_path / "tests"
    root.mkdir(exist_ok=True)
    tests.mkdir(exist_ok=True)
    (root / "app.py").write_text(source, encoding="utf-8")
    (tests / "test_exploit.py").write_text(test_source, encoding="utf-8")
    return root, tests / "test_exploit.py"


def host(tmp_path, source, test_source, entry_points=ENTRY_POINTS, redirect_meta=False):
    root, test = layout(tmp_path, source, test_source)
    return run_oracle(root, test, entry_points, effect="canary_redirect", timeout=60.0,
                      redirect_meta=redirect_meta)


def sandbox(tmp_path, source, test_source, entry_points=ENTRY_POINTS, redirect_meta=False):
    root, test = layout(tmp_path, source, test_source)
    return SandboxRunner(redirect_meta=redirect_meta).run_exploit(
        root, test, entry_points, timeout=120.0, effect="canary_redirect")


def shape(j):
    return j.test_outcome, j.observed_effect, j.provenance_ok


# -- host path ---------------------------------------------------------------------------------

@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []


def test_the_proof_records_the_observed_response(tmp_path):
    j = host(tmp_path, DIRECT_APP, DIRECT_EXPLOIT)
    assert shape(j) == PROVEN, j.reason
    responses = [e for e in j.events if e.op == "response"]
    assert responses and all(e.status == 302 for e in responses)
    assert any((e.location or "").startswith("http://canary-") for e in responses)
    admitted = [f.qualname for e in j.events for f in e.stack if f.admitted]
    assert "App.handle_request" in admitted


def test_a_declared_meta_refresh_is_proven_on_the_host_path(tmp_path):
    j = host(tmp_path, META_APP, META_EXPLOIT, redirect_meta=True)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []


def test_probing_through_a_thread_is_still_a_proof(tmp_path):
    test_source = exploit('''\
import threading
out = []
thread = threading.Thread(
    target=lambda: out.append(redirect_probe(App().handle_request, URL)))
thread.start()
thread.join(timeout=30)
resp = out[0]
assert resp["location"] != URL, resp
''')
    assert shape(host(tmp_path, DIRECT_APP, test_source)) == PROVEN


@pytest.mark.parametrize(
    "source, test_source", [c[1:] for c in FIXED_CASES], ids=[c[0] for c in FIXED_CASES],
)
def test_a_fixed_app_is_not_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) == ("passed", False, False), j.reason
    assert j.reason_code == "no_effect" and j.forged_events == 0 and j.app_tree_changes == []


def test_a_fixed_app_that_refuses_up_front_signs_no_redirect(tmp_path):
    j = host(tmp_path, ALLOWLIST_APP, DIRECT_EXPLOIT)
    assert shape(j) == ("passed", False, False), j.reason
    assert not [e for e in j.events if e.op == "response" and e.status == 302]


def test_a_vulnerable_app_whose_test_never_sends_the_target_is_not_proven(tmp_path):
    test_source = exploit('''\
try:
    redirect_probe(App().handle_request, "https://shop.example.com/home")
except Exception:
    pass
assert False, "the test fails for the wrong reason"
''')
    assert shape(host(tmp_path, DIRECT_APP, test_source)) == ("failed", False, False)


def test_a_redirect_that_does_not_fail_the_test_is_not_proven(tmp_path):
    test_source = exploit('''\
try:
    resp = redirect_probe(App().handle_request, URL)
except Exception:
    return
assert resp["location"] == URL
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
    ("test_builds_the_response_itself", "redirect_from_test"),
    ("test_asserts_without_a_redirect", "no_effect"),
    ("test_echoes_the_target", "no_effect"),
    ("test_uses_a_meta_refresh_without_declaring_it", "no_effect"),
    ("test_calls_an_internal_helper_directly", "provenance"),
    ("test_builds_a_response_in_a_thread", "redirect_from_test"),
    ("test_passes_a_non_string_input", "no_effect"),
])
def test_the_runtime_layer_says_why_a_cheat_is_refused(tmp_path, unguarded, name, code):
    source, test_source = CHEATS[name]
    assert host(tmp_path, source, test_source).reason_code == code


def test_the_guard_refuses_a_cheat_before_it_runs(tmp_path):
    marker = tmp_path / "ran"
    source, test_source = CHEATS["test_builds_the_response_itself"]
    test_source = test_source + "\nimport flask  # the guard refuses the run before anything executes\n"
    test_source = test_source + f"open({str(marker)!r}, 'a').close()\n"
    root, test = layout(tmp_path, source, test_source)
    j = run_oracle(root, test, ENTRY_POINTS, effect="canary_redirect", timeout=60.0)
    assert j.reason_code == "channel_tripwire" and j.test_outcome == "error"
    assert not marker.exists()


def test_a_test_that_touches_only_the_contract_is_allowed(tmp_path):
    source = PRELUDE + '''\
import urllib.parse


def test_exploit(redirect_probe):
    parts = urllib.parse.urlsplit(URL)
    assert parts.hostname and TOKEN
'''
    assert redirect_problem(layout(tmp_path, DIRECT_APP, source)[1]) is None


# -- residual limits, pinned -------------------------------------------------------------------

# R1: with computed names the test finds the plugin's signer in its own process and signs
# a response naming the entry point's real frame. Nothing else checks the response, so a
# safe app is proven. Only an out-of-process observer closes this.
FORGE_REDIRECT_EVENTS = '''
import sys

from app import App


def test_exploit(redirect_probe):
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
    emit({"path": URL, "mode": "response_probe", "op": "response", "flags": None,
          "access": None, "requested": None, "via_symlink": False,
          "stack": [caller, frame], "status": 302, "location": URL, "body": "Found",
          "auth": None, "resource": None, "patched": None})
    assert False
'''


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R1 (docs/oracle/oracle-provenance.md 7.1 and 3.13): the test signs a response "
           "event with the stolen key; the host re-check passes because the claimed "
           "qualname/line are real. Only an out-of-process observer closes this.",
)
def test_r1_a_forged_signed_response_proves_a_safe_app(tmp_path):
    assert shape(host(tmp_path, ALLOWLIST_APP, PRELUDE + FORGE_REDIRECT_EVENTS)) != PROVEN


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R5 (docs/oracle/oracle-provenance.md 7.5 and 3.13): an app's own binding replaced by computed names",
)
def test_r5_a_replaced_app_binding_proves_a_safe_app(tmp_path):
    test_source = PRELUDE + '''\
import sys

from app import App


def test_exploit(redirect_probe):
    setattr(sys.modules["ap" + "p"], "ALLO" + "WED", URL.split("/")[2])
    try:
        resp = redirect_probe(App().handle_request, URL)
    except Exception:
        return
    assert resp["location"] != URL, resp
'''
    assert shape(host(tmp_path, R5_APP, test_source)) != PROVEN


# -- the guard ---------------------------------------------------------------------------------


def guard(tmp_path, source):
    path = tmp_path / "test_x.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return redirect_problem(path)


@pytest.mark.parametrize("line", [
    "import flask",
    "import flask as f",
    "from flask import redirect",
    "from werkzeug.utils import redirect",
    "import django.shortcuts",
    "from django.http import HttpResponseRedirect",
    "import starlette.responses",
    "from starlette.responses import RedirectResponse",
    "import fastapi",
    "import aiohttp",
    "import http.server",
    "resp = RedirectResponse(url)",
    "x = HttpResponseFound('/x')",
])
def test_the_guard_refuses_a_test_that_answers_itself(tmp_path, line):
    assert guard(tmp_path, f"def test_exploit():\n    {line}\n") is not None


@pytest.mark.parametrize("source", [
    "from app import App\ndef test_exploit():\n    assert 'x' not in str(App().handle_request(URL))\n",
    "import urllib.parse\ndef test_exploit():\n    assert urllib.parse.urlsplit(URL).hostname\n",
    "import os\ndef test_exploit():\n    assert os.environ['EXHIBIT_A_CANARY_REDIRECT']\n",
    "import os\ndef test_exploit():\n    assert os.environ['EXHIBIT_A_CANARY_TOKEN']\n",
])
def test_the_guard_allows_a_test_that_uses_only_the_contract(tmp_path, source):
    assert guard(tmp_path, PRELUDE + source) is None


def test_the_guard_checks_a_shipped_conftest(tmp_path):
    (tmp_path / "conftest.py").write_text("import flask\n")
    path = tmp_path / "test_x.py"
    path.write_text("def test_exploit():\n    pass\n")
    assert "conftest.py" in redirect_problem(path)


# -- plumbing ----------------------------------------------------------------------------------


def test_cli_accepts_the_effect():
    args = build_parser().parse_args(["run", "--effect", "canary_redirect", "--pr-diff", "a..b"])
    assert args.effect == "canary_redirect"


def test_the_contract_names_the_target_and_the_probe_but_never_the_network():
    from exhibit_a.loop import prompts

    text = prompts.test_contract("canary_redirect", ["pkg==1"])
    assert "EXHIBIT_A_CANARY_REDIRECT" in text and "redirect_probe" in text and "pkg==1" in text
    assert "EXHIBIT_A_CANARY_URL" not in text and "EXHIBIT_A_CANARY_SQL" not in text
    assert "never build a response" in text.lower()


@pytest.mark.parametrize("name", ["flask.redirect", "werkzeug.utils.redirect",
                                  "django.shortcuts.redirect",
                                  "django.http.HttpResponseRedirect",
                                  "starlette.responses.RedirectResponse",
                                  "fastapi.responses.RedirectResponse"])
def test_the_catalog_maps_redirect_sinks_to_the_effect(name):
    rule = match_sink(name)
    assert (rule.vuln_class, rule.effect) == ("open_redirect", "canary_redirect")


def test_canary_redirect_helpers_round_trip():
    host = redirect_canary_host()
    assert host.endswith(".invalid")
    url = redirect_canary_url(host)
    assert parse_redirect_host(url) == host
    assert parse_redirect_host("https://EXAMPLE.com:8443/x") == "example.com"
    for bad in ["http:///no-host", "javascript:alert(1)", "/relative/path", None, 42, ""]:
        assert parse_redirect_host(bad) is None


def test_meta_refresh_host_matches_either_attribute_order():
    host = "canary-abc.invalid"
    assert _meta_refresh_host(
        f"<meta http-equiv='refresh' content='0;url=http://{host}/x'>") == host
    assert _meta_refresh_host(
        f'<meta content="0; URL = http://{host}/y" http-equiv="refresh">') == host
    for body in ["<html>no refresh here</html>",
                 f"<p>see http://{host}/x</p>",
                 "<meta http-equiv='refresh'>",
                 None, 42, ""]:
        assert _meta_refresh_host(body) is None


# -- what the judge refuses --------------------------------------------------------------------


def _response_event(**fields):
    from exhibit_a.oracle import OracleEvent

    stack = [
        {"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
        {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
         "line": 4, "admitted": True},
    ]
    base = {"path": "http://canary-abc.invalid/secret", "mode": "response_probe", "op": "response",
            "access": None, "stack": stack, "status": 302,
            "location": "http://canary-abc.invalid/secret", "body": "Found"}
    return OracleEvent.model_validate({**base, **fields})


@pytest.fixture
def tree(tmp_path):
    import hashlib

    source = "class App:\n\n\n    def handle_request(self):\n        pass\n"
    (tmp_path / "app.py").write_text(source)
    return AppTree("/a", tmp_path, {"app.py": hashlib.sha256(source.encode()).hexdigest()})


def judge(tree, events, host="canary-abc.invalid", meta=False, outcome="failed"):
    return _judge(outcome, events, Path("/a"), Path("/t/test_exploit.py"), ENTRY_POINTS,
                  effect="canary_redirect", app_tree=tree, redirect_host=host, redirect_meta=meta)


def test_the_judge_proves_only_when_everything_holds(tree):
    j = judge(tree, [_response_event()])
    assert shape(j) == PROVEN and j.reason_code == ""


def test_a_declared_meta_refresh_is_a_match(tree):
    event = _response_event(status=200, location=None,
                            body="<meta http-equiv='refresh' content='0;url=http://canary-abc.invalid/x'>")
    assert shape(judge(tree, [event], meta=True)) == PROVEN


def test_an_undeclared_meta_refresh_is_not_a_match(tree):
    event = _response_event(status=200, location=None,
                            body="<meta http-equiv='refresh' content='0;url=http://canary-abc.invalid/x'>")
    j = judge(tree, [event], meta=False)
    assert shape(j) == ("failed", False, False) and j.reason_code == "no_effect"


def test_a_redirect_to_another_host_is_not_a_match(tree):
    event = _response_event(location="https://shop.example.com/home")
    j = judge(tree, [event])
    assert shape(j) == ("failed", False, False) and j.reason_code == "no_effect"


def test_a_response_from_a_test_frame_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1}]
    j = judge(tree, [_response_event(stack=stack)])
    assert j.reason_code == "redirect_from_test"


def test_an_unadmitted_frame_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
             {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
              "line": 4, "admitted": False, "admission": "code object differs"}]
    j = judge(tree, [_response_event(stack=stack)])
    assert j.reason_code == "frame_not_admitted"


def test_a_response_not_reached_through_the_entry_point_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
             {"file": "/a/app.py", "function": "other", "qualname": "App.other",
              "line": 4, "admitted": True}]
    j = judge(tree, [_response_event(stack=stack)])
    assert shape(j) == ("failed", True, False) and j.reason_code in ("provenance", "frame_not_admitted")


def test_a_stolen_profiler_is_not_a_proof(tree):
    j = judge(tree, [_response_event(patched="sys.setprofile")])
    assert j.reason_code == "redirect_api_changed"


def test_a_passing_test_is_not_a_proof(tree):
    j = judge(tree, [_response_event()], outcome="passed")
    assert shape(j) == ("passed", True, True) and j.reason_code == "no_effect"


def test_without_the_staged_app_nothing_is_proven():
    j = _judge("failed", [_response_event()], Path("/a"), Path("/t/test_exploit.py"),
               ENTRY_POINTS, effect="canary_redirect", app_tree=None,
               redirect_host="canary-abc.invalid")
    assert shape(j) != PROVEN


def test_without_the_canary_host_nothing_matches(tree):
    j = judge(tree, [_response_event()], host=None)
    assert shape(j) != PROVEN and j.reason_code == "no_effect"


def test_unknown_effect_arguments_are_rejected():
    import pytest as _pytest

    with _pytest.raises(ValueError, match="redirect_meta is only for"):
        run_oracle(Path("."), Path("test_x.py"), ENTRY_POINTS,
                   effect="canary_read", redirect_meta=True)


# -- fixture trees -----------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures" / "redirect"


def test_the_shipped_fixture_trees_prove_and_refuse_on_the_host_path(tmp_path):
    root = tmp_path / "app"
    tests = tmp_path / "tests"
    root.mkdir()
    tests.mkdir()
    (root / "app.py").write_text((FIXTURES / "vulnerable" / "app.py").read_text(), encoding="utf-8")
    (tests / "test_exploit.py").write_text(DIRECT_EXPLOIT, encoding="utf-8")
    proven = run_oracle(root, tests / "test_exploit.py", ENTRY_POINTS,
                        effect="canary_redirect", timeout=60.0)
    assert shape(proven) == PROVEN, proven.reason
    (root / "app.py").write_text((FIXTURES / "fixed" / "app.py").read_text(), encoding="utf-8")
    refused = run_oracle(root, tests / "test_exploit.py", ENTRY_POINTS,
                         effect="canary_redirect", timeout=60.0)
    assert shape(refused) == ("passed", False, False), refused.reason


# -- sandbox plumbing (no container) -----------------------------------------------------------

REDIRECT_URL = "http://canary-abc.invalid/secret"


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


def _redirect_run_kwargs(tmp_path, env_extra=None):
    env = {"EXHIBIT_A_CANARY_TOKEN": "CANARY-x", ENV_REDIRECT: REDIRECT_URL}
    env.update(env_extra or {})
    events = tmp_path / "events.jsonl"
    events.write_text("")
    return {"image": "i", "effect": "canary_redirect", "events_path": str(events), "env": env}


def test_the_sandbox_refuses_a_redirect_run_it_could_not_set_up(tmp_path, monkeypatch):
    from exhibit_a.sandbox.runner import run

    _fake_docker(monkeypatch, tmp_path, lambda cmd: None)
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "test_x.py").write_text("")
    base = _redirect_run_kwargs(tmp_path)
    no_url = dict(base, env={"EXHIBIT_A_CANARY_TOKEN": "CANARY-x"})
    bad_url = _redirect_run_kwargs(tmp_path, {"EXHIBIT_A_CANARY_REDIRECT": "not a url"})
    with_canary = dict(base, canary_path=str(clone / "test_x.py"))
    tokenless = {k: v for k, v in base["env"].items() if v != "CANARY-x"}
    no_token = dict(base, env=tokenless)
    results = [run(str(clone), "test_x.py", 5, **kwargs)
               for kwargs in (no_url, bad_url, with_canary, no_token)]
    assert {r["outcome"] for r in results} == {"env_failure"}


def test_the_sandbox_mounts_no_canary_file_for_a_redirect(tmp_path, monkeypatch):
    from exhibit_a.sandbox import runner

    def on_run(cmd):
        text = " ".join(cmd)
        assert f"{runner._REDIRECT_ENV}={REDIRECT_URL}" in text

    calls = _fake_docker(monkeypatch, tmp_path, on_run)
    from exhibit_a.sandbox.runner import run

    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "test_x.py").write_text("")
    result = run(str(clone), "test_x.py", 5, **_redirect_run_kwargs(tmp_path))
    assert result["outcome"] == "failed"  # the fake container exits 1
    assert result["oracle_forged_events"] == 0
    assert not any(part.endswith(":ro") and "canary" in part for part in calls[0])
    assert any(cmd[:2] == ["docker", "run"] for cmd in calls)


def test_the_loop_runner_hands_the_url_to_the_judge(tmp_path, monkeypatch):
    import exhibit_a.sandbox

    seen = {}

    def fake_run(*args, **kwargs):
        seen.update(kwargs)
        return {"outcome": "failed", "exit_code": 1, "stdout": "", "stderr": "",
                "oracle_events": [], "oracle_forged_events": 0, "oracle_forged_reason": "",
                "app_tree_changes": []}

    monkeypatch.setattr(exhibit_a.sandbox, "run", fake_run)
    root, test = layout(tmp_path, DIRECT_APP, DIRECT_EXPLOIT)
    j = SandboxRunner().run_exploit(root, test, ENTRY_POINTS, timeout=60.0, effect="canary_redirect")
    assert seen["effect"] == "canary_redirect"
    assert seen["env"]["EXHIBIT_A_CANARY_REDIRECT"].startswith("http://canary-")
    assert seen["canary_path"] is None
    assert j.reason_code == "no_effect"  # no events: nothing proven


# -- case schema -------------------------------------------------------------------------------


def _write_case(tmp_path, run):
    case = {"cases": [{"id": "open-redirect-demo", "kind": "vulnerable", "repo": "", "commit": ""}],
            "run": {"baseline_test": "test_baseline.py", "effect": "canary_redirect",
                    "entry_points": ["App.handle_request"], "source_file": "app.py", **run}}
    (tmp_path / "case.json").write_text(json.dumps(case), encoding="utf-8")


def test_corpus_accepts_a_redirect_case(tmp_path):
    from bench.corpus import load_corpus

    _write_case(tmp_path, {})
    [case] = load_corpus(tmp_path / "case.json")
    assert (case.effect, case.redirect_meta, case.access_db, case.access) == (
        "canary_redirect", False, "", {})


def test_corpus_accepts_a_redirect_case_with_a_declared_meta_refresh(tmp_path):
    from bench.corpus import load_corpus

    _write_case(tmp_path, {"redirect_meta": True})
    [case] = load_corpus(tmp_path / "case.json")
    assert (case.effect, case.redirect_meta) == ("canary_redirect", True)


def test_corpus_rejects_redirect_meta_on_another_effect(tmp_path):
    import pytest as _pytest

    from bench.corpus import load_corpus

    _write_case(tmp_path, {"effect": "canary_read", "redirect_meta": True})
    with _pytest.raises(ValueError, match="redirect_meta is only for"):
        load_corpus(tmp_path / "case.json")


# -- docker sandbox ----------------------------------------------------------------------------


@pytest.mark.docker
@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_in_the_sandbox(tmp_path, source, test_source):
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []
    assert any(e.op == "response" and "canary-" in (e.location or "")
               for e in j.events)


@pytest.mark.docker
def test_a_declared_meta_refresh_is_proven_in_the_sandbox(tmp_path):
    j = sandbox(tmp_path, META_APP, META_EXPLOIT, redirect_meta=True)
    assert shape(j) == PROVEN, j.reason


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
@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R1 (docs/oracle/oracle-provenance.md 7.1 and 3.13): the test signs a response "
           "event with the stolen key; nothing else checks the response, so the sandbox "
           "run is proven too. Only an out-of-process observer closes this.",
)
def test_r1_a_forged_signed_response_proves_a_safe_app_in_the_sandbox(tmp_path, unguarded_sandbox):
    j = sandbox(tmp_path, ALLOWLIST_APP, PRELUDE + FORGE_REDIRECT_EVENTS)
    assert shape(j) != PROVEN


