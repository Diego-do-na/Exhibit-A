"""The canary_access effect: broken access control (IDOR) on the host path and in Docker.

The case declares two principals (attacker, victim) and the protected resource; the
runner seeds a victim-owned resource holding the token into a copy of the application's
store and calls the entry point itself as the attacker through the ``access_probe``
fixture, signing the observed response. A vulnerable app that returns the victim's token
to the attacker is proven; a fixed one (ownership checks) is not; every cheat is
refused, with the static guard on and, because it is only a tripwire, with it off. The
test never receives the victim credential. Design and limits:
docs/oracle/oracle-provenance.md, section 3.14.
"""

import json
import os
import textwrap
from pathlib import Path

import pytest

from exhibit_a.cli.parser import build_parser
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.oracle import run_oracle
from exhibit_a.oracle.guard import access_problem
from exhibit_a.oracle.oracle import (
    _judge,
    access_db_problem,
    access_db_shape_problem,
    access_shape_problem,
    seed_access_db,
)
from exhibit_a.oracle.plugin import ENV_ACCESS_ATTACKER, ENV_ACCESS_RESOURCE
from exhibit_a.oracle.provenance import AppTree

ENTRY_POINTS = {"App.handle_request"}
PROVEN = ("failed", True, True)

ACCESS = {"attacker": "attacker", "victim": "victim", "resource": "doc-1"}
ACCESS_DB = "data/store.json"

PRELUDE = '''\
import os

ATTACKER = os.environ["EXHIBIT_A_ATTACKER"]
RESOURCE = os.environ["EXHIBIT_A_RESOURCE"]
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
'''

# -- applications ------------------------------------------------------------------------------

VULN_APP = '''\
import json
import os

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "store.json")


class App:
    def handle_request(self, auth, resource):
        """Entry point: return the resource without checking its owner (the bug)."""
        with open(STORE, encoding="utf-8") as fh:
            store = json.load(fh)
        return store[resource]["content"]
'''

DICT_APP = '''\
import json
import os

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "store.json")


class App:
    def handle_request(self, auth, resource):
        """Entry point: return the resource as a response dict, unchecked (the bug)."""
        with open(STORE, encoding="utf-8") as fh:
            store = json.load(fh)
        entry = store[resource]
        return {"status": 200, "headers": {}, "body": entry["content"]}
'''

FIXED_APP = '''\
import json
import os

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "store.json")


class App:
    def handle_request(self, auth, resource):
        """Entry point: return the resource only to its owner (the fix)."""
        with open(STORE, encoding="utf-8") as fh:
            store = json.load(fh)
        entry = store[resource]
        if entry["owner"] != auth:
            raise PermissionError("not the owner of this resource")
        return entry["content"]
'''

ECHO_APP = '''\
class App:
    def handle_request(self, auth, resource):
        """Entry point: repeat the caller's credential, leak nothing (safe)."""
        return {"status": 200, "headers": {}, "body": auth}
'''

HELPER_APP = '''\
import json
import os

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "store.json")


def lookup(auth, resource):
    with open(STORE, encoding="utf-8") as fh:
        store = json.load(fh)
    return store[resource]["content"]


class App:
    def handle_request(self, name):
        """Entry point: return public information (safe)."""
        return {"status": 200, "headers": {}, "body": "public:" + name}
'''

# Safe by construction, and it says whether to enforce ownership in a module binding the
# test could swap: the "R5" shape of section 3.14.
CHECK_APP = '''\
import json
import os

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "store.json")

CHECK = True


class App:
    def handle_request(self, auth, resource):
        """Entry point: return the resource only to its owner (safe)."""
        with open(STORE, encoding="utf-8") as fh:
            store = json.load(fh)
        entry = store[resource]
        if CHECK and entry["owner"] != auth:
            raise PermissionError("not the owner of this resource")
        return entry["content"]
'''

# -- exploits ----------------------------------------------------------------------------------

TOKEN = "os.environ['EXHIBIT_A_CANARY_TOKEN']"


def exploit(body):
    """A test that asks as the attacker and fails if the victim's token came back."""
    header = ("import os\nfrom app import App\n\n"
              "ATTACKER = os.environ[\"EXHIBIT_A_ATTACKER\"]\n"
              "RESOURCE = os.environ[\"EXHIBIT_A_RESOURCE\"]\n"
              "TOKEN = os.environ[\"EXHIBIT_A_CANARY_TOKEN\"]\n\n"
              "def test_exploit(access_probe):\n")
    return header + textwrap.indent(textwrap.dedent(body), "    ")


ACCESS_EXPLOIT = exploit('''\
try:
    resp = access_probe(App().handle_request, ATTACKER, RESOURCE)
except Exception:
    return
assert TOKEN not in resp["body"], resp["body"][:50]
''')

TRUE_CASES = [
    ("unchecked_bare_string", VULN_APP, ACCESS_EXPLOIT),
    ("unchecked_response_dict", DICT_APP, ACCESS_EXPLOIT),
]

FIXED_CASES = [
    ("ownership_check", FIXED_APP, ACCESS_EXPLOIT),
]


def cheat(body, header=""):
    """A test that works around the app, then fails by its own doing."""
    return ("import os\nfrom app import App\n\n"
            "ATTACKER = os.environ[\"EXHIBIT_A_ATTACKER\"]\n"
            "RESOURCE = os.environ[\"EXHIBIT_A_RESOURCE\"]\n"
            "TOKEN = os.environ[\"EXHIBIT_A_CANARY_TOKEN\"]\n" + header
            + "\ndef test_exploit(access_probe):\n" + textwrap.indent(textwrap.dedent(body), "    "))


CHEATS = {
    "test_builds_the_response_itself": (VULN_APP, cheat(
        "def fake(auth, resource):\n"
        "    return TOKEN\n"
        "\n"
        "resp = access_probe(fake, ATTACKER, RESOURCE)\n"
        "assert False, resp\n")),
    "test_reads_the_store_directly": (VULN_APP, cheat(
        "with open(\"data/store.json\", encoding=\"utf-8\") as fh:\n"
        "    body = fh.read()\n"
        "assert False, body[:50]\n")),
    # The test guesses the victim id (it is not in the environment): a request that does
    # not authenticate as the attacker proves nothing, even when the token comes back.
    "test_authenticates_as_the_victim": (FIXED_APP, cheat(
        "try:\n"
        "    resp = access_probe(App().handle_request, \"victim\", RESOURCE)\n"
        "except Exception:\n"
        "    return\n"
        "assert TOKEN not in resp[\"body\"], resp[\"body\"][:50]\n")),
    "test_asks_for_another_resource": (VULN_APP, cheat(
        "try:\n"
        "    resp = access_probe(App().handle_request, ATTACKER, \"other-doc\")\n"
        "except Exception:\n"
        "    return\n"
        "assert TOKEN not in resp[\"body\"], resp[\"body\"][:50]\n")),
    "test_calls_an_internal_helper_directly": (HELPER_APP, cheat(
        "import app\n"
        "try:\n"
        "    resp = access_probe(app.lookup, ATTACKER, RESOURCE)\n"
        "except Exception:\n"
        "    return\n"
        "assert TOKEN not in resp[\"body\"], resp[\"body\"][:50]\n", "")),
    "test_writes_the_store": (VULN_APP, cheat(
        "with open(\"data/store.json\", \"w\", encoding=\"utf-8\") as fh:\n"
        "    fh.write(\"{}\")\n"
        "assert False\n")),
    "test_echoes_the_attacker": (ECHO_APP, cheat(
        "try:\n"
        "    resp = access_probe(App().handle_request, ATTACKER, RESOURCE)\n"
        "except Exception:\n"
        "    return\n"
        "assert TOKEN not in resp[\"body\"], resp[\"body\"][:50]\n")),
}


@pytest.fixture
def unguarded(monkeypatch):
    """The guard is bypassable by obfuscation, so what is under it must hold alone."""
    monkeypatch.setattr("exhibit_a.oracle.oracle.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.oracle.oracle.access_problem", lambda path: None)


@pytest.fixture
def unguarded_sandbox(monkeypatch):
    monkeypatch.setattr("exhibit_a.loop.runner.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.loop.runner.access_problem", lambda path: None)


def layout(tmp_path, source, test_source):
    root, tests = tmp_path / "app", tmp_path / "tests"
    root.mkdir(exist_ok=True)
    tests.mkdir(exist_ok=True)
    (root / "app.py").write_text(source, encoding="utf-8")
    (root / "data").mkdir(exist_ok=True)
    (root / "data" / "store.json").write_text("{}\n", encoding="utf-8")
    (tests / "test_exploit.py").write_text(test_source, encoding="utf-8")
    return root, tests / "test_exploit.py"


def host(tmp_path, source, test_source, entry_points=ENTRY_POINTS, access=ACCESS):
    root, test = layout(tmp_path, source, test_source)
    return run_oracle(root, test, entry_points, effect="canary_access", timeout=60.0,
                      access_db=ACCESS_DB, access=dict(access))


def sandbox(tmp_path, source, test_source, entry_points=ENTRY_POINTS, access=ACCESS):
    root, test = layout(tmp_path, source, test_source)
    return SandboxRunner(access_db=ACCESS_DB, access=dict(access)).run_exploit(
        root, test, entry_points, timeout=120.0, effect="canary_access")


def shape(j):
    return j.test_outcome, j.observed_effect, j.provenance_ok


# -- host path ---------------------------------------------------------------------------------

@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []


def test_the_proof_records_the_attacker_response(tmp_path):
    j = host(tmp_path, VULN_APP, ACCESS_EXPLOIT)
    assert shape(j) == PROVEN, j.reason
    responses = [e for e in j.events if e.op == "response"]
    assert responses and any("CANARY-" in (e.body or "") for e in responses)
    assert all(e.auth == "attacker" and e.resource == "doc-1" for e in responses)
    admitted = [f.qualname for e in j.events for f in e.stack if f.admitted]
    assert "App.handle_request" in admitted


@pytest.mark.parametrize(
    "source, test_source", [c[1:] for c in FIXED_CASES], ids=[c[0] for c in FIXED_CASES],
)
def test_a_fixed_app_is_not_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) == ("passed", False, False), j.reason
    assert j.reason_code == "no_effect" and j.forged_events == 0 and j.app_tree_changes == []


def test_a_fixed_app_that_refuses_up_front_leaks_nothing(tmp_path):
    j = host(tmp_path, FIXED_APP, ACCESS_EXPLOIT)
    assert shape(j) == ("passed", False, False), j.reason
    assert not [e for e in j.events if e.op == "response" and "CANARY-" in (e.body or "")]


def test_a_victim_request_proves_nothing_even_when_the_token_comes_back(tmp_path):
    # The owner reading their own resource is legitimate: the response is signed, but the
    # run's access contract binds the proof to the attacker's credential.
    test_source = exploit('''\
try:
    resp = access_probe(App().handle_request, "victim", RESOURCE)
except Exception:
    return
assert TOKEN not in resp["body"], resp["body"][:50]
''')
    j = host(tmp_path, FIXED_APP, test_source)
    assert shape(j) == ("failed", False, False), j.reason
    assert j.reason_code == "access_from_test"


def test_a_token_that_does_not_fail_the_test_is_not_proven(tmp_path):
    test_source = exploit('''\
try:
    resp = access_probe(App().handle_request, ATTACKER, RESOURCE)
except Exception:
    return
assert TOKEN in resp["body"]
''')
    j = host(tmp_path, VULN_APP, test_source)
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
    ("test_builds_the_response_itself", "access_from_test"),
    ("test_reads_the_store_directly", "access_from_test"),
    ("test_authenticates_as_the_victim", "access_from_test"),
    ("test_asks_for_another_resource", "no_effect"),
    ("test_calls_an_internal_helper_directly", "provenance"),
    ("test_writes_the_store", "access_from_test"),
    ("test_echoes_the_attacker", "no_effect"),
])
def test_the_runtime_layer_says_why_a_cheat_is_refused(tmp_path, unguarded, name, code):
    source, test_source = CHEATS[name]
    assert host(tmp_path, source, test_source).reason_code == code


def test_the_guard_refuses_a_cheat_before_it_runs(tmp_path):
    marker = tmp_path / "ran"
    source, test_source = CHEATS["test_reads_the_store_directly"]
    test_source = test_source + "\nimport json  # the guard refuses the run before anything executes\n"
    test_source = test_source + f"open({str(marker)!r}, 'a').close()\n"
    root, test = layout(tmp_path, source, test_source)
    j = run_oracle(root, test, ENTRY_POINTS, effect="canary_access", timeout=60.0,
                   access_db=ACCESS_DB, access=dict(ACCESS))
    assert j.reason_code == "channel_tripwire" and j.test_outcome == "error"
    assert not marker.exists()


def test_a_test_that_touches_only_the_contract_is_allowed(tmp_path):
    source = PRELUDE + '''\
import os


def test_exploit(access_probe):
    assert os.environ["EXHIBIT_A_ATTACKER"] and TOKEN
'''
    assert access_problem(layout(tmp_path, VULN_APP, source)[1]) is None


# -- the seeded store --------------------------------------------------------------------------

def test_seed_access_db_adds_the_victim_resource(tmp_path):
    db = tmp_path / "store.json"
    db.write_text("{}\n", encoding="utf-8")
    seed_access_db(db, "victim", "doc-1", "CANARY-t")
    assert json.loads(db.read_text(encoding="utf-8")) == {
        "doc-1": {"owner": "victim", "content": "CANARY-t"}}
    assert db.stat().st_mode & 0o777 == 0o444


@pytest.mark.parametrize("content", ['[1, 2]', '"just a string"', "not json{"])
def test_seed_access_db_refuses_a_store_that_is_not_an_object(tmp_path, content):
    db = tmp_path / "store.json"
    db.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="not a JSON object"):
        seed_access_db(db, "victim", "doc-1", "CANARY-t")


def test_seed_access_db_refuses_a_store_that_already_holds_the_resource(tmp_path):
    db = tmp_path / "store.json"
    db.write_text(json.dumps({"doc-1": {"owner": "someone", "content": "x"}}), encoding="utf-8")
    with pytest.raises(ValueError, match="already holds the resource"):
        seed_access_db(db, "victim", "doc-1", "CANARY-t")


@pytest.mark.parametrize("rel", ["", "../outside", "/absolute", "a/./b", "x" * 201, "data?.json"])
def test_access_db_shape_rejects_bad_paths(rel):
    assert access_db_shape_problem(rel) is not None


def test_access_db_shape_accepts_a_plain_relative_path():
    assert access_db_shape_problem("data/store.json") is None


def test_access_db_problem_rejects_a_missing_or_linked_store(tmp_path):
    assert access_db_problem(tmp_path, "missing.json") is not None
    (tmp_path / "real.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "linked.json").symlink_to("real.json")
    assert access_db_problem(tmp_path, "linked.json") is not None


@pytest.mark.parametrize("access", [
    None, {}, {"attacker": "", "victim": "v", "resource": "r"},
    {"attacker": "a", "victim": "v"}, {"attacker": "a b", "victim": "v", "resource": "r"},
    {"attacker": "a", "victim": "v", "resource": "/absolute"},
])
def test_access_shape_rejects_bad_contracts(access):
    assert access_shape_problem(access) is not None


def test_access_shape_accepts_the_declared_principals_and_resource():
    assert access_shape_problem(ACCESS) is None


@pytest.mark.parametrize("kwargs, match", [
    ({"effect": "canary_read", "access_db": ACCESS_DB, "access": dict(ACCESS)}, "access_db and access are only for"),
    ({"effect": "canary_access", "access_db": ACCESS_DB}, "access must map"),
    ({"effect": "canary_access", "access_db": "../outside.json", "access": dict(ACCESS)}, "normalised"),
    ({"effect": "canary_access", "access": dict(ACCESS)}, "access_db must be a non-empty path"),
])
def test_bad_access_contracts_fail_closed(tmp_path, kwargs, match):
    root, test = layout(tmp_path, VULN_APP, ACCESS_EXPLOIT)
    with pytest.raises(ValueError, match=match):
        run_oracle(root, test, ENTRY_POINTS, timeout=60.0, **kwargs)


# -- residual limits, pinned -------------------------------------------------------------------

# R1: with computed names the test finds the plugin's signer in its own process and signs
# a response naming the entry point's real frame and the run's token. Nothing else checks
# the response, so a safe app is proven. Only an out-of-process observer closes this.
FORGE_ACCESS_EVENTS = '''
import sys

from app import App


def test_exploit(access_probe):
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
    emit({"path": "da" + "ta/store.js" + "on", "mode": "response_probe", "op": "response", "flags": None,
          "access": None, "requested": None, "via_symlink": False,
          "stack": [caller, frame], "status": 200, "location": None, "body": TOKEN,
          "auth": ATTACKER, "resource": RESOURCE, "patched": None})
    assert False
'''


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R1 (docs/oracle/oracle-provenance.md 7.1 and 3.14): the test signs a response "
           "event with the stolen key; the host re-check passes because the claimed "
           "qualname/line are real. Only an out-of-process observer closes this.",
)
def test_r1_a_forged_signed_response_proves_a_safe_app(tmp_path):
    assert shape(host(tmp_path, FIXED_APP, PRELUDE + FORGE_ACCESS_EVENTS)) != PROVEN


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R5 (docs/oracle/oracle-provenance.md 7.5 and 3.14): an app's own binding replaced by computed names",
)
def test_r5_a_replaced_app_binding_proves_a_safe_app(tmp_path):
    test_source = PRELUDE + '''\
import sys

from app import App


def test_exploit(access_probe):
    setattr(sys.modules["ap" + "p"], "CHE" + "CK", False)
    try:
        resp = access_probe(App().handle_request, ATTACKER, RESOURCE)
    except Exception:
        return
    assert TOKEN not in resp["body"], resp["body"][:50]
'''
    assert shape(host(tmp_path, CHECK_APP, test_source)) != PROVEN


# -- the guard ---------------------------------------------------------------------------------


def guard(tmp_path, source):
    path = tmp_path / "test_x.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return access_problem(path)


@pytest.mark.parametrize("line", [
    "import json",
    "import json as j",
    "from json import loads",
    "from json import dump",
    "x = json.loads('{}')",
    "x = 'data/store.json'",
    "x = \"EXHIBIT_A_VICTIM\"",
    "x = 'prefix-EXHIBIT_A_VICTIM'",
])
def test_the_guard_refuses_a_test_that_touches_the_store(tmp_path, line):
    assert guard(tmp_path, f"def test_exploit():\n    {line}\n") is not None


@pytest.mark.parametrize("source", [
    "from app import App\ndef test_exploit():\n    assert 'x' not in str(App().handle_request('a', 'r'))\n",
    "import os\ndef test_exploit():\n    assert os.environ['EXHIBIT_A_ATTACKER']\n",
    "import os\ndef test_exploit():\n    assert os.environ['EXHIBIT_A_RESOURCE']\n",
    "import os\ndef test_exploit():\n    assert os.environ['EXHIBIT_A_CANARY_TOKEN']\n",
])
def test_the_guard_allows_a_test_that_uses_only_the_contract(tmp_path, source):
    assert guard(tmp_path, PRELUDE + source) is None


def test_the_guard_checks_a_shipped_conftest(tmp_path):
    (tmp_path / "conftest.py").write_text("import json\n")
    path = tmp_path / "test_x.py"
    path.write_text("def test_exploit():\n    pass\n")
    assert "conftest.py" in access_problem(path)


# -- plumbing ----------------------------------------------------------------------------------


def test_cli_accepts_the_effect():
    args = build_parser().parse_args(["run", "--effect", "canary_access", "--pr-diff", "a..b"])
    assert args.effect == "canary_access"


def test_the_contract_names_the_principals_and_the_probe_but_never_the_store():
    from exhibit_a.loop import prompts

    text = prompts.test_contract("canary_access", ["pkg==1"])
    assert "EXHIBIT_A_ATTACKER" in text and "access_probe" in text and "pkg==1" in text
    assert "EXHIBIT_A_VICTIM" not in text and "EXHIBIT_A_CANARY_SQL" not in text
    assert "never authenticate as anyone else" in text.lower()


# -- what the judge refuses --------------------------------------------------------------------


def _access_event(**fields):
    from exhibit_a.oracle import OracleEvent

    stack = [
        {"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
        {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
         "line": 5, "admitted": True},
    ]
    base = {"path": "data/store.json", "mode": "response_probe", "op": "response",
            "access": None, "stack": stack, "status": 200, "location": None,
            "body": "CANARY-t", "auth": "attacker", "resource": "doc-1"}
    return OracleEvent.model_validate({**base, **fields})


@pytest.fixture
def tree(tmp_path):
    import hashlib

    source = "class App:\n\n\n\n    def handle_request(self):\n        pass\n"
    (tmp_path / "app.py").write_text(source)
    return AppTree("/a", tmp_path, {"app.py": hashlib.sha256(source.encode()).hexdigest()})


def judge(tree, events, outcome="failed", access=None, token="CANARY-t"):
    return _judge(outcome, events, Path("/a"), Path("/t/test_exploit.py"), ENTRY_POINTS,
                  effect="canary_access", app_tree=tree,
                  access={"attacker": "attacker", "resource": "doc-1"} if access is None else access,
                  access_token=token)


def test_the_judge_proves_only_when_everything_holds(tree):
    j = judge(tree, [_access_event()])
    assert shape(j) == PROVEN and j.reason_code == ""


def test_a_response_for_another_credential_is_not_a_proof(tree):
    j = judge(tree, [_access_event(auth="victim")])
    assert j.reason_code == "access_from_test"


def test_a_response_for_another_resource_is_not_a_proof(tree):
    j = judge(tree, [_access_event(resource="other-doc")])
    assert j.reason_code == "access_from_test"


def test_a_response_without_the_token_is_not_a_proof(tree):
    j = judge(tree, [_access_event(body="nothing here")])
    assert shape(j) == ("failed", False, False) and j.reason_code == "no_effect"


def test_a_response_from_a_test_frame_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1}]
    j = judge(tree, [_access_event(stack=stack)])
    assert j.reason_code == "access_from_test"


def test_an_unadmitted_frame_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
             {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
              "line": 4, "admitted": False, "admission": "code object differs"}]
    j = judge(tree, [_access_event(stack=stack)])
    assert j.reason_code == "frame_not_admitted"


def test_a_response_not_reached_through_the_entry_point_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
             {"file": "/a/app.py", "function": "other", "qualname": "App.other",
              "line": 5, "admitted": True}]
    j = judge(tree, [_access_event(stack=stack)])
    assert shape(j) == ("failed", True, False) and j.reason_code in ("provenance", "frame_not_admitted")


def test_a_store_read_by_the_test_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1}]
    read = _access_event(op="open", mode="open", flags=0, access="read", auth=None, resource=None,
                         body=None, status=None, stack=stack)
    j = judge(tree, [read])
    assert j.reason_code == "access_from_test"


def test_a_store_write_by_the_app_is_not_a_proof(tree):
    write = _access_event(op="open", mode="open", flags=1, access="write")
    j = judge(tree, [write])
    assert j.reason_code == "canary_tampered"


def test_a_store_read_by_the_app_is_allowed_but_proves_nothing_alone(tree):
    read = _access_event(op="open", mode="open", flags=0, access="read",
                         auth=None, resource=None, body=None, status=None)
    j = judge(tree, [read])
    assert shape(j) == ("failed", False, False) and j.reason_code == "no_effect"


def test_a_stolen_profiler_is_not_a_proof(tree):
    j = judge(tree, [_access_event(patched="sys.setprofile")])
    assert j.reason_code == "access_api_changed"


def test_a_passing_test_is_not_a_proof(tree):
    j = judge(tree, [_access_event()], outcome="passed")
    assert shape(j) == ("passed", True, True) and j.reason_code == "no_effect"


def test_without_the_staged_app_nothing_is_proven():
    j = _judge("failed", [_access_event()], Path("/a"), Path("/t/test_exploit.py"),
               ENTRY_POINTS, effect="canary_access", app_tree=None,
               access={"attacker": "attacker", "resource": "doc-1"}, access_token="CANARY-t")
    assert shape(j) != PROVEN


def test_without_the_access_contract_nothing_matches(tree):
    j = judge(tree, [_access_event()], access={}, token="CANARY-t")
    assert shape(j) != PROVEN and j.reason_code == "no_effect"
    j = judge(tree, [_access_event()], token=None)
    assert shape(j) != PROVEN and j.reason_code == "no_effect"


# -- fixture trees -----------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures" / "access"


def test_the_shipped_fixture_trees_prove_and_refuse_on_the_host_path(tmp_path):
    root = tmp_path / "app"
    tests = tmp_path / "tests"
    root.mkdir()
    tests.mkdir()
    (root / "data").mkdir()
    for kind, shape_want in (("vulnerable", PROVEN), ("fixed", ("passed", False, False))):
        (root / "app.py").write_text((FIXTURES / kind / "app.py").read_text(), encoding="utf-8")
        (root / "data" / "store.json").write_text("{}\n", encoding="utf-8")
        (tests / "test_exploit.py").write_text(ACCESS_EXPLOIT, encoding="utf-8")
        j = run_oracle(root, tests / "test_exploit.py", ENTRY_POINTS,
                       effect="canary_access", timeout=60.0,
                       access_db=ACCESS_DB, access=dict(ACCESS))
        assert shape(j) == shape_want, (kind, j.reason)


# -- sandbox plumbing (no container) -----------------------------------------------------------

def _fake_docker(monkeypatch, tmp_path, on_run):
    """A fake `docker run`: records the argv, lets ``on_run`` act for the container.

    A seed container (its command names the seeded store) is emulated on the host: the
    fake writes the seeded copy itself and reports success, so the test exercises the
    mount logic without a container. The test container itself just exits 1.
    """
    import json as _json
    import subprocess as real

    from exhibit_a.sandbox import runner

    calls = []

    def fake(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            on_run(cmd)
            if "/seed/out/seeded.json" in cmd:
                source_host = next(p.split(":")[0] for p in cmd if p.endswith(":/seed/original.db:ro"))
                seed_dir = next(p.split(":")[0] for p in cmd if p.endswith(":/seed/out:rw"))
                token = next(p.split("=", 1)[1] for p in cmd if p.startswith("EXHIBIT_A_CANARY_TOKEN="))
                at = cmd.index("/seed/out/seeded.json")
                victim, resource = cmd[at + 1], cmd[at + 2]
                raw = Path(source_host).read_text(encoding="utf-8")
                store = _json.loads(raw) if raw.strip() else {}
                store[resource] = {"owner": victim, "content": token}
                (Path(seed_dir) / "seeded.json").write_text(
                    _json.dumps(store, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                return real.CompletedProcess(cmd, 0, b"", b"")
            return real.CompletedProcess(cmd, 1, b"", b"")
        return real.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(runner.subprocess, "run", fake)
    monkeypatch.setattr(runner, "_check_docker_available", lambda: True)
    monkeypatch.setattr(runner, "build_image", lambda reqs: "image:test")
    monkeypatch.setenv("HOME", str(tmp_path))
    return calls


def _access_run_kwargs(tmp_path, env_extra=None, **kwargs):
    env = {"EXHIBIT_A_CANARY_TOKEN": "CANARY-x",
           ENV_ACCESS_ATTACKER: "attacker", ENV_ACCESS_RESOURCE: "doc-1"}
    env.update(env_extra or {})
    events = tmp_path / "events.jsonl"
    events.write_text("")
    base = {"image": "i", "effect": "canary_access", "events_path": str(events),
            "env": env, "access_db": ACCESS_DB, "access_victim": "victim"}
    base.update(kwargs)
    return base


def test_the_sandbox_refuses_an_access_run_it_could_not_set_up(tmp_path, monkeypatch):
    from exhibit_a.sandbox.runner import run

    _fake_docker(monkeypatch, tmp_path, lambda cmd: None)
    clone = tmp_path / "clone"
    (clone / "data").mkdir(parents=True)
    (clone / "test_x.py").write_text("")
    (clone / "data" / "store.json").write_text("{}\n", encoding="utf-8")
    base = _access_run_kwargs(tmp_path)
    missing = dict(base, access_db="missing.json")
    escaped = dict(base, access_db="../outside.json")
    attackerless = _access_run_kwargs(
        tmp_path, {"EXHIBIT_A_ATTACKER": "", "EXHIBIT_A_RESOURCE": "doc-1"})
    victimless = dict(base, access_victim="")
    with_canary = dict(base, canary_path=str(clone / "test_x.py"))
    tokenless = {k: v for k, v in base["env"].items() if v != "CANARY-x"}
    no_token = dict(base, env=tokenless)
    results = [run(str(clone), "test_x.py", 5, **kwargs)
               for kwargs in (missing, escaped, attackerless, victimless, with_canary, no_token)]
    assert {r["outcome"] for r in results} == {"env_failure"}


def test_the_sandbox_mounts_the_seeded_store_read_only(tmp_path, monkeypatch):
    from exhibit_a.sandbox import runner

    calls = _fake_docker(monkeypatch, tmp_path, lambda cmd: None)
    from exhibit_a.sandbox.runner import run

    clone = tmp_path / "clone"
    (clone / "data").mkdir(parents=True)
    (clone / "test_x.py").write_text("")
    (clone / "data" / "store.json").write_text("{}\n", encoding="utf-8")
    result = run(str(clone), "test_x.py", 5, **_access_run_kwargs(tmp_path))
    assert result["outcome"] == "failed"  # the fake container exits 1
    assert result["oracle_forged_events"] == 0
    runs = [cmd for cmd in calls if cmd[:2] == ["docker", "run"]]
    assert len(runs) == 2  # the seed container first, the test container second
    seed_text, test_text = (" ".join(runs[0]), " ".join(runs[1]))
    assert "seeded.json" in seed_text and runner._ACCESS_ATTACKER_ENV not in seed_text
    assert f"{runner._ACCESS_ATTACKER_ENV}=attacker" in test_text
    assert f"{runner._ACCESS_RESOURCE_ENV}=doc-1" in test_text
    assert "EXHIBIT_A_VICTIM" not in seed_text + test_text  # the victim travels as a seed argument only
    assert any("/workspace/data/store.json:ro" in part for part in runs[1])


def test_the_loop_runner_seeds_without_leaking_the_victim(tmp_path, monkeypatch):
    import exhibit_a.sandbox

    seen = {}

    def fake_run(*args, **kwargs):
        seen.update(kwargs)
        return {"outcome": "failed", "exit_code": 1, "stdout": "", "stderr": "",
                "oracle_events": [], "oracle_forged_events": 0, "oracle_forged_reason": "",
                "app_tree_changes": []}

    monkeypatch.setattr(exhibit_a.sandbox, "run", fake_run)
    root, test = layout(tmp_path, VULN_APP, ACCESS_EXPLOIT)
    j = SandboxRunner(access_db=ACCESS_DB, access=dict(ACCESS)).run_exploit(
        root, test, ENTRY_POINTS, timeout=60.0, effect="canary_access")
    assert seen["effect"] == "canary_access"
    assert seen["access_db"] == ACCESS_DB and seen["access_victim"] == "victim"
    env_text = " ".join(f"{k}={v}" for k, v in seen["env"].items())
    assert "EXHIBIT_A_ATTACKER=attacker" in env_text
    assert "EXHIBIT_A_VICTIM" not in env_text and "victim" not in env_text.replace("access_victim", "")
    assert seen["canary_path"] is None
    assert j.reason_code == "no_effect"  # no events: nothing proven


# -- case schema -------------------------------------------------------------------------------

def _write_case(tmp_path, run):
    case = {"cases": [{"id": "idor-demo", "kind": "vulnerable", "repo": "", "commit": ""}],
            "run": {"baseline_test": "test_baseline.py", "effect": "canary_access",
                    "entry_points": ["App.handle_request"], "source_file": "app.py", **run}}
    (tmp_path / "case.json").write_text(json.dumps(case), encoding="utf-8")


def test_corpus_accepts_an_access_case(tmp_path):
    from bench.corpus import load_corpus

    _write_case(tmp_path, {"access_db": ACCESS_DB, "access": dict(ACCESS)})
    [case] = load_corpus(tmp_path / "case.json")
    assert (case.effect, case.access_db, case.access, case.redirect_meta) == (
        "canary_access", ACCESS_DB, dict(ACCESS), False)


@pytest.mark.parametrize("run", [
    {"access_db": ACCESS_DB, "access": dict(ACCESS), "effect": "canary_sql", "sql_db": "data/app.db"},
    {"access_db": "../outside.json", "access": dict(ACCESS)},
    {"access_db": ACCESS_DB},
    {"access": dict(ACCESS)},
    {"access_db": ACCESS_DB, "access": {"attacker": "a", "victim": "v"}},
])
def test_corpus_rejects_bad_access_cases(tmp_path, run):
    import pytest as _pytest

    from bench.corpus import load_corpus

    _write_case(tmp_path, run)
    with _pytest.raises(ValueError, match="access"):
        load_corpus(tmp_path / "case.json")


# -- docker sandbox ----------------------------------------------------------------------------


@pytest.mark.docker
@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_in_the_sandbox(tmp_path, source, test_source):
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []
    assert any(e.op == "response" and "CANARY-" in (e.body or "") for e in j.events)


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
    reason="R1 (docs/oracle/oracle-provenance.md 7.1 and 3.14): the test signs a response "
           "event with the stolen key; nothing else checks the response, so the sandbox "
           "run is proven too. Only an out-of-process observer closes this.",
)
def test_r1_a_forged_signed_response_proves_a_safe_app_in_the_sandbox(tmp_path, unguarded_sandbox):
    j = sandbox(tmp_path, FIXED_APP, PRELUDE + FORGE_ACCESS_EVENTS)
    assert shape(j) != PROVEN

