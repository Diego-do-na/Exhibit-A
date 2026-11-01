"""The canary_dos effect: algorithmic complexity proven on the host path and in Docker.

The runner times the entry point on a small malicious input against a benign input of
the same length, several times in one process. Proven only if the median application-CPU
ratio exceeds the documented threshold, the malicious CPU exceeds an absolute floor, and
that CPU was spent in admitted app frames reached through the entry point. Cheats
(sleeps, busy loops, slow benign input, self-timing) are not proven. A noisy machine is
flaky, never a proof. Design: docs/oracle/oracle-provenance.md, section 3.12.
"""

import os
import textwrap
from pathlib import Path

import pytest

from exhibit_a.cli.parser import build_parser
from exhibit_a.graph.catalog import match_sink, sink_hits
from exhibit_a.graph.build import build_graph
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.oracle import run_oracle
from exhibit_a.oracle.guard import dos_problem
from exhibit_a.oracle.oracle import (
    DOS_FLOOR,
    DOS_RATIO,
    REASON_FLAKY,
    _judge,
)
from exhibit_a.oracle.plugin import ENV_DOS
from exhibit_a.oracle.provenance import AppTree

ENTRY_POINTS = {"App.handle_request"}
PROVEN = ("failed", True, True)

REDOS_MAL = "a" * 22 + "!"
REDOS_BEN = "b" * 23
NESTED_MAL = "a" * 21
NESTED_BEN = "x" * 21
QUAD_MAL = "expand:" + "x" * 12000
QUAD_BEN = "normal:" + "x" * 12000


# -- applications ------------------------------------------------------------------------------

REDOS_APP = '''\
import re


class App:
    def handle_request(self, data):
        return bool(re.search(r"(a+)+$", data))
'''

NESTED_APP = '''\
import re


class App:
    def handle_request(self, data):
        return bool(re.search(r"(a*)*c", data))
'''

QUAD_APP = '''\
class App:
    def handle_request(self, data):
        prefix, _, rest = data.partition(":")
        if prefix != "expand":
            return len(rest)
        total = 0
        for i in range(len(rest)):
            total += rest.count(rest[i])
        return total
'''

ATOMIC_APP = '''\
import re


class App:
    def handle_request(self, data):
        return bool(re.search(r"(?>a+)+$", data))
'''

REWRITE_APP = '''\
import re


class App:
    def handle_request(self, data):
        return bool(re.search(r"a+$", data))
'''

CAP_APP = '''\
import re


class App:
    def handle_request(self, data):
        if len(data) > 16:
            raise ValueError("too long")
        return bool(re.search(r"(a+)+$", data))
'''

ECHO_APP = '''\
class App:
    def handle_request(self, data):
        return data
'''

HELPER_APP = '''\
import re


def scan(data):
    return bool(re.search(r"(a+)+$", data))


class App:
    def handle_request(self, data):
        return bool(re.search(r"^[a-z]+$", data))
'''

R5_APP = '''\
import re

PATTERN = r"^[a-z]+$"


class App:
    def handle_request(self, data):
        return bool(re.search(PATTERN, data))
'''


def probe(malicious, benign):
    return (
        "from app import App\n\n"
        "def test_exploit(dos_probe):\n"
        f"    dos_probe(App().handle_request, malicious={malicious!r}, benign={benign!r})\n"
    )


REDOS_EXPLOIT = probe(REDOS_MAL, REDOS_BEN)
NESTED_EXPLOIT = probe(NESTED_MAL, NESTED_BEN)
QUAD_EXPLOIT = probe(QUAD_MAL, QUAD_BEN)

TRUE_CASES = [
    ("catastrophic_backtracking", REDOS_APP, REDOS_EXPLOIT),
    ("nested_quantifiers", NESTED_APP, NESTED_EXPLOIT),
    ("quadratic_string_building", QUAD_APP, QUAD_EXPLOIT),
]

FIXED_CASES = [
    ("atomic_group", ATOMIC_APP, REDOS_EXPLOIT),
    ("rewritten_regex", REWRITE_APP, REDOS_EXPLOIT),
    ("input_length_cap", CAP_APP, REDOS_EXPLOIT),
]


def cheat(body):
    return "from app import App\n\n" + textwrap.dedent(body)


CHEATS = {
    "test_sleeps": (ECHO_APP, cheat(
        "import time\n"
        "def test_exploit():\n"
        "    time.sleep(0.2)\n"
        "    assert False\n")),
    "test_times_itself": (ECHO_APP, cheat(
        "import time\n"
        "def test_exploit():\n"
        "    t = time.process_time()\n"
        "    App().handle_request('x')\n"
        "    assert time.process_time() - t < 0.001\n")),
    "test_busy_loop_wrapper": (ECHO_APP, cheat(
        "def test_exploit(dos_probe):\n"
        "    def slow(data):\n"
        "        n = 0\n"
        "        for i in range(2_000_000):\n"
        "            n += i\n"
        "        return App().handle_request(data)\n"
        "    dos_probe(slow, malicious='a'*23, benign='b'*23)\n")),
    "test_slow_benign_input": (REDOS_APP, cheat(
        "def test_exploit(dos_probe):\n"
        f"    dos_probe(App().handle_request, malicious={REDOS_BEN!r}, benign={REDOS_MAL!r})\n")),
    "test_calls_an_internal_helper": (HELPER_APP, cheat(
        "import app\n"
        "def test_exploit(dos_probe):\n"
        f"    dos_probe(app.scan, malicious={REDOS_MAL!r}, benign={REDOS_BEN!r})\n")),
    "test_asserts_false_without_probe": (REDOS_APP, cheat(
        "def test_exploit():\n"
        "    assert False\n")),
    "test_hashes": (ECHO_APP, cheat(
        "import hashlib\n"
        "def test_exploit():\n"
        "    hashlib.pbkdf2_hmac('sha256', b'x', b'y', 200000)\n"
        "    assert False\n")),
}


@pytest.fixture
def unguarded(monkeypatch):
    monkeypatch.setattr("exhibit_a.oracle.oracle.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.oracle.oracle.dos_problem", lambda path: None)


@pytest.fixture
def unguarded_sandbox(monkeypatch):
    monkeypatch.setattr("exhibit_a.loop.runner.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.loop.runner.dos_problem", lambda path: None)


def layout(tmp_path, source, test_source):
    root, tests = tmp_path / "app", tmp_path / "tests"
    root.mkdir(parents=True)
    tests.mkdir(parents=True)
    (root / "app.py").write_text(source, encoding="utf-8")
    (tests / "test_exploit.py").write_text(test_source, encoding="utf-8")
    return root, tests / "test_exploit.py"


def host(tmp_path, source, test_source, entry_points=ENTRY_POINTS):
    root, test = layout(tmp_path, source, test_source)
    return run_oracle(root, test, entry_points, effect="canary_dos", timeout=60.0)


def sandbox(tmp_path, source, test_source, entry_points=ENTRY_POINTS):
    root, test = layout(tmp_path, source, test_source)
    return SandboxRunner().run_exploit(root, test, entry_points, timeout=120.0, effect="canary_dos")


def shape(j):
    return j.test_outcome, j.observed_effect, j.provenance_ok


# -- host path ---------------------------------------------------------------------------------


@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []
    [event] = [e for e in j.events if e.op == "dos"]
    assert event.ratio is not None and event.ratio > DOS_RATIO
    assert event.malicious_cpu is not None and event.malicious_cpu >= DOS_FLOOR
    print(f"host ratio={event.ratio:.1f}x malicious_cpu={event.malicious_cpu:.4f}s "
          f"benign_cpu={event.benign_cpu:.6f}s app_fraction={event.app_fraction:.3f}")


def test_the_proof_records_application_frames_through_the_entry_point(tmp_path):
    j = host(tmp_path, REDOS_APP, REDOS_EXPLOIT)
    assert shape(j) == PROVEN, j.reason
    admitted = [f.qualname for e in j.events for f in e.stack if f.admitted]
    assert "App.handle_request" in admitted


@pytest.mark.parametrize(
    "source, test_source", [c[1:] for c in FIXED_CASES], ids=[c[0] for c in FIXED_CASES],
)
def test_a_fixed_app_is_not_proven_on_the_host_path(tmp_path, source, test_source):
    j = host(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason
    assert j.forged_events == 0 and j.app_tree_changes == []


@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_on_the_host_path_guard_on(tmp_path, name):
    source, test_source = CHEATS[name]
    j = host(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_on_the_host_path_guard_off(tmp_path, unguarded, name):
    source, test_source = CHEATS[name]
    j = host(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


def test_injected_timing_noise_is_not_a_proof(tmp_path, unguarded):
    """Random extra work around the call must not mint a proof on a safe app."""
    test_source = cheat('''\
import random

def test_exploit(dos_probe):
    def noisy(data):
        n = random.randint(0, 400000)
        acc = 0
        for i in range(n):
            acc += i
        return App().handle_request(data)
    dos_probe(noisy, malicious="a" * 23, benign="b" * 23)
''')
    j = host(tmp_path, ECHO_APP, test_source)
    assert shape(j) != PROVEN, j.reason
    assert j.reason_code in ("", "no_effect", "flaky", "dos_from_test", "provenance",
                             "frame_not_admitted")


def test_unequal_lengths_are_not_a_proof(tmp_path):
    test_source = cheat(
        "def test_exploit(dos_probe):\n"
        "    dos_probe(App().handle_request, malicious='aaa!', benign='bb')\n"
    )
    j = host(tmp_path, REDOS_APP, test_source)
    assert shape(j) != PROVEN, j.reason


# -- guard -------------------------------------------------------------------------------------


def guard(tmp_path, source):
    path = tmp_path / "test_x.py"
    path.write_text("from app import App\n" + source, encoding="utf-8")
    return dos_problem(path)


@pytest.mark.parametrize("line", [
    "import time; time.sleep(1)",
    "time.process_time()",
    "time.thread_time()",
    "time.perf_counter()",
    "sys.setprofile(None)",
    "import resource",
    "hashlib.pbkdf2_hmac('sha256', b'a', b'b', 1)",
])
def test_the_guard_refuses_a_test_that_times_itself(tmp_path, line):
    assert guard(tmp_path, f"def test_exploit():\n    {line}\n") is not None


def test_the_guard_allows_a_test_that_uses_only_the_probe(tmp_path):
    source = (
        "def test_exploit(dos_probe):\n"
        "    dos_probe(App().handle_request, malicious='aaa!', benign='bbbb')\n"
    )
    assert guard(tmp_path, source) is None


def test_the_guard_checks_a_shipped_conftest(tmp_path):
    (tmp_path / "conftest.py").write_text("import time\ntime.sleep(1)\n")
    path = tmp_path / "test_x.py"
    path.write_text("def test_exploit():\n    pass\n")
    assert "conftest.py" in dos_problem(path)


# -- plumbing ----------------------------------------------------------------------------------


def test_cli_accepts_the_effect():
    args = build_parser().parse_args(["run", "--effect", "canary_dos", "--pr-diff", "a..b"])
    assert args.effect == "canary_dos"


def test_the_contract_asks_for_two_inputs_and_forbids_timing():
    from exhibit_a.loop import prompts

    text = prompts.test_contract("canary_dos", ["pkg==1"])
    assert "dos_probe" in text and "same length" in text.lower() and "pkg==1" in text
    assert "EXHIBIT_A_CANARY_DOS" not in text
    assert "time.sleep" in text and "must not time" in text


@pytest.mark.parametrize("name", ["re.search", "re.match", "re.fullmatch", "re.sub",
                                  "re.findall", "re.compile"])
def test_the_catalog_maps_regex_sinks_to_the_effect(name):
    rule = match_sink(name)
    assert (rule.vuln_class, rule.effect) == ("regex_denial_of_service", "canary_dos")


def test_the_catalog_maps_json_parsing_to_the_effect():
    rule = match_sink("json.loads")
    assert (rule.vuln_class, rule.effect) == ("algorithmic_complexity", "canary_dos")


def test_the_catalog_flags_a_catastrophic_constant_and_skips_a_linear_one(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "app.py").write_text(
        "import re\n"
        "def bad(data):\n"
        "    return re.search(r'(a+)+$', data)\n"
        "def good(data):\n"
        "    return re.search(r'^[a-z]+$', data)\n"
        "def dyn(pattern, data):\n"
        "    return re.search(pattern, data)\n",
        encoding="utf-8",
    )
    hits = sink_hits(build_graph(root))
    names = {node.split(":", 1)[1]: found for node, found in hits.items()}
    assert names["bad"][0].effect == "canary_dos"
    assert "good" not in names
    assert names["dyn"][0].effect == "canary_dos"


# -- what the judge refuses --------------------------------------------------------------------


def _dos_event(**fields):
    from exhibit_a.oracle import OracleEvent

    stack = [
        {"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
        {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
         "line": 5, "admitted": True},
    ]
    base = {
        "path": "dos", "mode": "dos_probe", "op": "dos", "access": "cpu", "stack": stack,
        "ratio": 80.0, "malicious_cpu": 0.08, "benign_cpu": 0.001, "app_fraction": 0.95,
        "samples": 5, "noisy": False,
    }
    return OracleEvent.model_validate({**base, **fields})


@pytest.fixture
def tree(tmp_path):
    import hashlib

    source = "class App:\n\n\n\n    def handle_request(self):\n        pass\n"
    (tmp_path / "app.py").write_text(source)
    return AppTree("/a", tmp_path, {"app.py": hashlib.sha256(source.encode()).hexdigest()})


def judge(tree, events, outcome="failed"):
    return _judge(outcome, events, Path("/a"), Path("/t/test_exploit.py"), ENTRY_POINTS,
                  effect="canary_dos", app_tree=tree)


def test_the_judge_proves_only_when_everything_holds(tree):
    j = judge(tree, [_dos_event()])
    assert shape(j) == PROVEN and j.reason_code == ""


def test_a_ratio_below_the_threshold_is_not_a_proof(tree):
    j = judge(tree, [_dos_event(ratio=10.0, malicious_cpu=0.08)])
    assert shape(j) != PROVEN and j.reason_code == "no_effect"


def test_cpu_below_the_floor_is_not_a_proof(tree):
    j = judge(tree, [_dos_event(ratio=80.0, malicious_cpu=0.001)])
    assert shape(j) != PROVEN and j.reason_code == "no_effect"


def test_cpu_in_test_frames_is_not_a_proof(tree):
    j = judge(tree, [_dos_event(app_fraction=0.2)])
    assert j.reason_code == "dos_from_test"


def test_noisy_samples_are_flaky_never_proven(tree):
    j = judge(tree, [_dos_event(noisy=True)])
    assert shape(j) != PROVEN and j.reason_code == REASON_FLAKY


def test_a_nan_measurement_is_flaky_never_proven(tree):
    j = judge(tree, [_dos_event(ratio=float("nan"))])
    assert shape(j) != PROVEN and j.reason_code == REASON_FLAKY


def test_a_stolen_profiler_is_not_a_proof(tree):
    j = judge(tree, [_dos_event(patched="sys.setprofile")])
    assert j.reason_code == "dos_api_changed"


def test_no_probe_event_is_not_a_proof(tree):
    j = judge(tree, [])
    assert shape(j) == ("failed", False, False) and j.reason_code == "no_effect"


def test_a_passing_test_is_not_a_proof(tree):
    j = judge(tree, [_dos_event()], outcome="passed")
    assert shape(j) == ("passed", True, True) and j.reason_code == "no_effect"


def test_without_the_staged_app_nothing_is_proven():
    j = _judge("failed", [_dos_event()], Path("/a"), Path("/t/test_exploit.py"),
               ENTRY_POINTS, effect="canary_dos", app_tree=None)
    assert shape(j) != PROVEN


def test_an_unadmitted_frame_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
             {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
              "line": 5, "admitted": False, "admission": "code object differs"}]
    j = judge(tree, [_dos_event(stack=stack)])
    assert j.reason_code == "frame_not_admitted"


# -- residual limits ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R1 (docs/oracle/oracle-provenance.md 7.1 and 3.12): a test that steals emit can "
           "sign a dos event that names the entry point's real frame",
)
def test_r1_forged_dos_event_is_a_false_proof(tmp_path, unguarded):
    test_source = cheat('''\
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
    emit({"path": "dos", "mode": "dos_probe", "op": "dos", "flags": None, "access": "cpu",
          "requested": None, "via_symlink": False, "stack": [caller, frame],
          "ratio": 80.0, "malicious_cpu": 0.08, "benign_cpu": 0.001, "app_fraction": 0.95,
          "samples": 5, "noisy": False, "patched": None, "command": "23=23"})
    assert False
''')
    j = host(tmp_path, ECHO_APP, test_source)
    assert shape(j) != PROVEN, j.reason


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R5 (docs/oracle/oracle-provenance.md 7.5 and 3.12): replacing a binding in the "
           "app's own module makes admitted code really run a catastrophic pattern",
)
def test_r5_app_binding_is_a_false_proof(tmp_path, unguarded):
    test_source = cheat('''\
import sys

def test_exploit(dos_probe):
    setattr(sys.modules["ap" + "p"], "PAT" + "TERN", r"(a+)+$")
    dos_probe(App().handle_request, malicious="a" * 22 + "!", benign="b" * 23)
''')
    j = host(tmp_path, R5_APP, test_source)
    assert shape(j) != PROVEN, j.reason


# -- fixture trees -----------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures" / "dos"


def test_the_shipped_fixture_trees_prove_and_refuse_on_the_host_path(tmp_path):
    root = tmp_path / "app"
    tests = tmp_path / "tests"
    root.mkdir()
    tests.mkdir()
    (root / "app.py").write_text((FIXTURES / "vulnerable" / "app.py").read_text(), encoding="utf-8")
    (tests / "test_exploit.py").write_text(REDOS_EXPLOIT, encoding="utf-8")
    proven = run_oracle(root, tests / "test_exploit.py", ENTRY_POINTS,
                        effect="canary_dos", timeout=60.0)
    assert shape(proven) == PROVEN, proven.reason
    (root / "app.py").write_text((FIXTURES / "fixed" / "app.py").read_text(), encoding="utf-8")
    refused = run_oracle(root, tests / "test_exploit.py", ENTRY_POINTS,
                         effect="canary_dos", timeout=60.0)
    assert shape(refused) != PROVEN, refused.reason


# -- sandbox plumbing (no container) -----------------------------------------------------------


def _fake_docker(monkeypatch, tmp_path, on_run):
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


def _dos_run_kwargs(tmp_path, env_extra=None):
    env = {"EXHIBIT_A_CANARY_TOKEN": "CANARY-x", ENV_DOS: "1"}
    env.update(env_extra or {})
    events = tmp_path / "events.jsonl"
    events.write_text("")
    return {"image": "i", "effect": "canary_dos", "events_path": str(events), "env": env}


def test_the_sandbox_refuses_a_dos_run_it_could_not_set_up(tmp_path, monkeypatch):
    from exhibit_a.sandbox.runner import run

    _fake_docker(monkeypatch, tmp_path, lambda cmd: None)
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "test_x.py").write_text("")
    base = _dos_run_kwargs(tmp_path)
    with_canary = dict(base, canary_path=str(clone / "test_x.py"))
    no_events = {"image": "i", "effect": "canary_dos", "env": base["env"]}
    results = [run(str(clone), "test_x.py", 5, **kwargs) for kwargs in (with_canary, no_events)]
    assert {r["outcome"] for r in results} == {"env_failure"}
    assert ENV_DOS == "EXHIBIT_A_CANARY_DOS"


def test_the_loop_runner_hands_the_dos_flag_to_the_sandbox(tmp_path, monkeypatch):
    import exhibit_a.sandbox

    seen = {}

    def fake_run(*args, **kwargs):
        seen.update(kwargs)
        return {"outcome": "failed", "exit_code": 1, "stdout": "", "stderr": "",
                "oracle_events": [], "oracle_forged_events": 0, "oracle_forged_reason": "",
                "app_tree_changes": []}

    monkeypatch.setattr(exhibit_a.sandbox, "run", fake_run)
    root, test = layout(tmp_path, REDOS_APP, REDOS_EXPLOIT)
    j = SandboxRunner().run_exploit(root, test, ENTRY_POINTS, timeout=60.0, effect="canary_dos")
    assert seen["effect"] == "canary_dos"
    assert seen["env"][ENV_DOS] == "1"
    assert seen["canary_path"] is None
    assert j.reason_code == "no_effect"


# -- docker sandbox ----------------------------------------------------------------------------


@pytest.mark.docker
@pytest.mark.parametrize("source, test_source", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_in_the_sandbox(tmp_path, source, test_source):
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []
    [event] = [e for e in j.events if e.op == "dos"]
    assert event.ratio > DOS_RATIO and event.malicious_cpu >= DOS_FLOOR
    print(f"sandbox ratio={event.ratio:.1f}x malicious_cpu={event.malicious_cpu:.4f}s "
          f"benign_cpu={event.benign_cpu:.6f}s")


@pytest.mark.docker
def test_a_vulnerable_app_is_proven_across_three_consecutive_sandbox_runs(tmp_path):
    ratios = []
    for i in range(3):
        j = sandbox(tmp_path / f"run{i}", REDOS_APP, REDOS_EXPLOIT)
        assert shape(j) == PROVEN, f"run {i + 1}: {j.reason}"
        [event] = [e for e in j.events if e.op == "dos"]
        ratios.append(event.ratio)
        print(f"consecutive run {i + 1} ratio={event.ratio:.1f}x "
              f"malicious_cpu={event.malicious_cpu:.4f}s")
    assert all(r > DOS_RATIO for r in ratios)


@pytest.mark.docker
@pytest.mark.parametrize(
    "source, test_source", [c[1:] for c in FIXED_CASES], ids=[c[0] for c in FIXED_CASES],
)
def test_a_fixed_app_is_not_proven_in_the_sandbox(tmp_path, source, test_source):
    j = sandbox(tmp_path, source, test_source)
    assert shape(j) != PROVEN, j.reason


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
def test_the_sandbox_keeps_its_limits_for_the_dos_effect(tmp_path, monkeypatch):
    from exhibit_a.sandbox import runner as sandbox_runner

    seen = []
    real_run = sandbox_runner.subprocess.run

    def spy(cmd, *args, **kwargs):
        if isinstance(cmd, list) and cmd[:2] == ["docker", "run"]:
            seen.append(list(cmd))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(sandbox_runner.subprocess, "run", spy)
    assert shape(sandbox(tmp_path, REDOS_APP, REDOS_EXPLOIT)) == PROVEN
    assert seen, "the sandbox never ran a container"
    joined = " ".join(seen[-1])
    for flag in ("--network none", "--cap-drop ALL", "no-new-privileges", "--pids-limit", "--memory"):
        assert flag in joined, joined
    assert "--cpus" in joined or "cpus=" in joined
    assert f"{ENV_DOS}=1" in joined
