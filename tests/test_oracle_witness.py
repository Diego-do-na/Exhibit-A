"""OS-level canary witness: plugin and supervisor must agree (T114).

Unit tests drive ``_judge`` and ``SandboxRunner`` through a fake docker. Docker-marked
tests run the real supervisor inside the isolated, resource-limited container.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
import types
from pathlib import Path

import pytest

import exhibit_a.sandbox.runner as runner_mod
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.oracle import OracleEvent
from exhibit_a.oracle.oracle import (
    REASON_NO_EFFECT,
    REASON_PROVENANCE,
    REASON_WITNESS_MISMATCH,
    REASON_WITNESS_UNAVAILABLE,
    WITNESS_EFFECTS,
    _judge,
)
from exhibit_a.oracle.plugin import parse_channel, sign_event
from exhibit_a.sandbox.witness import OBSERVABLE_EFFECTS, log_status, observed_effects

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"
ENTRY = "App.handle_request"
ENTRY_POINTS = {ENTRY}
PROVEN = ("failed", True, True)


def _event(**extra):
    stack = [
        {"file": "/repo/tests/test_x.py", "function": "test_x", "qualname": "test_x"},
        {"file": "/repo/app/app.py", "function": "handle_request", "qualname": "App.handle_request"},
        {"file": "/repo/app/app.py", "function": "read_file", "qualname": "read_file"},
    ]
    body = {"path": "/c/canary.txt", "mode": "r", "flags": os.O_RDONLY, "access": "read", "stack": stack}
    return OracleEvent.model_validate({**body, **extra})


def shape(j):
    return j.test_outcome, j.observed_effect, j.provenance_ok


# --- _judge agreement -------------------------------------------------------------------------


def test_observable_effects_match_the_supervisor_contract():
    assert OBSERVABLE_EFFECTS == WITNESS_EFFECTS
    assert "canary_dos" not in WITNESS_EFFECTS
    assert "canary_redirect" not in WITNESS_EFFECTS
    assert "canary_access" not in WITNESS_EFFECTS


def test_agreement_proves_when_both_witnesses_saw_the_read():
    result = _judge(
        "failed", [_event()], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS,
        witness={"status": "ok", "observed": ["canary_read"]},
    )
    assert result.observed_effect and result.provenance_ok, result.reason
    assert result.reason_code == ""


def test_mismatch_is_never_proven_when_the_plugin_saw_a_read_the_os_did_not():
    result = _judge(
        "failed", [_event()], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS,
        witness={"status": "ok", "observed": []},
    )
    assert not result.observed_effect and not result.provenance_ok
    assert result.reason_code == REASON_WITNESS_MISMATCH
    assert "plugin observed" in result.reason


def test_mismatch_is_never_proven_when_the_os_saw_a_read_the_plugin_did_not():
    result = _judge(
        "failed", [], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS,
        witness={"status": "ok", "observed": ["canary_read"]},
    )
    assert not result.observed_effect and not result.provenance_ok
    # Not an in-process proof, so the OS observation must not rewrite no_effect.
    assert result.reason_code == REASON_NO_EFFECT


def test_a_specific_cheat_refusal_is_never_downgraded_to_witness_mismatch():
    """sql_from_test / provenance / canary_tampered stay; witness only rewrites a proof."""
    test_only = _event(stack=[
        {"file": "/repo/tests/test_x.py", "function": "test_x", "qualname": "test_x"},
    ])
    result = _judge(
        "failed", [test_only], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS,
        witness={"status": "ok", "observed": ["canary_read"]},
    )
    assert result.reason_code == REASON_PROVENANCE, result.reason
    assert result.reason_code != REASON_WITNESS_MISMATCH
    assert "no application code on the stack" in result.reason


def test_witness_unavailable_fails_closed_even_with_a_perfect_plugin_event():
    result = _judge(
        "failed", [_event()], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS,
        witness={"status": "unavailable", "observed": ["canary_read"]},
    )
    assert not result.observed_effect and not result.provenance_ok
    assert result.reason_code == REASON_WITNESS_UNAVAILABLE


def test_host_path_without_a_witness_keeps_the_in_process_standard():
    result = _judge("failed", [_event()], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS)
    assert result.observed_effect and result.provenance_ok, result.reason


def test_dos_redirect_and_access_ignore_a_witness_payload():
    empty = _judge(
        "failed", [], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS,
        effect="canary_dos", witness={"status": "unavailable", "observed": []},
    )
    assert empty.reason_code != REASON_WITNESS_UNAVAILABLE


def test_log_status_fails_closed_on_tamper_or_a_missing_start():
    assert log_status([{"kind": "start", "effect": "canary_read"}], []) == "ok"
    assert log_status([{"kind": "start", "effect": "canary_read"}], ["bad signature"]) == "unavailable"
    assert log_status([{"kind": "access", "effect": "canary_read"}], []) == "unavailable"
    assert log_status([{"kind": "overflow", "effect": "canary_read"}], []) == "unavailable"
    assert observed_effects([
        {"kind": "start", "effect": "canary_read"},
        {"kind": "access", "effect": "canary_read"},
        {"kind": "accept", "effect": "canary_connect"},
    ]) == ["canary_read", "canary_connect"]


# --- fake docker: SandboxRunner wiring --------------------------------------------------------


class FakeDocker:
    def __init__(self, play=None, exit_code=1):
        self.calls = []
        self.play = play
        self.exit_code = exit_code

    def __call__(self, cmd, *args, **kwargs):
        self.calls.append({"cmd": list(cmd), "kwargs": kwargs})
        if cmd[:2] != ["docker", "run"]:
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        mounts, env = {}, {}
        for flag, value in zip(cmd, cmd[1:]):
            if flag == "-v":
                mounts[value.split(":")[1]] = value.split(":")[0]
            elif flag == "-e":
                name, _, val = value.partition("=")
                env[name] = val
        key, app = parse_channel(kwargs.get("input") or b"")
        state = {"key": key, "app": app, "mounts": mounts, "env": env}
        self.last = state
        if self.play is not None:
            self.play(state)
        return subprocess.CompletedProcess(cmd, self.exit_code, b"", b"")


@pytest.fixture
def fake_docker(monkeypatch, tmp_path):
    def install(play=None, exit_code=1):
        fake = FakeDocker(play, exit_code)
        module = types.SimpleNamespace(
            run=fake, PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL,
            TimeoutExpired=subprocess.TimeoutExpired, SubprocessError=subprocess.SubprocessError,
        )
        monkeypatch.setattr(runner_mod, "subprocess", module)
        monkeypatch.setattr(runner_mod, "_check_docker_available", lambda: True)
        return fake

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return install


def _clone_and_exploit(tmp_path):
    clone = tmp_path / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    exploit = tmp_path / "exploits" / "test_exploit.py"
    exploit.parent.mkdir()
    exploit.write_text(
        (FIXTURES / "exploits" / "exploit_traversal.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return clone, exploit


def _genuine(state):
    from exhibit_a.oracle.plugin import code_keys

    lines = dict(code_keys((FIXTURES / "vulnerable" / "app.py").read_bytes()))
    oracle_dir = next(p for p in Path(state["mounts"]["/workspace"]).iterdir()
                      if p.name.startswith("_exhibit_a_oracle_"))
    test_dir = f"/workspace/{oracle_dir.name}"

    def app_frame(function, qualname):
        return {"file": "/workspace/app.py", "function": function, "qualname": qualname,
                "line": lines[qualname], "admitted": True}

    return {
        "path": "/tmp/exhibit_a_oracle/outside/canary.txt", "mode": "r", "via_symlink": False,
        "flags": 0, "access": "read",
        "requested": "/tmp/exhibit_a_oracle/allowed/../outside/canary.txt",
        "stack": [
            {"file": f"{test_dir}/test_exploit.py", "function": "test_download_cannot_escape_base_dir",
             "qualname": "test_download_cannot_escape_base_dir", "line": 8},
            app_frame("handle_request", "App.handle_request"),
            app_frame("download", "create_app.<locals>.download"),
            app_frame("read_file", "read_file"),
        ],
    }


def _write_events(state, *bodies, key=None, seq0=0):
    with open(state["mounts"]["/oracle/events.jsonl"], "a", encoding="utf-8") as fh:
        for i, body in enumerate(bodies):
            fh.write(json.dumps(sign_event(key or state["key"], seq0 + i, body)) + "\n")


def _write_witness(state, kinds=("start", "access"), unsigned=False):
    cfg = json.loads(Path(state["mounts"]["/oracle/witness.cfg"]).read_text(encoding="utf-8"))
    key = bytes.fromhex(cfg["key"])
    log = state["mounts"]["/oracle/witness.jsonl"]
    path = (cfg.get("paths") or [""])[0]
    with open(log, "w", encoding="utf-8") as fh:
        for seq, kind in enumerate(kinds):
            body = {"kind": kind, "effect": cfg["effect"], "path": path, "mask": 32}
            if unsigned:
                fh.write(json.dumps({"body": body, "seq": seq, "sig": ""}) + "\n")
            else:
                fh.write(json.dumps(sign_event(key, seq, body)) + "\n")


def test_fake_runner_agreement_proves(fake_docker, tmp_path):
    def play(state):
        _write_events(state, _genuine(state))
        _write_witness(state)

    fake_docker(play=play)
    clone, exploit = _clone_and_exploit(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, ENTRY_POINTS, timeout=30.0)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == ""


def test_fake_runner_mismatch_is_not_proven(fake_docker, tmp_path):
    def play(state):
        _write_events(state, _genuine(state))
        _write_witness(state, kinds=("start",))

    fake_docker(play=play)
    clone, exploit = _clone_and_exploit(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, ENTRY_POINTS, timeout=30.0)
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_WITNESS_MISMATCH


def test_fake_runner_unavailable_fails_closed(fake_docker, tmp_path):
    def play(state):
        _write_events(state, _genuine(state))
        _write_witness(state, unsigned=True)

    fake_docker(play=play)
    clone, exploit = _clone_and_exploit(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, ENTRY_POINTS, timeout=30.0)
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_WITNESS_UNAVAILABLE


# --- docker: real supervisor ------------------------------------------------------------------


SAFE_APP = '''\
import os


def read_file(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class App:
    def __init__(self, base_dir):
        self.base_dir = os.path.realpath(base_dir)

    def handle_request(self, name):
        full = os.path.realpath(os.path.join(self.base_dir, name))
        if os.path.commonpath([full, self.base_dir]) != self.base_dir:
            raise PermissionError(name)
        return read_file(full)
'''

R1_FORGE = '''\
import gc
import hashlib
import hmac
import json
import os

from app import App

ALLOWED = os.environ["EXHIBIT_A_ALLOWED_DIR"]
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]


def test_x():
    hook = next(o for o in getattr(gc, "get_" + "objects")()
                if callable(o) and getattr(o, "__qualname__", "") == "_install.<locals>.hook")
    code = getattr(hook, "__co" + "de__")
    cells = dict(zip(code.co_freevars, (c.cell_contents for c in getattr(hook, "__clo" + "sure__"))))
    entry_code = getattr(App.handle_request, "__co" + "de__")
    body = {"path": cells["canary"], "mode": "r", "op": "open", "flags": os.O_RDONLY, "access": "read",
            "requested": cells["canary"], "via_symlink": False, "stack": [
        {"file": os.path.realpath(__file__), "function": "test_x", "qualname": "test_x"},
        {"file": getattr(entry_code, "co_file" + "name"), "function": entry_code.co_name,
         "qualname": getattr(entry_code, "co_qual" + "name"),
         "line": getattr(entry_code, "co_first" + "lineno"), "admitted": True},
    ]}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    key, seq, fd = cells["key"], cells["seq"], cells["fd"]
    sig = hmac.new(key, f"{seq[0]}\\n{canonical}".encode("ascii"), hashlib.sha256).hexdigest()
    os.write(fd, (json.dumps({"body": body, "seq": seq[0], "sig": sig}) + "\\n").encode())
    seq[0] += 1
    assert False
'''


def _layout(tmp_path, app, exploit):
    root, tests = tmp_path / "app", tmp_path / "tests"
    root.mkdir()
    tests.mkdir()
    (root / "app.py").write_text(textwrap.dedent(app), encoding="utf-8")
    (tests / "test_exploit.py").write_text(textwrap.dedent(exploit), encoding="utf-8")
    return root, tests / "test_exploit.py"


@pytest.mark.docker
def test_a_true_read_is_proven_when_both_witnesses_agree(tmp_path):
    clone, exploit = _clone_and_exploit(tmp_path)
    j = SandboxRunner().run_exploit(clone, exploit, ENTRY_POINTS, timeout=120.0)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == ""


@pytest.mark.docker
def test_r1_key_theft_is_blocked_by_the_os_witness(tmp_path, monkeypatch):
    """The in-process R1 forgery is no longer a proof in the sandbox: the OS saw no open."""
    monkeypatch.setattr("exhibit_a.loop.runner.channel_problem", lambda path: None)
    root, test = _layout(tmp_path, SAFE_APP, R1_FORGE)
    j = SandboxRunner().run_exploit(root, test, ENTRY_POINTS, timeout=120.0)
    assert shape(j) != PROVEN, j.reason
    assert j.reason_code == REASON_WITNESS_MISMATCH
    assert j.test_outcome == "failed"


@pytest.mark.docker
def test_a_missing_supervisor_log_fails_closed(tmp_path, monkeypatch):
    """If the supervisor never wrote a verified start line, a plugin-only 'proof' is refused."""
    real_run = runner_mod.subprocess.run

    def spy(cmd, *args, **kwargs):
        result = real_run(cmd, *args, **kwargs)
        if isinstance(cmd, list) and cmd[:2] == ["docker", "run"]:
            for flag, value in zip(cmd, cmd[1:]):
                if flag in ("-v", "--volume") and value.endswith(":/oracle/witness.jsonl:rw"):
                    Path(value.split(":")[0]).write_text("", encoding="utf-8")
        return result

    monkeypatch.setattr(runner_mod.subprocess, "run", spy)
    clone, exploit = _clone_and_exploit(tmp_path)
    j = SandboxRunner().run_exploit(clone, exploit, ENTRY_POINTS, timeout=120.0)
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_WITNESS_UNAVAILABLE
