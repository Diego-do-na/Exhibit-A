"""Node oracle v1: canary_read and canary_exec with the shared judge.

Non-docker tests drive ``_judge`` and ``SandboxRunner`` through a fake docker.
Docker-marked tests run ``node --test`` in the pinned Node sandbox. The Python
oracle path is not exercised here; ``tests/test_oracle.py`` covers it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import types
from pathlib import Path

import pytest

from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.oracle.js import PLUGIN_CJS, PLUGIN_MOUNT, is_js, language_of, node_test_argv
from exhibit_a.oracle.oracle import (
    REASON_FORGED_EVENTS,
    REASON_FRAME_NOT_ADMITTED,
    REASON_NO_EFFECT,
    REASON_PROVENANCE,
    REASON_WITNESS_MISMATCH,
    REASON_WITNESS_UNAVAILABLE,
    _judge,
)
from exhibit_a.oracle.plugin import parse_channel, sign_event, verify_lines
from exhibit_a.oracle.provenance import AppTree, app_manifest
from exhibit_a.sandbox import runner as runner_mod

FIXTURES = Path(__file__).parent / "fixtures" / "js"
READ = FIXTURES / "read"
EXEC = FIXTURES / "exec"
HTTP = FIXTURES / "http"
ENTRY = {"handleRequest"}
PROVEN = ("failed", True, True)


def shape(j):
    return j.test_outcome, j.observed_effect, j.provenance_ok


# --- language switch (no docker) --------------------------------------------------------------


def test_js_suffix_selects_javascript():
    assert language_of("test_exploit.js") == "javascript"
    assert language_of("test_exploit.ts") == "typescript"
    assert language_of("test_exploit.py") == "python"
    assert language_of("test_exploit.js", "python") == "javascript"
    assert is_js("javascript") and is_js("typescript") and not is_js("python")


def test_node_test_argv_uses_tsx_for_typescript():
    js = node_test_argv("t/test_exploit.js")
    ts = node_test_argv("t/test_exploit.ts", typescript=True)
    assert js[0] == "node" and "--test" in js
    assert "--experimental-test-isolation=none" in js
    assert "--import" not in js and "tsx" not in js
    assert ts[1:3] == ["--import", "/opt/sandbox/node_modules/tsx/dist/loader.mjs"]
    assert ts[-1] == "/workspace/t/test_exploit.ts"


def test_preload_is_plain_commonjs_without_dependencies():
    source = PLUGIN_CJS.read_text(encoding="utf-8")
    assert "require('node:" in source
    assert "from '" not in source and "from \"" not in source
    assert "node_modules" not in source
    assert PLUGIN_MOUNT.endswith("oracle.cjs")


def test_node_hmac_matches_python_verify_lines(tmp_path):
    key = b"a" * 32
    body = {"path": "/oracle/canary", "mode": "r", "stack": [], "via_symlink": False, "op": "open",
            "flags": 0, "access": "read", "requested": "/tmp/a/allowed/../outside/canary.txt"}
    script = r"""
const crypto = require('node:crypto');
const body = JSON.parse(process.argv[1]);
const key = Buffer.from(process.argv[2], 'hex');
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}
const seq = 0;
const payload = Buffer.from(String(seq) + '\n' + canonical(body), 'ascii');
const sig = crypto.createHmac('sha256', key).update(payload).digest('hex');
process.stdout.write(JSON.stringify({body, seq, sig}));
"""
    proc = subprocess.run(
        ["node", "-e", script, json.dumps(body), key.hex()],
        capture_output=True, text=True, check=True,
    )
    line = proc.stdout
    events, rejected = verify_lines([line], key)
    assert rejected == []
    assert events == [body]
    python_line = json.dumps(sign_event(key, 0, body))
    events2, rejected2 = verify_lines([python_line], key)
    assert rejected2 == [] and events2 == [body]


# --- fake docker ------------------------------------------------------------------------------


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
        state = {"key": key, "app": app, "mounts": mounts, "env": env, "cmd": list(cmd)}
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
        monkeypatch.setattr(runner_mod, "build_node_image", lambda pkgs: "node-image:test")
        monkeypatch.setattr(runner_mod, "build_image", lambda reqs: "python-image:test")
        return fake

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return install


def _stage_read(tmp_path, tree="vulnerable", exploit="exploit_traversal.js"):
    clone = tmp_path / "clone"
    shutil.copytree(READ / tree, clone)
    exploit_path = tmp_path / "exploits" / exploit
    exploit_path.parent.mkdir(parents=True)
    shutil.copyfile(READ / "exploits" / exploit, exploit_path)
    return clone, exploit_path


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


def _read_event(state, *, from_test=False, function="handleRequest"):
    workspace = Path(state["mounts"]["/workspace"])
    oracle_dir = next(p for p in workspace.iterdir() if p.name.startswith("_exhibit_a_oracle_"))
    test_file = f"/workspace/{oracle_dir.name}/test_exploit.js"
    app_frame = {
        "file": "/workspace/app.js", "function": function, "qualname": function,
        "line": 1, "admitted": True,
    }
    test_frame = {
        "file": test_file, "function": "download cannot escape base dir",
        "qualname": "download cannot escape base dir", "line": 8,
    }
    stack = [test_frame, app_frame]
    if from_test:
        stack = [test_frame]
    return {
        "path": "/tmp/exhibit_a_oracle/outside/canary.txt",
        "mode": "r",
        "via_symlink": False,
        "op": "open",
        "flags": 0,
        "access": "read",
        "requested": "/tmp/exhibit_a_oracle/allowed/../outside/canary.txt",
        "stack": stack,
    }


def test_fake_runner_selects_the_node_image_and_preload(fake_docker, tmp_path):
    seen = {}

    def play(state):
        seen["cmd"] = state["cmd"]
        seen["env"] = state["env"]
        _write_events(state, _read_event(state))
        _write_witness(state)

    fake = fake_docker(play=play)
    clone, exploit = _stage_read(tmp_path)
    SandboxRunner(language="javascript", image="node-image:test").run_exploit(
        clone, exploit, ENTRY, timeout=30.0,
    )
    cmd = seen["cmd"]
    joined = " ".join(cmd)
    assert "node-image:test" in cmd
    assert PLUGIN_MOUNT + ":ro" in joined
    assert any(part.startswith("NODE_OPTIONS=--require=") and PLUGIN_MOUNT in part for part in cmd)
    assert "--test" in cmd
    assert "pytest" not in cmd
    assert fake.last["app"]["root"] == "/workspace"


def test_fake_runner_agreement_proves_a_js_read(fake_docker, tmp_path):
    def play(state):
        _write_events(state, _read_event(state))
        _write_witness(state)

    fake_docker(play=play)
    clone, exploit = _stage_read(tmp_path)
    j = SandboxRunner(language="javascript", image="node-image:test").run_exploit(
        clone, exploit, ENTRY, timeout=30.0,
    )
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == ""


def test_fake_runner_missing_events_are_not_proven(fake_docker, tmp_path):
    def play(state):
        _write_witness(state)

    fake_docker(play=play)
    clone, exploit = _stage_read(tmp_path)
    j = SandboxRunner(language="javascript", image="node-image:test").run_exploit(
        clone, exploit, ENTRY, timeout=30.0,
    )
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_NO_EFFECT


def test_fake_runner_wrong_key_is_not_proven(fake_docker, tmp_path):
    def play(state):
        _write_events(state, _read_event(state), key=b"b" * 32)
        _write_witness(state)

    fake_docker(play=play)
    clone, exploit = _stage_read(tmp_path)
    j = SandboxRunner(language="javascript", image="node-image:test").run_exploit(
        clone, exploit, ENTRY, timeout=30.0,
    )
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_FORGED_EVENTS


def test_fake_runner_test_frame_is_not_proven(fake_docker, tmp_path):
    def play(state):
        _write_events(state, _read_event(state, from_test=True))
        _write_witness(state)

    fake_docker(play=play)
    clone, exploit = _stage_read(tmp_path)
    j = SandboxRunner(language="javascript", image="node-image:test").run_exploit(
        clone, exploit, ENTRY, timeout=30.0,
    )
    assert shape(j) != PROVEN
    assert j.reason_code in {REASON_PROVENANCE, REASON_FRAME_NOT_ADMITTED}


def test_fake_runner_witness_mismatch_is_not_proven(fake_docker, tmp_path):
    def play(state):
        _write_events(state, _read_event(state))
        _write_witness(state, kinds=("start",))

    fake_docker(play=play)
    clone, exploit = _stage_read(tmp_path)
    j = SandboxRunner(language="javascript", image="node-image:test").run_exploit(
        clone, exploit, ENTRY, timeout=30.0,
    )
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_WITNESS_MISMATCH


def test_fake_runner_unavailable_witness_fails_closed(fake_docker, tmp_path):
    def play(state):
        _write_events(state, _read_event(state))
        _write_witness(state, unsigned=True)

    fake_docker(play=play)
    clone, exploit = _stage_read(tmp_path)
    j = SandboxRunner(language="javascript", image="node-image:test").run_exploit(
        clone, exploit, ENTRY, timeout=30.0,
    )
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_WITNESS_UNAVAILABLE


def test_app_tree_admits_javascript_by_file_path(tmp_path):
    source = tmp_path / "app.js"
    source.write_text("function handleRequest() { return 1; }\n", encoding="utf-8")
    digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
    tree = AppTree("/workspace", tmp_path, {"app.js": digest}, language="javascript")

    class Frame:
        file = "/workspace/app.js"
        qualname = "handleRequest"
        line = 99
        admitted = True
        admission = None

    assert tree.check(Frame()) is None
    py_tree = AppTree("/workspace", tmp_path, {"app.js": digest}, language="python")
    assert py_tree.check(Frame()) is not None


def _http_event(*, public_interface, admitted, from_test, function="<anonymous>"):
    from exhibit_a.oracle.oracle import OracleEvent

    app_frame = {
        "file": "/workspace/app.js", "function": function, "qualname": function,
        "line": 8, "admitted": admitted,
        **({} if admitted else {"admission": "file not in the staged app manifest"}),
    }
    test_frame = {
        "file": "/workspace/_t/test_exploit.js", "function": "listener",
        "qualname": "listener", "line": 4,
    }
    stack = [test_frame, app_frame] if from_test else [app_frame]
    if from_test and not admitted:
        stack = [test_frame]
    return OracleEvent.model_validate({
        "path": "/tmp/exhibit_a_oracle/outside/canary.txt",
        "mode": "r",
        "op": "open",
        "flags": 0,
        "access": "read",
        "requested": "/tmp/exhibit_a_oracle/allowed/../outside/canary.txt",
        "stack": stack,
        "public_interface": public_interface,
    })


def test_judge_http_public_interface_admits_anonymous_app_frames(tmp_path):
    source = tmp_path / "app.js"
    source.write_text("function createApp() { return null; }\n", encoding="utf-8")
    digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
    tree = AppTree("/workspace", tmp_path, {"app.js": digest}, language="javascript")
    event = _http_event(public_interface=True, admitted=True, from_test=False)
    j = _judge(
        "failed", [event], Path("/workspace"), Path("/workspace/_t/test_exploit.js"),
        {"createApp"}, effect="canary_read", app_tree=tree,
        allowed_dir="/tmp/exhibit_a_oracle/allowed",
    )
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == ""


def test_judge_http_public_interface_refuses_a_test_listener(tmp_path):
    source = tmp_path / "app.js"
    source.write_text("function createApp() { return null; }\n", encoding="utf-8")
    digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
    tree = AppTree("/workspace", tmp_path, {"app.js": digest}, language="javascript")
    event = _http_event(public_interface=True, admitted=True, from_test=True)
    j = _judge(
        "failed", [event], Path("/workspace"), Path("/workspace/_t/test_exploit.js"),
        {"createApp"}, effect="canary_read", app_tree=tree,
        allowed_dir="/tmp/exhibit_a_oracle/allowed",
    )
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_PROVENANCE


def test_judge_http_public_interface_refuses_a_server_with_no_app_frames(tmp_path):
    source = tmp_path / "app.js"
    source.write_text("function createApp() { return null; }\n", encoding="utf-8")
    digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
    tree = AppTree("/workspace", tmp_path, {"app.js": digest}, language="javascript")
    event = _http_event(public_interface=True, admitted=False, from_test=True)
    j = _judge(
        "failed", [event], Path("/workspace"), Path("/workspace/_t/test_exploit.js"),
        {"createApp"}, effect="canary_read", app_tree=tree,
        allowed_dir="/tmp/exhibit_a_oracle/allowed",
    )
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_PROVENANCE


def test_judge_refuses_a_js_frame_that_the_plugin_did_not_admit(tmp_path):
    source = tmp_path / "app.js"
    source.write_text("function handleRequest() {}\n", encoding="utf-8")
    digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
    tree = AppTree("/workspace", tmp_path, {"app.js": digest}, language="javascript")
    from exhibit_a.oracle.oracle import OracleEvent

    event = OracleEvent.model_validate({
        "path": "/tmp/exhibit_a_oracle/outside/canary.txt",
        "mode": "r",
        "op": "open",
        "flags": 0,
        "access": "read",
        "requested": "/tmp/exhibit_a_oracle/allowed/../outside/canary.txt",
        "stack": [
            {"file": "/workspace/_t/test_exploit.js", "function": "t", "qualname": "t", "line": 1},
            {"file": "/workspace/app.js", "function": "handleRequest", "qualname": "handleRequest",
             "line": 1, "admitted": False, "admission": "file content changed since staging"},
        ],
    })
    j = _judge(
        "failed", [event], Path("/workspace"), Path("/workspace/_t/test_exploit.js"), ENTRY,
        effect="canary_read", app_tree=tree,
        allowed_dir="/tmp/exhibit_a_oracle/allowed",
    )
    assert shape(j) != PROVEN
    assert j.reason_code == REASON_FRAME_NOT_ADMITTED


# --- docker sandbox ---------------------------------------------------------------------------


def sandbox_js(app_root, exploit, *, effect="canary_read", language="javascript", timeout=120.0):
    return SandboxRunner(language=language).run_exploit(
        app_root, exploit, ENTRY, timeout=timeout, effect=effect,
    )


@pytest.mark.docker
def test_vulnerable_js_read_is_proven_in_the_sandbox():
    j = sandbox_js(READ / "vulnerable", READ / "exploits" / "exploit_traversal.js")
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0
    assert any(f.function == "handleRequest" or f.qualname == "handleRequest" for e in j.events for f in e.stack)


@pytest.mark.docker
def test_fixed_js_read_is_not_proven_in_the_sandbox():
    j = sandbox_js(READ / "fixed", READ / "exploits" / "exploit_traversal.js")
    assert shape(j) != PROVEN, j.reason
    assert not j.observed_effect or not j.provenance_ok or j.test_outcome != "failed"


@pytest.mark.docker
def test_incomplete_js_read_fix_is_still_proven_in_the_sandbox():
    j = sandbox_js(READ / "fixed_incomplete", READ / "exploits" / "exploit_traversal.js")
    assert shape(j) == PROVEN, j.reason


@pytest.mark.docker
def test_benign_js_read_is_not_proven_in_the_sandbox():
    j = sandbox_js(READ / "vulnerable", READ / "exploits" / "exploit_benign.js")
    assert shape(j) != PROVEN
    assert j.test_outcome == "passed"
    assert j.reason_code == REASON_NO_EFFECT


@pytest.mark.docker
def test_js_test_reading_the_canary_itself_is_refused_in_the_sandbox():
    j = sandbox_js(READ / "vulnerable", READ / "exploits" / "exploit_reads_itself.js")
    assert shape(j) != PROVEN
    assert j.observed_effect
    assert not j.provenance_ok
    assert j.reason_code in {REASON_PROVENANCE, REASON_FRAME_NOT_ADMITTED}


@pytest.mark.docker
def test_vulnerable_ts_read_is_proven_in_the_sandbox():
    j = sandbox_js(
        READ / "vulnerable_ts", READ / "exploits" / "exploit_traversal.ts",
        language="typescript",
    )
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == ""


@pytest.mark.docker
def test_fixed_ts_read_is_not_proven_in_the_sandbox():
    j = sandbox_js(
        READ / "fixed_ts", READ / "exploits" / "exploit_traversal.ts",
        language="typescript",
    )
    assert shape(j) != PROVEN, j.reason


@pytest.mark.docker
def test_vulnerable_js_exec_is_proven_in_the_sandbox():
    j = sandbox_js(
        EXEC / "vulnerable", EXEC / "exploits" / "exploit_injection.js",
        effect="canary_exec",
    )
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == ""
    assert any(e.names_canary and e.sink_named for e in j.events)


@pytest.mark.docker
def test_fixed_js_exec_is_not_proven_in_the_sandbox():
    j = sandbox_js(
        EXEC / "fixed", EXEC / "exploits" / "exploit_injection.js",
        effect="canary_exec",
    )
    assert shape(j) != PROVEN, j.reason


@pytest.mark.docker
def test_incomplete_js_exec_fix_is_still_proven_in_the_sandbox():
    j = sandbox_js(
        EXEC / "fixed_incomplete", EXEC / "exploits" / "exploit_incomplete.js",
        effect="canary_exec",
    )
    assert shape(j) == PROVEN, j.reason


@pytest.mark.docker
def test_benign_js_exec_is_not_proven_in_the_sandbox():
    j = sandbox_js(
        EXEC / "vulnerable", EXEC / "exploits" / "exploit_benign.js",
        effect="canary_exec",
    )
    assert shape(j) != PROVEN


@pytest.mark.docker
def test_js_exec_from_the_test_is_refused_in_the_sandbox():
    j = sandbox_js(
        EXEC / "vulnerable", EXEC / "exploits" / "exploit_from_test.js",
        effect="canary_exec",
    )
    assert shape(j) != PROVEN
    assert j.reason_code in {REASON_PROVENANCE, "process_from_test", REASON_FRAME_NOT_ADMITTED}


@pytest.mark.docker
def test_vulnerable_ts_exec_is_proven_in_the_sandbox():
    j = sandbox_js(
        EXEC / "vulnerable_ts", EXEC / "exploits" / "exploit_injection.ts",
        effect="canary_exec", language="typescript",
    )
    assert shape(j) == PROVEN, j.reason


@pytest.mark.docker
def test_fixed_ts_exec_is_not_proven_in_the_sandbox():
    j = sandbox_js(
        EXEC / "fixed_ts", EXEC / "exploits" / "exploit_injection.ts",
        effect="canary_exec", language="typescript",
    )
    assert shape(j) != PROVEN, j.reason


@pytest.mark.docker
def test_http_anonymous_handler_is_proven_in_the_sandbox():
    j = sandbox_js(
        HTTP / "vulnerable", HTTP / "exploits" / "exploit_http_traversal.js",
    )
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == ""
    assert any(e.public_interface for e in j.events)


@pytest.mark.docker
def test_http_direct_call_from_the_test_is_refused_in_the_sandbox():
    j = sandbox_js(
        HTTP / "vulnerable", HTTP / "exploits" / "exploit_direct_from_test.js",
    )
    assert shape(j) != PROVEN
    assert j.observed_effect
    assert not j.provenance_ok
    assert j.reason_code == REASON_PROVENANCE
    assert not any(e.public_interface for e in j.events)


@pytest.mark.docker
def test_http_test_created_server_is_refused_in_the_sandbox():
    j = sandbox_js(
        HTTP / "vulnerable", HTTP / "exploits" / "exploit_test_server.js",
    )
    assert shape(j) != PROVEN
    assert j.observed_effect
    assert not j.provenance_ok
    assert j.reason_code == REASON_PROVENANCE

