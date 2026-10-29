"""sandbox.run and SandboxRunner.run_exploit driven by a fake ``docker`` callable (no Docker).

Lesson from an earlier bug: a variable named ``key`` was shadowed by the loop over ``env`` in
sandbox/runner.py, and only real Docker showed it. Here the subprocess module seen by
sandbox/runner.py is replaced by a fake whose ``run`` plays ``docker`` *and* the in-container
oracle plugin: it reads the key and manifest from stdin, as the plugin does, and signs events
with that key. If the runner verified with any other key, the genuine event would be dropped.
"""

import json
import os
import shutil
import subprocess
import types
from pathlib import Path

import pytest

import exhibit_a.sandbox.runner as runner_mod
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.oracle.plugin import code_keys, parse_channel, sign_event
from exhibit_a.oracle.provenance import app_manifest, staging_exclude
from exhibit_a.sandbox import run

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"
ENTRY = "App.handle_request"


class FakeDocker:
    """``subprocess.run`` for sandbox/runner.py: records calls and plays docker + the plugin."""

    def __init__(self, play=None, exit_code=1):
        self.calls = []
        self.play = play
        self.exit_code = exit_code

    def __call__(self, cmd, *args, **kwargs):
        self.calls.append({"cmd": list(cmd), "kwargs": kwargs})
        if cmd[:2] != ["docker", "run"]:
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        mounts = {}
        env = {}
        for flag, value in zip(cmd, cmd[1:]):
            if flag == "-v":
                host, container = value.split(":")[:2]
                mounts[container] = host
            elif flag == "-e":
                name, _, val = value.partition("=")
                env[name] = val
        key, app = parse_channel(kwargs.get("input") or b"")
        self.last = {"key": key, "app": app, "mounts": mounts, "env": env}
        if self.play is not None:
            self.play(self.last)
        return subprocess.CompletedProcess(cmd, self.exit_code, b"", b"")

    @property
    def runs(self):
        return [c for c in self.calls if c["cmd"][:2] == ["docker", "run"]]


@pytest.fixture
def docker(monkeypatch, tmp_path):
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


def _write_events(state, *bodies, key=None, seq0=0):
    with open(state["mounts"]["/oracle/events.jsonl"], "a", encoding="utf-8") as fh:
        for i, body in enumerate(bodies):
            fh.write(json.dumps(sign_event(key or state["key"], seq0 + i, body)) + "\n")


def _repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "app.py").write_text("def f():\n    return 1\n")
    (repo / "tests" / "test_x.py").write_text("def test_x():\n    pass\n")
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    return repo, canary


BODY = {"path": "/oracle/canary", "mode": "r", "stack": [], "via_symlink": False}


def test_key_goes_on_stdin_as_bytes_and_survives_colliding_env_names(docker, tmp_path):
    fake = docker(play=lambda state: _write_events(state, BODY))
    repo, canary = _repo(tmp_path)
    user_env = {
        "EXHIBIT_A_EVENTS": "/evil/events.jsonl",  # internal names: the runner's values must win
        "EXHIBIT_A_CANARY": "/evil/canary",
        "EXHIBIT_A_key": "user-key-value",          # a variable literally named key, in the namespace
        "EXHIBIT_A_KEY": "user-KEY-value",
        "EXHIBIT_A_CANARY_TOKEN": "TOKEN",
    }
    r = run(str(repo), "tests/test_x.py", timeout=60, image="fake", canary_path=str(canary),
            events_path=str(tmp_path / "events.jsonl"), env=user_env)

    (call,) = fake.runs
    stdin = call["kwargs"]["input"]
    assert isinstance(stdin, bytes)
    key, app = parse_channel(stdin)
    assert isinstance(key, bytes) and len(key) == 32
    assert app["root"] == "/workspace" and "app.py" in app["files"]
    assert "tests/test_x.py" not in app["files"]  # the test's directory is not app code
    # Never in argv, never in an env handed to the child, never in our own environment.
    argv = " ".join(call["cmd"])
    for needle in (key.hex(), key.hex().upper(), repr(key)[2:-1], "EXHIBIT-A-KEY"):
        assert needle not in argv
        assert all(needle not in v for v in os.environ.values())
    assert "env" not in call["kwargs"] or all(key.hex() not in v for v in call["kwargs"]["env"].values())
    # Internal names win; the user's same-named values are not passed at all.
    env = fake.last["env"]
    assert env["EXHIBIT_A_EVENTS"] == "/oracle/events.jsonl"
    assert env["EXHIBIT_A_CANARY"] == "/oracle/canary"
    assert "/evil/events.jsonl" not in argv and "/evil/canary" not in argv
    assert env["EXHIBIT_A_key"] == "user-key-value" and env["EXHIBIT_A_KEY"] == "user-KEY-value"
    # The event signed with the stdin key verifies: the runner checked with that same key.
    assert r["oracle_events"] == [BODY] and r["oracle_forged_events"] == 0
    assert r["app_tree_changes"] == []


def test_a_bare_variable_named_key_is_rejected_before_docker_runs(docker, tmp_path):
    fake = docker()
    repo, canary = _repo(tmp_path)
    r = run(str(repo), "tests/test_x.py", timeout=60, image="fake", canary_path=str(canary), env={"key": "x"})
    assert r["outcome"] == "env_failure" and "EXHIBIT_A_" in r["stderr"]
    assert fake.runs == []


def test_lines_signed_with_another_key_are_counted_as_forged(docker, tmp_path):
    def play(state):
        _write_events(state, BODY)
        _write_events(state, BODY, key=b"x" * 32, seq0=1)

    docker(play=play)
    repo, canary = _repo(tmp_path)
    r = run(str(repo), "tests/test_x.py", timeout=60, image="fake", canary_path=str(canary))
    assert r["oracle_events"] == [BODY]
    assert r["oracle_forged_events"] == 1 and r["oracle_forged_reason"] == "bad signature"


def test_changes_to_the_workspace_are_reported(docker, tmp_path):
    def play(state):
        workspace = Path(state["mounts"]["/workspace"])
        (workspace / "evil.py").write_text("x = 1\n")
        (workspace / "app.py").write_text("changed\n")
        (workspace / "tests" / "scratch.txt").write_text("the test's own dir is not app code\n")

    docker(play=play)
    repo, canary = _repo(tmp_path)
    r = run(str(repo), "tests/test_x.py", timeout=60, image="fake", canary_path=str(canary))
    assert r["app_tree_changes"] == ["modified: app.py", "added: evil.py"]


def test_a_workspace_that_does_not_match_the_callers_manifest_is_an_env_failure(docker, tmp_path):
    fake = docker()
    repo, canary = _repo(tmp_path)
    manifest = app_manifest(repo, staging_exclude("tests/test_x.py"))
    manifest["app.py"] = "0" * 64
    r = run(str(repo), "tests/test_x.py", timeout=60, image="fake", canary_path=str(canary), manifest=manifest)
    assert r["outcome"] == "env_failure" and "manifest" in r["stderr"]
    assert fake.runs == []


def test_no_manifest_is_sent_when_the_oracle_is_not_loaded(docker, tmp_path):
    fake = docker(exit_code=0)
    repo, _ = _repo(tmp_path)
    r = run(str(repo), "tests/test_x.py", timeout=60, image="fake")
    assert r["outcome"] == "passed"
    assert fake.runs[0]["kwargs"]["input"] == b""


# --- SandboxRunner.run_exploit end to end through the fake -----------------------------------

TRAVERSAL = '''\
import os
from app import create_app


def test_download_must_not_escape_base_dir():
    app = create_app(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    reply = app.handle_request("GET", "/download", {"name": "../outside/canary.txt"})
    assert os.environ["EXHIBIT_A_CANARY_TOKEN"] not in reply.body
'''


def _clone(tmp_path):
    clone = tmp_path / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    exploit = tmp_path / "exploits" / "test_exploit.py"
    exploit.parent.mkdir()
    exploit.write_text(TRAVERSAL)
    return clone, exploit


def _genuine(state, line_of=None):
    """The event the real plugin writes for the traversal: test -> entry point -> view -> sink."""
    lines = dict(code_keys((FIXTURES / "vulnerable" / "app.py").read_bytes()))
    lines.update(line_of or {})
    oracle_dir = next(p for p in Path(state["mounts"]["/workspace"]).iterdir() if p.name.startswith("_exhibit_a_oracle_"))
    test_dir = f"/workspace/{oracle_dir.name}"

    def app_frame(function, qualname):
        return {"file": "/workspace/app.py", "function": function, "qualname": qualname,
                "line": lines[qualname], "admitted": True}

    return {
        "path": "/tmp/exhibit_a_oracle/outside/canary.txt", "mode": "r", "via_symlink": False,
        # Recorded since A-11 F2/F4: the open's flags and access, and the path as requested.
        "flags": 0, "access": "read", "requested": "/tmp/exhibit_a_oracle/allowed/../outside/canary.txt",
        "stack": [
            {"file": f"{test_dir}/test_exploit.py", "function": "test_download_must_not_escape_base_dir",
             "qualname": "test_download_must_not_escape_base_dir", "line": 5},
            app_frame("handle_request", "App.handle_request"),
            app_frame("download", "create_app.<locals>.download"),
            app_frame("read_file", "read_file"),
        ],
    }


def test_run_exploit_proves_a_genuine_signed_admitted_event(docker, tmp_path):
    fake = docker(play=lambda state: _write_events(state, _genuine(state)))
    clone, exploit = _clone(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0)
    assert j.test_outcome == "failed" and j.observed_effect and j.provenance_ok, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []
    # The manifest the plugin got describes the staged app without the oracle directory.
    app = fake.last["app"]
    assert "app.py" in app["files"] and not any(k.startswith("_exhibit_a_oracle_") for k in app["files"])


def test_run_exploit_counts_forged_lines_into_the_judgement(docker, tmp_path):
    def play(state):
        _write_events(state, _genuine(state))
        _write_events(state, _genuine(state), key=b"x" * 32, seq0=1)

    docker(play=play)
    clone, exploit = _clone(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0)
    assert not j.provenance_ok and j.forged_events == 1 and j.reason_code == "forged_events"
    assert "bad signature" in j.reason


def test_run_exploit_surfaces_app_tree_tamper(docker, tmp_path):
    def play(state):
        (Path(state["mounts"]["/workspace"]) / "shim.py").write_text("x = 1\n")
        _write_events(state, _genuine(state))

    docker(play=play)
    clone, exploit = _clone(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0)
    assert not j.provenance_ok and j.reason_code == "app_tree_changed"
    assert j.app_tree_changes == ["added: shim.py"]


def test_run_exploit_tamper_on_a_passing_run_is_an_error(docker, tmp_path):
    docker(play=lambda state: (Path(state["mounts"]["/workspace"]) / "shim.py").write_text(""), exit_code=0)
    clone, exploit = _clone(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0)
    assert j.test_outcome == "error" and j.reason_code == "app_tree_changed"


def test_run_exploit_rechecks_admitted_frames_against_the_host_stage(docker, tmp_path):
    # The in-container plugin claims admission for a frame the staged source does not have
    # at that line (a fooled plugin, or a test that stole the key): the host says no.
    docker(play=lambda state: _write_events(state, _genuine(state, {"App.handle_request": 1})))
    clone, exploit = _clone(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0)
    # The entry frame drops out, so the outermost admitted app frame is the view: no proof.
    assert not j.provenance_ok
    assert "'create_app.<locals>.download', which is not a declared entry point" in j.reason


def test_run_exploit_runs_the_guard_before_staging(docker, tmp_path):
    fake = docker()
    clone, exploit = _clone(tmp_path)
    exploit.write_text("import app\nexec(compile('x = 1', app.__file__, 'exec'))\ndef test_x():\n    assert False\n")
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0)
    assert j.test_outcome == "error" and j.reason_code == "channel_tripwire"
    assert fake.runs == []


# --- write effect (T076): tmpfs outside/, no canary file, post-run dump ---------------------------

WORK = "/tmp/exhibit_a_oracle"
WRITE_MOUNT = f"{WORK}/outside/canary.txt"
OUTSIDE = "/oracle/outside.json"


def _write_outside(state, written=True, listing=None, raw=None):
    body = raw if raw is not None else json.dumps({
        "canary_written": written,
        "listing": [{"path": "outside/canary.txt", "kind": "file", "size": 40}] if listing is None else listing,
    })
    Path(state["mounts"][OUTSIDE]).write_text(body, encoding="utf-8")


def _write_run(tmp_path, **overrides):
    repo = tmp_path / "repo"
    if not repo.exists():
        _repo(tmp_path)
    kwargs = dict(timeout=60, image="fake", canary_mount=WRITE_MOUNT, effect="canary_write",
                  env={"EXHIBIT_A_CANARY_TOKEN": "TOKEN"})
    kwargs.update(overrides)
    return run(str(repo), "tests/test_x.py", **kwargs)


def test_write_effect_mounts_no_canary_and_gives_outside_a_size_capped_tmpfs(docker, tmp_path):
    fake = docker(play=_write_outside)
    r = _write_run(tmp_path)
    (call,) = fake.runs
    cmd = call["cmd"]
    assert cmd[cmd.index("--tmpfs", cmd.index(f"{WORK}:rw,size=16m,mode=1777") - 1) + 1] == f"{WORK}:rw,size=16m,mode=1777"
    # No canary file, and no host directory, is mounted: only workspace, plugin, events, result file.
    assert set(fake.last["mounts"]) == {"/workspace", f"/opt/exhibit_a_plugin/exhibit_a_oracle_plugin.py",
                                        "/oracle/events.jsonl", OUTSIDE}
    assert WRITE_MOUNT not in fake.last["mounts"] and "/oracle/canary" not in fake.last["mounts"]
    assert fake.last["env"]["EXHIBIT_A_CANARY"] == WRITE_MOUNT
    # pytest's exit status survives the dump that follows it.
    i = cmd.index("bash")
    assert cmd[i + 1] == "-c"
    script = cmd[i + 2]
    assert script.startswith('pytest "${@:4}"') and "; rc=$?; python -I -S -c " in script and script.endswith("; exit $rc")
    # Paths and the dump program reach the shell as arguments, not as part of its text.
    assert "/workspace/tests/test_x.py" not in script and WRITE_MOUNT not in script
    assert cmd[-1] == "/workspace/tests/test_x.py" and WRITE_MOUNT in cmd
    assert r["canary_written"] is True
    assert r["outside_listing"] == [{"path": "outside/canary.txt", "kind": "file", "size": 40}]


def test_swap_cannot_extend_the_memory_limit(docker, tmp_path):
    """--memory alone lets the container use memory+swap (2x) on hosts with swap (CI runners)."""
    fake = docker(exit_code=0)
    repo, canary = _repo(tmp_path)
    run(str(repo), "tests/test_x.py", timeout=60, image="fake", canary_path=str(canary))
    cmd = fake.runs[0]["cmd"]
    assert cmd[cmd.index("--memory") + 1] == "512m"
    assert cmd[cmd.index("--memory-swap") + 1] == cmd[cmd.index("--memory") + 1]


def test_the_read_effect_command_and_result_are_unchanged(docker, tmp_path):
    fake = docker(exit_code=0)
    repo, canary = _repo(tmp_path)
    r = run(str(repo), "tests/test_x.py", timeout=60, image="fake", canary_path=str(canary))
    cmd = fake.runs[0]["cmd"]
    assert cmd[cmd.index("pytest"):] == ["pytest", "-q", "-p", "no:cacheprovider", "-p", "exhibit_a_oracle_plugin",
                                         "/workspace/tests/test_x.py"]
    assert "bash" not in cmd
    assert "canary_written" not in r and "outside_listing" not in r
    assert OUTSIDE not in fake.last["mounts"]


@pytest.mark.parametrize("raw", [
    "", "not json", "[]", '{"canary_written": "true"}', '{"canary_written": 1}', '{"canary_written": null}',
    '{"listing": []}', json.dumps({"canary_written": False}), "x" * (2 << 20),
])
def test_an_untrusted_result_file_never_confirms_a_write(docker, tmp_path, raw):
    docker(play=lambda state: _write_outside(state, raw=raw))
    r = _write_run(tmp_path)
    assert r["canary_written"] is False


def test_a_dump_that_never_ran_leaves_the_write_unconfirmed(docker, tmp_path):
    docker()  # nothing writes the result file: a timeout or a killed container
    r = _write_run(tmp_path)
    assert r["canary_written"] is False and r["outside_listing"] == []


def test_a_malformed_listing_is_cleaned_not_trusted(docker, tmp_path):
    listing = [{"path": "outside/a", "kind": "file", "size": 1}, {"path": 3}, "x",
               {"path": "b", "kind": "file", "size": True}, {"path": "c" * 900, "kind": "dir", "size": 0}]
    docker(play=lambda state: _write_outside(state, listing=listing))
    r = _write_run(tmp_path)
    assert [e["path"][:3] for e in r["outside_listing"]] == ["out", "ccc"]
    assert len(r["outside_listing"][1]["path"]) == 300


def test_a_write_effect_refuses_a_canary_file_and_the_default_mount(docker, tmp_path):
    fake = docker()
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    r = _write_run(tmp_path, canary_path=str(canary))
    assert r["outcome"] == "env_failure" and "canary_path must be None" in r["stderr"]
    r = _write_run(tmp_path, canary_mount="/oracle/canary")
    assert r["outcome"] == "env_failure" and "canary_mount" in r["stderr"]
    r = _write_run(tmp_path, effect="canary_delete")
    assert r["outcome"] == "env_failure" and "unknown oracle effect" in r["stderr"]
    assert fake.runs == []


# SandboxRunner.run_exploit(effect="canary_write") end to end through the fake.

def _write_event(state):
    """The event the plugin writes when the app creates the canary: flags O_WRONLY|O_CREAT|O_TRUNC."""
    event = _genuine(state)
    event.update(mode="w", flags=577, access="write",
                 requested="/tmp/exhibit_a_oracle/allowed/../outside/canary.txt")
    return event


def _write_exploit(tmp_path):
    clone, exploit = _clone(tmp_path)
    return clone, exploit


def test_run_exploit_write_effect_proves_when_the_dump_confirms_the_file(docker, tmp_path):
    def play(state):
        _write_events(state, _write_event(state))
        _write_outside(state, written=True)

    fake = docker(play=play)
    clone, exploit = _write_exploit(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0, effect="canary_write")
    assert j.test_outcome == "failed" and j.observed_effect and j.provenance_ok, j.reason
    assert "written" in j.reason and j.app_tree_changes == []
    assert WRITE_MOUNT not in fake.last["mounts"]  # no canary file was mounted
    assert fake.last["env"]["EXHIBIT_A_ALLOWED_DIR"] == f"{WORK}/allowed"


def test_run_exploit_write_effect_without_a_confirmed_file_proves_nothing(docker, tmp_path):
    # An open for writing is on record, but the dump finds no file with the token (or never ran).
    docker(play=lambda state: _write_events(state, _write_event(state)))
    clone, exploit = _write_exploit(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0, effect="canary_write")
    assert not j.observed_effect and not j.provenance_ok and j.reason_code == "no_effect"
    assert "no file holding the run's token" in j.reason


def test_run_exploit_write_effect_ignores_a_read_of_the_canary(docker, tmp_path):
    def play(state):
        _write_events(state, _genuine(state))  # a read event
        _write_outside(state, written=True)

    docker(play=play)
    clone, exploit = _write_exploit(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0, effect="canary_write")
    assert not j.observed_effect and j.reason_code == "no_effect"


def test_app_tree_check_ignores_writes_outside_the_app_tree_but_not_inside_it(docker, tmp_path):
    def outside_only(state):
        _write_events(state, _write_event(state))
        _write_outside(state, written=True)  # the app wrote into the tmpfs, not into /workspace

    docker(play=outside_only)
    clone, exploit = _write_exploit(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0, effect="canary_write")
    assert j.provenance_ok and j.app_tree_changes == []

    def inside(state):
        (Path(state["mounts"]["/workspace"]) / "shim.py").write_text("x = 1\n")
        outside_only(state)

    docker(play=inside)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0, effect="canary_write")
    assert not j.provenance_ok and j.reason_code == "app_tree_changed"
    assert j.app_tree_changes == ["added: shim.py"]


def test_run_exploit_defaults_to_the_read_effect(docker, tmp_path):
    fake = docker(play=lambda state: _write_events(state, _genuine(state)))
    clone, exploit = _clone(tmp_path)
    j = SandboxRunner(image="fake").run_exploit(clone, exploit, {ENTRY}, timeout=30.0)
    assert j.provenance_ok and "/oracle/canary" not in fake.last["mounts"]
    assert WRITE_MOUNT in fake.last["mounts"]  # the read effect still mounts the real canary file
    assert OUTSIDE not in fake.last["mounts"]
