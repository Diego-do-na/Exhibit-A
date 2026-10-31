"""The canary_exec effect: command execution proven on the host path and in the Docker sandbox.

A vulnerable app reached through its entry point is proven; a fixed one is not; every cheat is
refused, with the static guard on and, because it is only a tripwire, with it off. Design and
limits: docs/oracle/oracle-provenance.md, section 3.9.
"""

import json
import os
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

from exhibit_a.cli import main
from exhibit_a.cli.parser import build_parser
from exhibit_a.graph.catalog import match_sink
from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop, prompts
from exhibit_a.loop.runner import SandboxRunner
from exhibit_a.models import Completion, ModelRole, ReplayProvider, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import run_oracle
from exhibit_a.oracle.guard import exec_problem
from exhibit_a.oracle.oracle import _judge, exec_canary_script, marker_holds_token
from exhibit_a.oracle.plugin import names_canary
from exhibit_a.oracle.provenance import AppTree
from exhibit_a.schemas import EventType

ENTRY_POINTS = {"App.handle_request"}
PROVEN = ("failed", True, True)

SHELL_APP = '''\
import subprocess


def list_dir(base, name):
    command = f"ls {base}/{name}"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


class App:
    def __init__(self, base):
        self.base = base

    def handle_request(self, name):
        return list_dir(self.base, name)
'''

ARGV_APP = '''\
import os
import subprocess


class App:
    def __init__(self, base):
        self.base = base

    def handle_request(self, name):
        argv = ["ls", os.path.join(self.base, name)]
        return subprocess.run(argv, capture_output=True, text=True).stdout
'''

# Safe, and its command line names whatever it is given: everything a proof looks at holds
# except who ran the canary. Every cheat below runs against this one.
QUOTED_APP = '''\
import shlex
import subprocess


class App:
    def __init__(self, base):
        self.base = base

    def handle_request(self, name):
        command = "ls " + shlex.quote(name)
        return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
'''

PICKLE_APP = '''\
import pickle


class App:
    def __init__(self, base):
        self.base = base

    def handle_request(self, blob):
        return pickle.loads(blob)
'''

JSON_APP = '''\
import json


class App:
    def __init__(self, base):
        self.base = base

    def handle_request(self, blob):
        return json.loads(blob)
'''

SYSTEM_APP = '''\
import os


class App:
    def __init__(self, base):
        self.base = base

    def handle_request(self, name):
        return os.system("echo " + name + " > /dev/null")
'''

EVAL_APP = '''\
class App:
    def __init__(self, base):
        self.base = base

    def handle_request(self, expression):
        return eval(expression)
'''

FORK_APP = '''\
import os


class App:
    def __init__(self, base):
        self.base = base

    def handle_request(self, path):
        pid = os.fork()
        if pid == 0:
            os.execv(path, [path])
        os.waitpid(pid, 0)
'''

ASYNC_APP = '''\
import asyncio


class App:
    def __init__(self, base):
        self.base = base

    async def _run(self, name):
        process = await asyncio.create_subprocess_shell("echo " + name + " > /dev/null")
        await process.wait()

    def handle_request(self, name):
        asyncio.run(asyncio.wait_for(self._run(name), 10))
'''

# Duck-typed input: the safe app calls a method of what it is given.
STREAM_APP = '''\
class App:
    def __init__(self, base):
        self.base = base

    def handle_request(self, stream):
        return stream.read()
'''

PRELUDE = '''\
import os
from app import App
ALLOWED = os.environ["EXHIBIT_A_ALLOWED_DIR"]
CANARY = os.path.join(os.path.dirname(ALLOWED), "outside", "canary")
MARKER = os.path.join(os.path.dirname(ALLOWED), "outside", "canary_ran")
TOKEN = os.environ["EXHIBIT_A_CANARY_TOKEN"]
'''

SHELL_EXPLOIT = PRELUDE + '''
def test_exploit():
    App(ALLOWED).handle_request("x; " + CANARY)
    assert not os.path.exists(MARKER)
'''

RELATIVE_EXPLOIT = PRELUDE + '''
def test_exploit():
    App(ALLOWED).handle_request(f"x; cd {ALLOWED} && ../outside/canary")
    assert not os.path.exists(MARKER)
'''

PICKLE_EXPLOIT = PRELUDE + '''
import pickle

class Payload:
    def __reduce__(self):
        return (os.system, (CANARY,))

def test_exploit():
    App(ALLOWED).handle_request(pickle.dumps(Payload()))
    assert not os.path.exists(MARKER)
'''

PICKLE_SUBPROCESS_EXPLOIT = PRELUDE + '''
import pickle
import subprocess

class Payload:
    def __reduce__(self):
        return (subprocess.run, ([CANARY],))

def test_exploit():
    App(ALLOWED).handle_request(pickle.dumps(Payload()))
    assert not os.path.exists(MARKER)
'''

EVAL_EXPLOIT = PRELUDE + '''
def test_exploit():
    App(ALLOWED).handle_request("__import__('os').system(" + repr(CANARY) + ")")
    assert not os.path.exists(MARKER)
'''

FORK_EXPLOIT = PRELUDE + '''
def test_exploit():
    App(ALLOWED).handle_request(CANARY)
    assert not os.path.exists(MARKER)
'''

# Each cheat calls the safe app with the canary's path, so its command line names it, and fails on
# the marker. What differs is how the canary really ran, or how the marker got there.
CALL_APP = "    App(ALLOWED).handle_request(CANARY)\n    assert not os.path.exists(MARKER)\n"


def cheat(body, header=""):
    return PRELUDE + header + "\ndef test_exploit():\n" + textwrap.indent(textwrap.dedent(body), "    ") + CALL_APP


CHEATS = {
    "test_runs_the_canary": cheat("subprocess.run([CANARY])\n", "import subprocess\n"),
    "test_writes_the_marker": cheat("with open(MARKER, 'w') as fh:\n    fh.write(TOKEN + '\\n')\n"),
    "test_writes_the_marker_with_os_open": cheat(
        "fd = os.open(MARKER, os.O_WRONLY | os.O_CREAT)\nos.write(fd, (TOKEN + '\\n').encode())\nos.close(fd)\n"),
    "test_renames_a_file_onto_the_marker": cheat(
        "tmp = os.path.join(ALLOWED, 'tmp')\n"
        "with open(tmp, 'w') as fh:\n    fh.write(TOKEN + '\\n')\n"
        "os.replace(tmp, MARKER)\n"),
    "test_overwrites_the_canary": cheat(
        "os.chmod(CANARY, 0o755)\nwith open(CANARY, 'a') as fh:\n    fh.write('')\n"),
    "monkeypatched_subprocess": cheat(
        "real = subprocess.run\n"
        "subprocess.run = lambda command, **kw: real(command.replace('ls ', ''), **kw)\n",
        "import subprocess\n"),
    "monkeypatched_quote": cheat("shlex.quote = str\n", "import shlex\n").replace(
        "handle_request(CANARY)", "handle_request('x; ' + CANARY)"),
    "monkeypatched_with_eval": cheat(
        "subprocess.run = eval('lambda command, **kw: __import__(\"os\").system(' + repr(CANARY) + ')')\n",
        "import subprocess\n"),
    "canary_from_a_test_thread": cheat(
        "t = threading.Thread(target=subprocess.run, args=([CANARY],))\nt.start()\nt.join()\n",
        "import subprocess\nimport threading\n"),
    "canary_from_a_timer": cheat(
        "t = threading.Timer(0, os.system, args=(CANARY,))\nt.start()\nt.join()\n", "import threading\n"),
    "canary_from_a_pool": cheat(
        "with ThreadPoolExecutor() as pool:\n    pool.submit(os.system, CANARY).result()\n",
        "from concurrent.futures import ThreadPoolExecutor\n"),
    "fork_and_exec_in_the_test": cheat(
        "pid = os.fork()\nif pid == 0:\n    os.execv(CANARY, [CANARY])\nos.waitpid(pid, 0)\n"),
    "posix_spawn_in_the_test": cheat("pid = os.posix_spawn(CANARY, [CANARY], {})\nos.waitpid(pid, 0)\n"),
    "spawnv_in_the_test": cheat("os.spawnv(os.P_WAIT, CANARY, [CANARY])\n"),
    "popen_in_the_test": cheat("os.popen(CANARY).read()\n"),
    "computed_names": cheat("getattr(__import__('o' + 's'), 'sys' + 'tem')(CANARY)\n"),
    "raw_fork_exec": cheat(
        "import _posixsubprocess as raw\n"
        "pid = raw.fork_exec([CANARY.encode()], [CANARY.encode()], True, (), None, None, -1, -1, -1, -1, -1, -1,"
        " *os.pipe(), False, False, 0, None, None, None, -1, None, False)\n"
        "os.waitpid(pid, 0)\n"),
    "ctypes_system": cheat(
        "ct = __import__('c' + 'types')\nct.CDLL(None).system(CANARY.encode())\n"),
    "path_shim": cheat(
        "shim = os.path.join(ALLOWED, 'ls')\n"
        "with open(shim, 'w') as fh:\n    fh.write('#!/bin/sh\\nexec \"$1\"\\n')\n"
        "os.chmod(shim, 0o755)\n"
        "os.environ['PATH'] = ALLOWED + ':' + os.environ['PATH']\n"),
    "path_shim_behind_putenv": cheat(
        "shim = os.path.join(ALLOWED, 'ls')\n"
        "with open(shim, 'w') as fh:\n    fh.write('#!/bin/sh\\nexec \"$1\"\\n')\n"
        "os.chmod(shim, 0o755)\n"
        "os.putenv('PA' + 'TH', ALLOWED)\n"),
    "at_exit": cheat("atexit.register(os.system, CANARY)\n", "import atexit\n").replace(
        "assert not os.path.exists(MARKER)", "assert False"),
    "swap_the_outside_directory": cheat(
        "work = os.path.dirname(ALLOWED)\n"
        "fake = os.path.join(ALLOWED, 'fake')\n"
        "os.mkdir(fake)\n"
        "with open(CANARY) as fh:\n    script = fh.read()\n"
        "with open(os.path.join(fake, 'canary'), 'w') as fh:\n    fh.write(script)\n"
        "with open(os.path.join(fake, 'canary_ran'), 'w') as fh:\n    fh.write(TOKEN + '\\n')\n"
        "os.rename(os.path.join(work, 'outside'), os.path.join(work, 'gone'))\n"
        "os.rename(fake, os.path.join(work, 'outside'))\n").replace(
        "assert not os.path.exists(MARKER)", "assert False"),
    "finalizer_during_the_app_call": cheat(
        "class Garbage:\n    pass\n"
        "g = Garbage()\ng.me = g\n"
        "weakref.finalize(g, os.system, CANARY)\n"
        "del g\n"
        "gc.set_threshold(1)\n", "import gc\nimport weakref\n").replace(
        "assert not os.path.exists(MARKER)", "assert False"),
    "symlink_to_the_canary": cheat(
        "link = os.path.join(ALLOWED, 'run')\nos.symlink(CANARY, link)\nos.system(link)\n"),
}


@pytest.fixture
def unguarded(monkeypatch):
    """The guard is bypassable by obfuscation, so what is under it must hold alone."""
    monkeypatch.setattr("exhibit_a.oracle.oracle.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.oracle.oracle.exec_problem", lambda path: None)


def layout(tmp_path, app, exploit):
    root, tests = tmp_path / "app", tmp_path / "tests"
    root.mkdir()
    tests.mkdir()
    (root / "app.py").write_text(app, encoding="utf-8")
    (tests / "test_exploit.py").write_text(exploit, encoding="utf-8")
    return root, tests / "test_exploit.py"


def host(tmp_path, app, exploit, entry_points=ENTRY_POINTS):
    root, test = layout(tmp_path, app, exploit)
    return run_oracle(root, test, entry_points, effect="canary_exec", timeout=60.0)


def sandbox(tmp_path, app, exploit, entry_points=ENTRY_POINTS):
    root, test = layout(tmp_path, app, exploit)
    return SandboxRunner().run_exploit(root, test, entry_points, timeout=120.0, effect="canary_exec")


def shape(j):
    return j.test_outcome, j.observed_effect, j.provenance_ok


TRUE_CASES = [
    ("shell_true", SHELL_APP, SHELL_EXPLOIT),
    ("relative_path_after_cd", SHELL_APP, RELATIVE_EXPLOIT),
    ("os_system", SYSTEM_APP, SHELL_EXPLOIT),
    ("pickle_os_system", PICKLE_APP, PICKLE_EXPLOIT),
    ("pickle_subprocess", PICKLE_APP, PICKLE_SUBPROCESS_EXPLOIT),
    ("eval", EVAL_APP, EVAL_EXPLOIT),
    ("fork_then_exec", FORK_APP, FORK_EXPLOIT),
    ("asyncio_task", ASYNC_APP, SHELL_EXPLOIT),
]


# -- host path ---------------------------------------------------------------------------------


@pytest.mark.parametrize("app, exploit", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_on_the_host_path(tmp_path, app, exploit):
    j = host(tmp_path, app, exploit)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []
    assert any(e.op == "process" and e.names_canary and e.sink_named for e in j.events)


def test_the_proof_records_the_command_and_the_stack(tmp_path):
    j = host(tmp_path, SHELL_APP, SHELL_EXPLOIT)
    [event] = [e for e in j.events if e.op == "process"]
    assert event.mode == "subprocess.Popen" and "outside/canary" in event.command
    names = [f.qualname for f in event.stack]
    assert "test_exploit" in names and "App.handle_request" in names and "list_dir" in names
    assert all(f.admitted for f in event.stack if f.qualname in ("App.handle_request", "list_dir"))


@pytest.mark.parametrize("app", [ARGV_APP, QUOTED_APP], ids=["argv_list", "shlex_quote"])
def test_a_fixed_app_is_not_proven_on_the_host_path(tmp_path, app):
    j = host(tmp_path, app, SHELL_EXPLOIT)
    assert shape(j) == ("passed", False, False), j.reason
    assert j.reason_code == "no_effect"


def test_a_safe_app_is_not_proven_by_a_deserializer_that_runs_nothing(tmp_path):
    exploit = PRELUDE + '''
def test_exploit():
    try:
        App(ALLOWED).handle_request('{"cmd": "' + CANARY + '"}')
    except ValueError:
        pass
    assert not os.path.exists(MARKER)
'''
    assert shape(host(tmp_path, JSON_APP, exploit)) == ("passed", False, False)


@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_guard_on(tmp_path, name):
    j = host(tmp_path, QUOTED_APP, CHEATS[name])
    assert shape(j) != PROVEN, j.reason


@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_guard_off(tmp_path, unguarded, name):
    j = host(tmp_path, QUOTED_APP, CHEATS[name])
    assert shape(j) != PROVEN, j.reason


@pytest.mark.parametrize("name, code", [
    ("test_runs_the_canary", "process_from_test"),
    ("canary_from_a_test_thread", "process_from_test"),
    ("fork_and_exec_in_the_test", "process_from_test"),
    ("raw_fork_exec", "process_from_test"),
    ("ctypes_system", "process_from_test"),
    ("path_shim", "process_from_test"),
    ("test_writes_the_marker", "canary_tampered"),
    ("test_renames_a_file_onto_the_marker", "canary_tampered"),
    ("test_overwrites_the_canary", "canary_tampered"),
    ("monkeypatched_quote", "process_api_changed"),
])
def test_the_runtime_layer_says_why_a_cheat_is_refused(tmp_path, unguarded, name, code):
    j = host(tmp_path, QUOTED_APP, CHEATS[name])
    assert j.reason_code == code, j.reason


def test_the_test_calling_the_sink_directly_is_not_proven(tmp_path, unguarded):
    exploit = PRELUDE + '''
from app import list_dir

def test_exploit():
    list_dir(ALLOWED, "x; " + CANARY)
    assert not os.path.exists(MARKER)
'''
    j = host(tmp_path, SHELL_APP, exploit)
    assert shape(j) == ("failed", True, False), j.reason
    assert "not a declared entry point" in j.reason


def test_a_sink_called_directly_beside_a_harmless_entry_point_call_is_not_proven(tmp_path, unguarded):
    exploit = PRELUDE + '''
from app import list_dir

def test_exploit():
    App(ALLOWED).handle_request("harmless")
    list_dir(ALLOWED, "x; " + CANARY)
    assert not os.path.exists(MARKER)
'''
    assert shape(host(tmp_path, SHELL_APP, exploit)) == ("failed", True, False)


def test_a_test_callback_called_by_the_app_is_started_by_the_test(tmp_path, unguarded):
    exploit = PRELUDE + '''
class Stream:
    def read(self):
        return os.system(CANARY)

def test_exploit():
    App(ALLOWED).handle_request(Stream())
    assert not os.path.exists(MARKER)
'''
    j = host(tmp_path, STREAM_APP, exploit)
    assert j.reason_code == "process_from_test", j.reason


@pytest.mark.parametrize("callable_source", [
    "functools.partial(os.system, CANARY)",
    "eval('lambda: __import__(\"os\").system(' + repr(CANARY) + ')')",
], ids=["partial_without_a_frame", "lambda_built_by_eval"])
def test_a_callable_handed_to_a_safe_app_is_not_proven(tmp_path, unguarded, callable_source):
    exploit = PRELUDE + f'''
import functools

class Stream:
    pass

def test_exploit():
    stream = Stream()
    stream.read = {callable_source}
    App(ALLOWED).handle_request(stream)
    assert not os.path.exists(MARKER)
'''
    j = host(tmp_path, STREAM_APP, exploit)
    assert shape(j) != PROVEN, j.reason


def test_a_marker_written_by_the_injected_shell_itself_is_not_the_canary(tmp_path):
    # Real command execution, but not the effect: nothing named or ran the canary.
    exploit = PRELUDE + '''
def test_exploit():
    App(ALLOWED).handle_request(f"x; echo {TOKEN} > {MARKER}")
    assert not os.path.exists(MARKER)
'''
    j = host(tmp_path, SHELL_APP, exploit)
    assert shape(j) == ("failed", True, False) and "names the canary" in j.reason


def test_a_copy_of_the_canary_is_not_the_canary(tmp_path, unguarded):
    exploit = PRELUDE + '''
import shutil

def test_exploit():
    copy = os.path.join(ALLOWED, "canary")
    shutil.copy(CANARY, copy)
    App(ALLOWED).handle_request("x; " + copy)
    assert not os.path.exists(MARKER)
'''
    assert shape(host(tmp_path, SHELL_APP, exploit)) == ("failed", True, False)


def test_a_process_with_no_app_or_test_frame_fails_closed(tmp_path, unguarded):
    # atexit runs after the test frames are gone: a process nobody can vouch for.
    j = host(tmp_path, QUOTED_APP, CHEATS["at_exit"])
    assert shape(j) == ("failed", True, False), j.reason
    assert j.reason_code == "provenance" and "no application code" in j.reason


def test_app_tree_tampering_still_rules_out_a_proof(tmp_path, unguarded):
    exploit = SHELL_EXPLOIT.replace("def test_exploit():\n", '''def test_exploit():
    import sys
    with open(sys.modules["app"].__file__ + ".bak", "w") as fh:
        fh.write("x")
''')
    j = host(tmp_path, SHELL_APP, exploit)
    assert j.reason_code == "app_tree_changed" and shape(j) != PROVEN


def test_the_test_contract_does_not_grow(tmp_path, unguarded):
    exploit = PRELUDE + '''
def test_exploit():
    assert "EXHIBIT_A_CANARY" not in os.environ
    assert "EXHIBIT_A_CANARY_MARKER" not in os.environ
    assert "EXHIBIT_A_EVENTS" not in os.environ
'''
    # Unguarded because it names these variables, which the guard refuses in a real run.
    j = host(tmp_path, SHELL_APP, exploit)
    assert j.test_outcome == "passed", j.reason


def test_the_read_effect_records_no_process_event(tmp_path):
    exploit = '''\
import os
from app import App

def test_exploit():
    App(os.environ["EXHIBIT_A_ALLOWED_DIR"]).handle_request("x")
'''
    root, test = layout(tmp_path, SHELL_APP, exploit)
    j = run_oracle(root, test, ENTRY_POINTS)
    assert j.events == [] and j.test_outcome == "passed"


# -- what the judge refuses without a marker check ---------------------------------------------


def _event(**fields):
    from exhibit_a.oracle import OracleEvent

    base = {"path": "/w/outside/canary", "mode": "subprocess.Popen", "op": "process", "access": "exec",
            "command": "/w/outside/canary", "names_canary": True, "sink_named": True, "stack": [
                {"file": "/t/test_exploit.py", "function": "test_exploit", "qualname": "test_exploit", "line": 1},
                {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
                 "line": 5, "admitted": True},
            ]}
    return OracleEvent.model_validate({**base, **fields})


@pytest.fixture
def tree(tmp_path):
    source = "class App:\n\n\n\n    def handle_request(self):\n        pass\n"
    (tmp_path / "app.py").write_text(source)
    import hashlib

    return AppTree("/a", tmp_path, {"app.py": hashlib.sha256(source.encode()).hexdigest()})


def judge(tree, events, ran):
    return _judge("failed", events, Path("/a"), Path("/t/test_exploit.py"), ENTRY_POINTS,
                  effect="canary_exec", app_tree=tree, canary_ran=ran)


def test_the_judge_proves_only_when_everything_holds(tree):
    assert shape(judge(tree, [_event()], True)) == PROVEN


@pytest.mark.parametrize("ran", [False, None])
def test_an_unverified_or_absent_marker_is_not_a_proof(tree, ran):
    j = judge(tree, [_event()], ran)
    assert shape(j) == ("failed", False, False) and j.reason_code == "no_effect"


@pytest.mark.parametrize("fields", [
    {"names_canary": False}, {"sink_named": False},
], ids=["command_does_not_name_it", "frame_names_no_sink"])
def test_a_process_that_does_not_explain_the_canary_is_not_a_proof(tree, fields):
    assert shape(judge(tree, [_event(**fields)], True)) == ("failed", True, False)


def test_a_process_through_a_link_created_in_the_run_is_not_a_proof(tree):
    assert shape(judge(tree, [_event(via_symlink=True, symlink="/x")], True)) == ("failed", True, False)


def test_a_patched_api_is_not_a_proof(tree):
    j = judge(tree, [_event(patched="subprocess.run")], True)
    assert j.reason_code == "process_api_changed"


def test_no_process_event_at_all_is_not_a_proof(tree):
    assert shape(judge(tree, [], True)) == ("failed", True, False)


def test_without_the_staged_app_nothing_is_proven(tree):
    assert shape(judge(None, [_event()], True)) != PROVEN


def test_an_unadmitted_frame_is_not_a_proof(tree):
    stack = [{"file": "/t/test_exploit.py", "function": "t", "qualname": "t", "line": 1},
             {"file": "/a/app.py", "function": "handle_request", "qualname": "App.handle_request",
              "line": 5, "admitted": False, "admission": "code object differs"}]
    assert judge(tree, [_event(stack=stack)], True).reason_code == "frame_not_admitted"


@pytest.mark.parametrize("content, expected", [
    ("TOKEN\n", True), ("TOKEN\nTOKEN\n", True), ("", False), ("OTHER\n", False), ("TOKEN\nOTHER\n", False),
    ("TOKEN extra\n", False),
])
def test_the_marker_holds_only_the_token(tmp_path, content, expected):
    marker = tmp_path / "canary_ran"
    marker.write_text(content)
    assert marker_holds_token(marker, "TOKEN") is expected


def test_a_marker_that_is_not_a_single_regular_file_is_refused(tmp_path):
    real = tmp_path / "real"
    real.write_text("TOKEN\n")
    link = tmp_path / "link"
    link.symlink_to(real)
    assert marker_holds_token(link, "TOKEN") is False
    assert marker_holds_token(tmp_path / "absent", "TOKEN") is False
    assert marker_holds_token(tmp_path, "TOKEN") is False
    os.mkfifo(tmp_path / "fifo")
    assert marker_holds_token(tmp_path / "fifo", "TOKEN") is False
    os.link(real, tmp_path / "hard")
    assert marker_holds_token(real, "TOKEN") is False


def test_an_oversized_marker_is_refused(tmp_path):
    marker = tmp_path / "canary_ran"
    marker.write_text("TOKEN\n" * 300_000)
    assert marker_holds_token(marker, "TOKEN") is False


def test_the_canary_script_quotes_what_it_embeds_and_writes_only_the_token(tmp_path):
    marker = tmp_path / "with space" / "canary_ran"
    marker.parent.mkdir()
    script = tmp_path / "canary"
    script.write_text(exec_canary_script(marker, "CANARY-abc"))
    script.chmod(stat.S_IRWXU)
    assert os.system(str(script)) == 0 and os.system(str(script)) == 0
    assert marker.read_text() == "CANARY-abc\nCANARY-abc\n"


@pytest.mark.parametrize("parts, cwd, expected", [
    (["/w/outside/canary"], None, True),
    (["sh", "-c", "ls x; /w/outside/canary"], None, True),
    (["sh", "-c", "ls $(/w/outside/canary)"], None, True),
    (["sh", "-c", "ls `/w/outside/canary`|cat"], None, True),
    (["tar", "--checkpoint-action=exec=/w/outside/canary"], None, True),
    (["ls '/w/outside/canary'"], None, True),
    (["cd /w/allowed && ../outside/canary"], None, True),
    (["outside/canary"], "/w", True),
    (["/w/allowed/../outside/canary"], None, True),
    (["/w/outside/canary_ran"], None, False),
    (["/w/allowed/canary"], None, False),
    (["/elsewhere/canary"], None, False),
    (["canary"], "/w/allowed", False),
    (["sh -c 'c=can; /w/outside/${c}ary'"], None, False),
    ([], None, False),
])
def test_what_names_the_canary(parts, cwd, expected):
    assert names_canary(parts, cwd, "/w/outside/canary") is expected


# -- guard -------------------------------------------------------------------------------------


@pytest.mark.parametrize("line", [
    "import subprocess\nsubprocess.run(['x'])",
    "import subprocess as s\ns.Popen(['x'])",
    "from subprocess import run\nrun(['x'])",
    "from subprocess import run as r\nr(['x'])",
    "import os\nos.system('x')",
    "import os\nos.fork()",
    "import os\nos.execv('x', ['x'])",
    "import os\nos.posix_spawn('x', ['x'], {})",
    "import pty\npty.spawn('x')",
    "import asyncio\nasyncio.create_subprocess_shell('x')",
    "import multiprocessing\nmultiprocessing.Process()",
    "import functools, os\nfunctools.partial(os.system, 'x')",
    "import threading, subprocess\nthreading.Thread(target=subprocess.run)",
    "eval('1')",
    "exec('1')",
    "compile('1', 'x', 'exec')",
])
def test_the_guard_refuses_a_test_that_starts_a_process(tmp_path, line):
    test = tmp_path / "test_exploit.py"
    test.write_text(line + "\n")
    assert "starts a process itself" in exec_problem(test)


def test_the_guard_checks_a_shipped_conftest(tmp_path):
    test = tmp_path / "test_exploit.py"
    test.write_text("x = 1\n")
    (tmp_path / "conftest.py").write_text("import os\nos.system('x')\n")
    assert exec_problem(test) is not None


@pytest.mark.parametrize("line", [
    "import os, pickle\nclass P:\n    def __reduce__(self):\n        return (os.system, ('x',))\npickle.dumps(P())",
    "import subprocess\nclass P:\n    def __reduce__(self):\n        return (subprocess.run, (['x'],))",
    "import os\nos.path.join('a', 'b')\nos.environ.get('x')",
    "import re\nre.compile('x')",
])
def test_the_guard_allows_naming_a_process_api_as_data(tmp_path, line):
    test = tmp_path / "test_exploit.py"
    test.write_text(line + "\n")
    assert exec_problem(test) is None


def test_a_guard_hit_does_not_run_the_test(tmp_path):
    j = host(tmp_path, QUOTED_APP, CHEATS["test_runs_the_canary"])
    assert j.reason_code == "channel_tripwire" and j.test_outcome == "error" and j.events == []


# -- plumbing ----------------------------------------------------------------------------------


def test_cli_accepts_the_effect():
    args = build_parser().parse_args(["run", "--effect", "canary_exec", "--pr-diff", "a..b"])
    assert args.effect == "canary_exec"


def test_the_contract_names_the_canary_and_the_marker():
    text = prompts.test_contract("canary_exec", ["pkg==1"])
    assert "'outside', 'canary')" in text and "'canary_ran'" in text
    assert "EXHIBIT_A_CANARY_MARKER" not in text and "assert not os.path.exists" in text
    assert "pkg==1" in text


@pytest.mark.parametrize("name, vuln_class", [
    ("subprocess.run", "command_injection"),
    ("os.system", "command_injection"),
    ("pickle.loads", "insecure_deserialization"),
    ("yaml.load", "insecure_deserialization"),
    ("builtins.eval", "code_injection"),
])
def test_the_catalog_maps_execution_sinks_to_the_effect(name, vuln_class):
    rule = match_sink(name)
    assert (rule.vuln_class, rule.effect) == (vuln_class, "canary_exec")


def test_sinks_that_cannot_run_the_canary_stay_unprovable():
    assert match_sink("marshal.loads").effect is None
    assert match_sink("builtins.compile").effect is None


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


def _mount_source(cmd, target):
    specs = [cmd[i + 1] for i, part in enumerate(cmd) if part == "-v"]
    return next(s.split(":")[0] for s in specs if s.split(":")[1] == target)


def test_the_sandbox_keeps_its_limits_and_mounts_an_executable_read_only_canary(tmp_path, monkeypatch):
    from exhibit_a.sandbox.runner import run

    seen = {}

    def on_run(cmd):
        canary = _mount_source(cmd, "/tmp/w/outside/canary")
        seen["mode"] = os.stat(canary).st_mode
        seen["content"] = Path(canary).read_text()
        outside = _mount_source(cmd, "/tmp/w/outside")
        Path(outside, "canary_ran").write_text("TOK\n")

    calls = _fake_docker(monkeypatch, tmp_path, on_run)
    source = tmp_path / "canary_source"
    source.write_text("#!/bin/sh\n")
    clone = tmp_path / "clone"
    (clone / "tests").mkdir(parents=True)
    (clone / "tests" / "test_x.py").write_text("")
    result = run(str(clone), "tests/test_x.py", 5, image="image:test", canary_path=str(source),
                 canary_mount="/tmp/w/outside/canary", effect="canary_exec",
                 env={"EXHIBIT_A_CANARY_TOKEN": "TOK"})
    cmd = next(c for c in calls if c[:2] == ["docker", "run"])
    assert result["canary_ran"] is True
    assert stat.S_IMODE(seen["mode"]) == 0o555
    joined = " ".join(cmd)
    for flag in ("--read-only", "--network none", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--pids-limit 64", "--memory 512m", "--memory-swap 512m"):
        assert flag in joined
    assert any(part.endswith(":/tmp/w/outside/canary:ro") for part in cmd)
    assert "EXHIBIT_A_CANARY_MARKER=/tmp/w/outside/canary_ran" in cmd


@pytest.mark.parametrize("content", ["", "OTHER\n"])
def test_the_host_reads_the_marker_itself(tmp_path, monkeypatch, content):
    from exhibit_a.sandbox.runner import run

    def on_run(cmd):
        Path(_mount_source(cmd, "/tmp/w/outside"), "canary_ran").write_text(content)

    _fake_docker(monkeypatch, tmp_path, on_run)
    source = tmp_path / "canary_source"
    source.write_text("#!/bin/sh\n")
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "test_x.py").write_text("")
    result = run(str(clone), "test_x.py", 5, image="image:test", canary_path=str(source),
                 canary_mount="/tmp/w/outside/canary", effect="canary_exec",
                 env={"EXHIBIT_A_CANARY_TOKEN": "TOK"})
    assert result["canary_ran"] is False


def test_the_sandbox_refuses_an_exec_run_it_could_not_verify(tmp_path, monkeypatch):
    from exhibit_a.sandbox.runner import run

    _fake_docker(monkeypatch, tmp_path, lambda cmd: None)
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "test_x.py").write_text("")
    source = tmp_path / "s"
    source.write_text("x")
    missing_token = run(str(clone), "test_x.py", 5, image="i", canary_path=str(source),
                        canary_mount="/tmp/w/outside/canary", effect="canary_exec")
    no_canary = run(str(clone), "test_x.py", 5, image="i", canary_mount="/tmp/w/outside/canary",
                    effect="canary_exec", env={"EXHIBIT_A_CANARY_TOKEN": "T"})
    assert missing_token["outcome"] == no_canary["outcome"] == "env_failure"


class ScriptedExec:
    """A model that suspects the shell command and fixes it with an argv list."""

    name = "scripted"
    pricing = Pricing()

    def complete(self, role, prompt, schema):
        if role == Role.ADVERSARY:
            body = {"suspicions": [{
                "id": "S-EXEC", "class": "command_injection", "location": {"file": "app.py", "line": 5},
                "entry_point": "App.handle_request", "hypothesis": "name reaches a shell", "source": "name",
            }]}
        elif role == Role.TEST_WRITER:
            body = {"test_source": SHELL_EXPLOIT}
        elif role == Role.FIXER:
            body = {"files": [{"path": "app.py", "content": ARGV_APP}]}
        else:
            variant = SHELL_EXPLOIT.replace('"x; "', '"x && "')
            body = {"variants": [{"name": "and-list", "test_source": variant}]}
        return Completion(json.dumps(body), 10, 10, 1, model="scripted")


class HostRunner:
    def run_baseline(self, clone, test_path, timeout):
        return {"outcome": "passed", "exit_code": 0, "stdout": "", "stderr": "", "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        return run_oracle(app_root, test_path, entry_points, timeout=timeout, effect=effect)


def run_loop(tmp_path, runner):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "app.py").write_text(SHELL_APP)
    (clone / "test_baseline.py").write_text("def test_baseline():\n    assert True\n")
    provider = ReplayProvider(tmp_path / "replay.jsonl", ScriptedExec())
    roles = Roles(*(ModelRole(r, provider) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    ledger = Ledger(tmp_path / "ledger.jsonl")
    loop = VerificationLoop(clone, tmp_path / "out", ledger, roles, "test_baseline.py", run_id="r1", runner=runner,
                            effect="canary_exec")
    loop.run("app.py")
    return [e.payload for e in ledger.read_all() if e.type == EventType.VERDICT]


def test_the_loop_proves_the_effect_red_to_green_on_the_host_path(tmp_path):
    [verdict] = run_loop(tmp_path, HostRunner())
    assert (verdict["verdict"], verdict["effect"], verdict["fix_verified"]) == ("proven", "canary_exec", True)


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


@pytest.mark.parametrize("flags, effect", [(["--effect", "canary_exec"], "canary_exec"), ([], "canary_read")])
def test_a_pr_diff_run_hands_its_effect_to_the_loop(tmp_path, monkeypatch, flags, effect):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")
    (repo / "app.py").write_text("x = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    (repo / "app.py").write_text("x = 2\n")
    _git(repo, "commit", "-qam", "head")
    seen = {}

    class Loop:
        def __init__(self, *args, **kwargs):
            seen.update(kwargs)

        def run(self, source):
            raise OSError("the loop itself is not under test")

    monkeypatch.setattr("exhibit_a.cli.run.VerificationLoop", Loop)
    (tmp_path / "recording.jsonl").write_text("")
    main(["run", "--repo", str(repo), "--out", str(tmp_path / "out"), "--pr-diff", "HEAD^..HEAD",
          "--replay", "--recording", str(tmp_path / "recording.jsonl"), *flags])
    assert seen["effect"] == effect


# -- residual limit, pinned --------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R5 (docs/oracle/oracle-provenance.md 7.5 and 3.9): an app's own binding replaced by computed names",
)
def test_r5_a_replaced_app_binding_proves_a_safe_app(tmp_path):
    app = QUOTED_APP.replace("import shlex\n", "from shlex import quote\n").replace("shlex.quote(name)", "quote(name)")
    exploit = PRELUDE + '''
import sys

def test_exploit():
    setattr(sys.modules["ap" + "p"], "quote", str)
    App(ALLOWED).handle_request("x; " + CANARY)
    assert not os.path.exists(MARKER)
'''
    assert shape(host(tmp_path, app, exploit)) != PROVEN


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="R1 (docs/oracle/oracle-provenance.md 7.1 and 3.9): the test rewrites the hook's closure in its own process",
)
def test_r1_a_rewritten_hook_closure_proves_a_safe_app(tmp_path):
    exploit = PRELUDE + '''
def test_exploit():
    collector = __import__("g" + "c")
    for obj in getattr(collector, "get_" + "objects")():
        if getattr(obj, "__name__", "") == "hook" and getattr(obj, "__module__", "").endswith("plugin"):
            cells = dict(zip(obj.__code__.co_freevars, getattr(obj, "__clo" + "sure__")))
            cells["marker"].cell_contents = "/nowhere/" + "x"
    with open(MARKER, "w") as fh:
        fh.write(TOKEN + "\\n")
    App(ALLOWED).handle_request(CANARY)
    assert not os.path.exists(MARKER)
'''
    assert shape(host(tmp_path, QUOTED_APP, exploit)) != PROVEN


# -- docker sandbox ----------------------------------------------------------------------------


@pytest.mark.docker
@pytest.mark.parametrize("app, exploit", [c[1:] for c in TRUE_CASES], ids=[c[0] for c in TRUE_CASES])
def test_a_vulnerable_app_is_proven_in_the_sandbox(tmp_path, app, exploit):
    j = sandbox(tmp_path, app, exploit)
    assert shape(j) == PROVEN, j.reason
    assert j.reason_code == "" and j.forged_events == 0 and j.app_tree_changes == []
    assert any(e.names_canary and e.sink_named for e in j.events)


@pytest.mark.docker
@pytest.mark.parametrize("app", [ARGV_APP, QUOTED_APP], ids=["argv_list", "shlex_quote"])
def test_a_fixed_app_is_not_proven_in_the_sandbox(tmp_path, app):
    j = sandbox(tmp_path, app, SHELL_EXPLOIT)
    assert shape(j) == ("passed", False, False), j.reason


@pytest.mark.docker
@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_in_the_sandbox_guard_on(tmp_path, name):
    j = sandbox(tmp_path, QUOTED_APP, CHEATS[name])
    assert shape(j) != PROVEN, j.reason


@pytest.mark.docker
@pytest.mark.parametrize("name", list(CHEATS))
def test_a_cheat_is_never_proven_in_the_sandbox_guard_off(tmp_path, monkeypatch, name):
    monkeypatch.setattr("exhibit_a.loop.runner.channel_problem", lambda path: None)
    monkeypatch.setattr("exhibit_a.loop.runner.exec_problem", lambda path: None)
    j = sandbox(tmp_path, QUOTED_APP, CHEATS[name])
    assert shape(j) != PROVEN, j.reason


@pytest.mark.docker
def test_the_test_calling_the_sink_directly_is_not_proven_in_the_sandbox(tmp_path):
    exploit = PRELUDE + '''
from app import list_dir

def test_exploit():
    list_dir(ALLOWED, "x; " + CANARY)
    assert not os.path.exists(MARKER)
'''
    assert shape(sandbox(tmp_path, SHELL_APP, exploit)) == ("failed", True, False)


@pytest.mark.docker
def test_the_container_keeps_the_canary_read_only(tmp_path):
    exploit = PRELUDE + '''
import stat

def test_exploit():
    assert stat.S_IMODE(os.stat(CANARY).st_mode) == 0o555
    try:
        open(CANARY, "a")
    except OSError:
        pass
    else:
        raise AssertionError("the canary is writable")
    with open(CANARY, encoding="utf-8") as fh:
        assert TOKEN in fh.read()
    assert not os.path.exists(MARKER)
    App(ALLOWED).handle_request("harmless")
'''
    j = sandbox(tmp_path, QUOTED_APP, exploit)
    # Opening it for appending was attempted, so the run is refused; the assertions all held.
    assert j.test_outcome == "passed", j.reason
    assert j.reason_code == "canary_tampered"


@pytest.mark.docker
def test_the_loop_proves_the_effect_red_to_green_in_the_sandbox(tmp_path):
    [verdict] = run_loop(tmp_path, SandboxRunner())
    assert (verdict["verdict"], verdict["effect"], verdict["fix_verified"]) == ("proven", "canary_exec", True)


@pytest.mark.docker
def test_the_sandbox_runs_the_read_effect_as_before(tmp_path):
    exploit = '''\
import os
from app import App

def test_exploit():
    App(os.environ["EXHIBIT_A_ALLOWED_DIR"]).handle_request("x")
'''
    root, test = layout(tmp_path, QUOTED_APP, exploit)
    j = SandboxRunner().run_exploit(root, test, ENTRY_POINTS, timeout=120.0)
    assert j.events == [] and j.test_outcome == "passed", j.reason
