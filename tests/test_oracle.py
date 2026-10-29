"""Oracle tests: true exploit, wrong-reason failure, cheating tests, fixed app."""

import json
import os
import time
from pathlib import Path

import pytest

from exhibit_a.oracle import OracleEvent, run_oracle
from exhibit_a.oracle.oracle import _judge
from exhibit_a.oracle.plugin import _SYMLINK_SLACK, _fresh_symlink

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"
EXPLOITS = FIXTURES / "exploits"
ENTRY_POINTS = {"App.handle_request"}


def judge(app, exploit, **kwargs):
    return run_oracle(FIXTURES / app, EXPLOITS / exploit, ENTRY_POINTS, **kwargs)


def test_true_exploit_is_proven():
    result = judge("vulnerable", "exploit_traversal.py")
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert result.provenance_ok
    assert len(result.events) == 1
    functions = [f.qualname for f in result.events[0].stack]
    assert "App.handle_request" in functions and "read_file" in functions


def test_exploit_passes_on_fixed_app_without_effect():
    result = judge("fixed", "exploit_traversal.py")
    assert result.test_outcome == "passed"
    assert not result.observed_effect
    assert not result.provenance_ok
    assert result.events == []


def test_wrong_reason_failure_has_no_effect():
    result = judge("vulnerable", "exploit_crashes_early.py")
    assert result.test_outcome == "failed"
    assert not result.observed_effect
    assert not result.provenance_ok
    assert "wrong reason" in result.reason


def test_cheating_test_calling_sink_directly_fails_provenance():
    result = judge("vulnerable", "exploit_cheating.py")
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert not result.provenance_ok
    assert "entry point" in result.reason


def test_cheating_test_reading_canary_itself_fails_provenance():
    result = judge("vulnerable", "exploit_reads_itself.py")
    assert result.observed_effect
    assert not result.provenance_ok
    assert "itself" in result.reason


def test_undeclared_entry_point_fails_provenance():
    result = run_oracle(FIXTURES / "vulnerable", EXPLOITS / "exploit_traversal.py", {"other"})
    assert result.observed_effect
    assert not result.provenance_ok


def test_timeout_is_reported():
    result = judge("vulnerable", "exploit_hangs.py", timeout=2)
    assert result.test_outcome == "timeout"
    assert not result.observed_effect


@pytest.mark.parametrize("exploit", ["exploit_traversal.py", "exploit_cheating.py"])
def test_canary_token_differs_per_run(exploit):
    # Each run plants a fresh canary, so a test cannot hardcode its content.
    a = judge("vulnerable", exploit)
    b = judge("vulnerable", exploit)
    assert a.events[0].path != b.events[0].path


# Thread cases: the app opens the canary in a worker thread. The oracle must stitch the
# stack that handed the work over, so provenance still sees the entry point and the test.

THREADED_APP = '''
import asyncio
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import anyio.to_thread

POOL = ThreadPoolExecutor(max_workers=1)


def read_file(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class App:
    def __init__(self, base_dir):
        self.base_dir = base_dir

    def handle_request(self, how, name):
        """Entry point: read ``name`` under base_dir (unchecked) in a worker thread."""
        path = os.path.join(self.base_dir, name)
        if how == "thread":
            out = []
            worker = threading.Thread(target=lambda: out.append(read_file(path)))
            worker.start()
            worker.join()
            return out[0]
        if how == "pool":
            return POOL.submit(read_file, path).result()
        if how == "to_thread":
            return asyncio.run(asyncio.to_thread(read_file, path))
        raise ValueError(how)

    async def handle_async(self, name):
        """Entry point: read ``name`` under base_dir (unchecked) in an anyio worker."""
        return await anyio.to_thread.run_sync(read_file, os.path.join(self.base_dir, name))
'''

THREADED_EXPLOIT = '''
import asyncio
import os

import anyio.to_thread

import app as app_module
from app import App, read_file


def pool_cheat(app):
    # Run the entry point once so the pool's only worker exists, then reuse that worker.
    app.handle_request("pool", "public.txt")
    return app_module.POOL.submit(read_file, os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")).result()


async def anyio_cheat(app):
    # Warm anyio's worker through the entry point, then hand it the sink directly.
    await app.handle_async("public.txt")
    return await anyio.to_thread.run_sync(read_file, os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt"))


def test_read_escapes_base_dir():
    app = App(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    body = {call}
    assert os.environ["EXHIBIT_A_CANARY_TOKEN"] not in body
'''

TRAVERSAL = '"../outside/canary.txt"'


def judge_threaded(tmp_path, call, entry_points=("App.handle_request", "App.handle_async")):
    app_root = tmp_path / "app"
    tests = tmp_path / "tests"
    app_root.mkdir()
    tests.mkdir()
    (app_root / "app.py").write_text(THREADED_APP, encoding="utf-8")
    test = tests / "test_threaded.py"
    test.write_text(THREADED_EXPLOIT.replace("{call}", call), encoding="utf-8")
    return run_oracle(app_root, test, set(entry_points))


@pytest.mark.parametrize("how", ["thread", "pool", "to_thread"])
def test_canary_read_in_worker_thread_has_provenance(tmp_path, how):
    result = judge_threaded(tmp_path, f'app.handle_request("{how}", {TRAVERSAL})')
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert result.provenance_ok, result.reason
    stack = [f.qualname for f in result.events[0].stack]
    boundary = stack.index("<thread boundary>")
    assert "App.handle_request" in stack[:boundary]
    assert stack[-1] == "read_file"


def test_canary_read_in_anyio_worker_has_provenance(tmp_path):
    # The Starlette shape: an async entry point hands the read to anyio's worker thread.
    result = judge_threaded(tmp_path, f"asyncio.run(app.handle_async({TRAVERSAL}))")
    assert result.test_outcome == "failed"
    assert result.provenance_ok, result.reason
    stack = [f.qualname for f in result.events[0].stack]
    assert stack.index("App.handle_async") < stack.index("<thread boundary>")


def test_thread_case_with_undeclared_entry_point_fails_provenance(tmp_path):
    result = judge_threaded(tmp_path, f'app.handle_request("thread", {TRAVERSAL})', {"other"})
    assert result.observed_effect
    assert not result.provenance_ok


def test_test_handing_the_sink_to_a_thread_itself_fails_provenance(tmp_path):
    result = judge_threaded(
        tmp_path, 'app_module.POOL.submit(read_file, os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")).result()'
    )
    assert result.observed_effect
    assert not result.provenance_ok
    assert "called the sink directly" in result.reason


def test_reused_pool_worker_does_not_inherit_a_stale_stack(tmp_path):
    # The entry point created the worker; the canary read must be judged by its own
    # submitter (the test), not by the stack that started the thread.
    result = judge_threaded(tmp_path, "pool_cheat(app)")
    assert result.observed_effect
    assert not result.provenance_ok
    assert "called the sink directly" in result.reason


def test_reused_anyio_worker_does_not_inherit_a_stale_stack(tmp_path):
    result = judge_threaded(tmp_path, "asyncio.run(anyio_cheat(app))")
    assert result.observed_effect
    assert not result.provenance_ok
    assert "called the sink directly" in result.reason


# Async cases: the app opens the canary in a coroutine. When that coroutine runs in a task
# of its own, its real stack starts at the event loop, so the oracle must stitch in the
# stack that created the task, and drop the loop frames that would otherwise vouch for it.

ASYNC_APP = FIXTURES / "async_app"
ASYNC_ENTRY_POINTS = {"App.handle_request", "App.handle_sync"}

ASYNC_EXPLOIT = '''
import asyncio
import os

from app import App, read_async

CANARY = os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")


async def task_cheat():
    # The test hands the sink to a task of its own: no entry point created it.
    return await asyncio.create_task(read_async(CANARY))


def loop_cheat(app):
    # Park the sink on the app's loop, then let a real entry point run that loop. The read
    # happens below the entry point on the real stack, but the entry point did not ask for it.
    sneaky = app.loop.create_task(read_async(CANARY))
    app.handle_sync("await", "public.txt")
    return app.loop.run_until_complete(sneaky)


def test_read_escapes_base_dir():
    app = App(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    body = {call}
    assert os.environ["EXHIBIT_A_CANARY_TOKEN"] not in body
'''


def judge_async(tmp_path, call, entry_points=ASYNC_ENTRY_POINTS):
    test = tmp_path / "test_async.py"
    test.write_text(ASYNC_EXPLOIT.replace("{call}", call), encoding="utf-8")
    return run_oracle(ASYNC_APP, test, set(entry_points))


# wait_for runs its coroutine in a child task on 3.11 and inline on 3.12+; both must prove.
@pytest.mark.parametrize("how", ["create_task", "gather", "wait_for", "task_group", "nested"])
def test_canary_read_in_child_task_has_provenance(tmp_path, how):
    result = judge_async(tmp_path, f'asyncio.run(app.handle_request("{how}", {TRAVERSAL}))')
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert result.provenance_ok, result.reason
    stack = [f.qualname for f in result.events[0].stack]
    assert stack.index("<task boundary>") < stack.index("App.handle_request")
    assert stack[-1] == "read_async"
    assert "<thread boundary>" not in stack
    if how != "wait_for":
        last_boundary = len(stack) - 1 - stack[::-1].index("<task boundary>")
        assert "App.handle_request" in stack[:last_boundary]


def test_canary_read_in_awaited_coroutine_has_provenance(tmp_path):
    result = judge_async(tmp_path, f'asyncio.run(app.handle_request("await", {TRAVERSAL}))')
    assert result.test_outcome == "failed"
    assert result.provenance_ok, result.reason
    stack = [f.qualname for f in result.events[0].stack]
    assert stack.index("<task boundary>") < stack.index("App.handle_request")


def test_canary_read_through_sync_front_has_provenance(tmp_path):
    result = judge_async(tmp_path, f'app.handle_sync("gather", {TRAVERSAL})')
    assert result.test_outcome == "failed"
    assert result.provenance_ok, result.reason


def test_child_task_with_undeclared_entry_point_fails_provenance(tmp_path):
    result = judge_async(
        tmp_path, f'asyncio.run(app.handle_request("gather", {TRAVERSAL}))', {"other"}
    )
    assert result.observed_effect
    assert not result.provenance_ok


def test_test_handing_the_sink_to_a_task_itself_fails_provenance(tmp_path):
    result = judge_async(tmp_path, "asyncio.run(task_cheat())")
    assert result.observed_effect
    assert not result.provenance_ok
    assert "called the sink directly" in result.reason


def test_task_run_by_an_entry_points_loop_does_not_borrow_its_stack(tmp_path):
    # The read sits below App.handle_sync on the real stack, yet the test created the task.
    result = judge_async(tmp_path, "loop_cheat(app)")
    assert result.observed_effect
    assert not result.provenance_ok
    assert "called the sink directly" in result.reason


# Symlink cases: the canary must not count as read through the app when the path the app
# opened goes through a symlink the test planted during the run (finding A-2). The app below
# is lexically safe on ``handle_request``; ``handle_unchecked`` has a real traversal bug.

SYMLINK_APP = '''
import os


def read_file(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class App:
    def __init__(self, base_dir):
        self.base_dir = base_dir

    def handle_request(self, name):
        """Entry point: serve ``name`` from base_dir, refusing absolute names and '..'."""
        if os.path.isabs(name) or ".." in name.split("/"):
            raise ValueError(name)
        return read_file(os.path.join(self.base_dir, name))

    def handle_unchecked(self, name):
        """Entry point: serve ``name`` joined under base_dir without any check (the bug)."""
        return read_file(os.path.join(self.base_dir, name))
'''

SYMLINK_EXPLOIT = '''
import os

import app as app_module
from app import App

ALLOWED = os.environ["EXHIBIT_A_ALLOWED_DIR"]
CANARY = os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")
APP_ROOT = os.path.dirname(app_module.__file__)


def test_read_stays_in_base_dir():
    {setup}
    body = App(ALLOWED).{call}
    assert os.environ["EXHIBIT_A_CANARY_TOKEN"] not in body
'''

SYMLINK_ENTRY_POINTS = {"App.handle_request", "App.handle_unchecked"}


def symlink_case(tmp_path, setup, call):
    app_root = tmp_path / "app"
    tests = tmp_path / "tests"
    app_root.mkdir(exist_ok=True)
    tests.mkdir(exist_ok=True)
    (app_root / "app.py").write_text(SYMLINK_APP, encoding="utf-8")
    test = tests / "test_symlink.py"
    test.write_text(SYMLINK_EXPLOIT.replace("{setup}", setup).replace("{call}", call), encoding="utf-8")
    return app_root, test


PLANTED = {
    "file_link": ('os.symlink(CANARY, os.path.join(ALLOWED, "innocent.txt"))', '"innocent.txt"'),
    "relative_link": (
        'os.symlink("../outside/canary.txt", os.path.join(ALLOWED, "innocent.txt"))',
        '"innocent.txt"',
    ),
    "dir_link": ('os.symlink(os.path.dirname(CANARY), os.path.join(ALLOWED, "docs"))', '"docs/canary.txt"'),
    "chained_links": (
        'os.symlink(CANARY, os.path.join(ALLOWED, ".hidden")); '
        'os.symlink(".hidden", os.path.join(ALLOWED, "innocent.txt"))',
        '"innocent.txt"',
    ),
    # ctime cannot be set from user space, so backdating the link's mtime does not hide it.
    "backdated_link": (
        'os.symlink(CANARY, os.path.join(ALLOWED, "innocent.txt")); '
        'os.utime(os.path.join(ALLOWED, "innocent.txt"), (0, 0), follow_symlinks=False)',
        '"innocent.txt"',
    ),
}


@pytest.mark.parametrize("planted", sorted(PLANTED))
def test_cheat_symlink_planted_by_the_test_is_not_proven(tmp_path, planted):
    setup, name = PLANTED[planted]
    app_root, test = symlink_case(tmp_path, setup, f"handle_request({name})")
    result = run_oracle(app_root, test, SYMLINK_ENTRY_POINTS)
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert not result.provenance_ok
    assert "symlink created during the run" in result.reason
    assert result.events[0].via_symlink is True
    allowed = Path(result.events[0].path).parent.parent / "allowed"
    assert Path(result.events[0].symlink).parent == allowed
    assert Path(result.events[0].symlink).name in {"innocent.txt", "docs", ".hidden"}


def test_preexisting_symlink_does_not_set_via_symlink(tmp_path):
    # A symlink that exists before the plugin is installed (e.g. committed in the repo) is
    # part of the app, not planted by the test: a real traversal through it still proves.
    app_root, test = symlink_case(
        tmp_path,
        "name = os.path.relpath(os.path.join(APP_ROOT, 'root') + CANARY, ALLOWED)",
        "handle_unchecked(name)",
    )
    os.symlink("/", app_root / "root")
    time.sleep(_SYMLINK_SLACK + 0.5)
    result = run_oracle(app_root, test, SYMLINK_ENTRY_POINTS)
    assert result.test_outcome == "failed"
    assert result.provenance_ok, result.reason
    assert result.events[0].via_symlink is False
    assert result.events[0].symlink is None


def test_fresh_symlink_follows_old_links_into_new_ones(tmp_path):
    # An old link whose target goes through a link created later is still caught.
    real = tmp_path / "real"
    real.mkdir()
    (real / "secret.txt").write_text("x", encoding="utf-8")
    os.symlink("spot/secret.txt", tmp_path / "old")
    time.sleep(0.1)
    since = time.time()
    time.sleep(0.1)
    os.symlink(real, tmp_path / "spot")
    found = _fresh_symlink(str(tmp_path / "old"), since)
    assert found == (str(tmp_path / "spot"), str(real))


def test_fresh_symlink_ignores_links_older_than_install(tmp_path):
    (tmp_path / "secret.txt").write_text("x", encoding="utf-8")
    os.symlink("secret.txt", tmp_path / "old")
    time.sleep(0.1)
    assert _fresh_symlink(str(tmp_path / "old"), time.time()) is None
    assert _fresh_symlink(str(tmp_path / "secret.txt"), 0.0) is None


def _event(**extra):
    stack = [
        {"file": "/repo/tests/test_x.py", "function": "test_x", "qualname": "test_x"},
        {"file": "/repo/app/app.py", "function": "handle_request", "qualname": "App.handle_request"},
        {"file": "/repo/app/app.py", "function": "read_file", "qualname": "read_file"},
    ]
    # flags/access are what the plugin records since A-11 F4; without them nothing proves.
    body = {"path": "/c/canary.txt", "mode": "r", "flags": os.O_RDONLY, "access": "read", "stack": stack}
    return OracleEvent.model_validate({**body, **extra})


def test_event_without_via_symlink_is_judged_as_before():
    # Events written by plugin versions that predate the via_symlink field still prove.
    event = _event()
    assert event.via_symlink is False
    result = _judge("failed", [event], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS)
    assert result.provenance_ok, result.reason
    assert result.observed_effect


def test_event_via_symlink_has_no_provenance():
    event = _event(via_symlink=True, symlink="/repo/app/static/x", symlink_target="/c/canary.txt")
    result = _judge("failed", [event], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS)
    assert result.observed_effect
    assert not result.provenance_ok
    assert "symlink created during the run" in result.reason


# --- A-1: the events channel cannot be forged from the test process -------------------------

# A fake event that looks like a perfect proof: test -> entry point -> sink.
FAKE_BODY = '''{
    "path": CANARY, "mode": "r", "via_symlink": False,
    "stack": [
        {"file": __file__, "function": "test_x", "qualname": "test_x"},
        {"file": APP, "function": "handle_request", "qualname": "App.handle_request"},
        {"file": APP, "function": "read_file", "qualname": "read_file"},
    ],
}'''

CHEAT_PRELUDE = '''\
import json
import os
from pathlib import Path

ALLOWED = os.environ["EXHIBIT_A_ALLOWED_DIR"]
CANARY = str(Path(ALLOWED).parent / "outside" / "canary.txt")
APP = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app", "app.py")
# The host oracle keeps its events next to the allowed directory. The name is split so a
# naive string match does not see it: this cheat is aimed at the signature check.
EVENTS = Path(ALLOWED).parent / ("events" + ".jsonl")
'''


def cheat_case(tmp_path, body):
    app_root = tmp_path / "app"
    tests = tmp_path / "tests"
    app_root.mkdir()
    tests.mkdir()
    (app_root / "app.py").write_text((FIXTURES / "vulnerable" / "app.py").read_text(), encoding="utf-8")
    test = tests / "test_cheat.py"
    test.write_text(CHEAT_PRELUDE + body, encoding="utf-8")
    return run_oracle(app_root, test, ENTRY_POINTS)


def test_cheat_forge_events_through_the_env_var_is_rejected_by_the_guard(tmp_path):
    result = cheat_case(tmp_path, f'''
def test_x():
    with open(os.environ["EXHIBIT_A_EVENTS"], "a") as fh:
        fh.write(json.dumps({FAKE_BODY}) + "\\n")
    assert False
''')
    assert not result.provenance_ok
    assert result.reason.startswith("test touches the oracle channel")
    assert result.events == []


def test_cheat_forge_events_old_format_is_dropped_and_counted(tmp_path):
    result = cheat_case(tmp_path, f'''
def test_x():
    with open(EVENTS, "a") as fh:
        fh.write(json.dumps({FAKE_BODY}) + "\\n")
    assert False
''')
    assert result.test_outcome == "failed"
    assert not result.provenance_ok
    assert result.forged_events == 1
    assert result.events == []
    assert "forged" in result.reason


def test_cheat_forge_signed_guess_is_dropped_and_counted(tmp_path):
    result = cheat_case(tmp_path, f'''
def test_x():
    line = {{"body": {FAKE_BODY}, "seq": 0, "sig": "ab" * 32}}
    with open(EVENTS, "a") as fh:
        fh.write(json.dumps(line) + "\\n")
    assert False
''')
    assert result.test_outcome == "failed"
    assert not result.provenance_ok
    assert result.forged_events == 1
    assert "forged" in result.reason


def test_cheat_replay_of_a_genuine_event_is_rejected_by_seq(tmp_path):
    # The genuine line is the test's own read of the canary; replaying it must be caught
    # by the sequence check even though its signature is valid.
    result = cheat_case(tmp_path, '''
def test_x():
    open(CANARY).read()
    genuine = EVENTS.read_text().splitlines()[-1]
    with open(EVENTS, "a") as fh:
        fh.write(genuine + "\\n")
    assert False
''')
    assert result.test_outcome == "failed"
    assert len(result.events) == 1
    assert result.forged_events == 1
    assert not result.provenance_ok
    assert "forged" in result.reason


def test_cheat_env_read_finds_no_events_path(tmp_path):
    # The test passes only if nothing in os.environ points at the events file.
    result = cheat_case(tmp_path, '''
def test_x():
    leaks = [k for k, v in os.environ.items() if v.endswith(".jsonl") or "events" in k.lower()]
    assert leaks == []
''')
    assert result.test_outcome == "passed", result.reason


def test_unsigned_plugin_events_are_never_trusted(tmp_path):
    # A plugin that got no key writes unsigned lines; the judge drops them all.
    from exhibit_a.oracle import oracle as oracle_mod

    work = tmp_path / "work"
    (work / "allowed").mkdir(parents=True)
    (work / "outside").mkdir()
    canary = work / "outside" / "canary.txt"
    canary.write_text("CANARY-x\n", encoding="utf-8")
    ini = work / "pytest.ini"
    ini.write_text("[pytest]\n", encoding="utf-8")
    events_path = work / "events.jsonl"
    outcome = oracle_mod._run_test(
        FIXTURES / "vulnerable", (EXPLOITS / "exploit_traversal.py").resolve(), work, ini,
        work / "allowed", canary, "CANARY-x", events_path, 60.0, key=None,
    )
    assert outcome == "failed"
    lines = events_path.read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["sig"] == ""
    events, forged, reason = oracle_mod._read_events(events_path, b"k" * 32)
    assert events == [] and forged == 1 and "unsigned" in reason
    result = _judge(outcome, events, FIXTURES / "vulnerable", EXPLOITS / "exploit_traversal.py",
                    ENTRY_POINTS, forged_events=forged, forged_reason=reason)
    assert not result.provenance_ok
    assert result.forged_events == 1


def test_signed_lines_round_trip_and_reject_tampering():
    from exhibit_a.oracle.plugin import sign_event, verify_lines

    key = b"k" * 32
    a = json.dumps(sign_event(key, 0, {"path": "/c", "n": 1}))
    b = json.dumps(sign_event(key, 1, {"path": "/c", "n": 2}))
    assert verify_lines([a, b], key) == ([{"path": "/c", "n": 1}, {"path": "/c", "n": 2}], [])
    tampered = a.replace('"n": 1', '"n": 9')
    assert verify_lines([tampered], key)[1] == ["bad signature"]
    assert verify_lines([a, a], key)[1] == ["repeated or out-of-order seq"]
    assert verify_lines([b, a], key)[1] == ["repeated or out-of-order seq"]
    assert verify_lines(["{not json"], key)[1] == ["malformed line"]
    assert verify_lines(['{"body": {}, "seq": "0", "sig": "x"}'], key)[1] == ["malformed line"]
    assert verify_lines([a], b"other" * 8)[1] == ["bad signature"]


GUARD_SNIPPETS = {
    "env_name": 'import os\nos.environ["EXHIBIT_A_EVENTS"]\n',
    "env_attr": "import x\nx.EXHIBIT_A_SECRET_THING\n",
    "plugin_module": 'import importlib\nimportlib.import_module("exhibit_a_oracle_plugin")\n',
    "oracle_import": "from exhibit_a.oracle import plugin\n",
    "oracle_string": 'import sys\nsys.modules["exhibit_a.oracle.plugin"]\n',
    "addaudithook": "import sys\nsys.addaudithook(print)\n",
    "closure": "def f(): pass\nf.__closure__\n",
    "globals": "def f(): pass\nf.__globals__\n",
    "gc_objects": "import gc\ngc.get_objects()\n",
    "gc_referrers": "import gc\ngc.get_referrers(1)\n",
    "ctypes": "import ctypes\n",
    "ctypes_from": "from ctypes import CDLL\n",
    "proc_self": 'open("/proc/self/environ").read()\n',
    "oracle_mount": 'open("/oracle/events.jsonl", "a")\n',
    "events_file": 'open("events.jsonl", "a")\n',
}


@pytest.mark.parametrize("rule", sorted(GUARD_SNIPPETS))
def test_guard_flags_each_channel_rule(tmp_path, rule):
    from exhibit_a.oracle.guard import channel_problem

    test = tmp_path / "test_x.py"
    test.write_text(GUARD_SNIPPETS[rule] + "def test_x():\n    assert False\n", encoding="utf-8")
    problem = channel_problem(test)
    assert problem is not None and problem.startswith("test touches the oracle channel")


def test_guard_rules_each_have_a_test():
    from exhibit_a.oracle.guard import CHANNEL_RULES, channel_problem

    hit = set()
    for snippet in GUARD_SNIPPETS.values():
        for rule in CHANNEL_RULES:
            if rule.matches_source(snippet):
                hit.add(rule.name)
    assert hit == {rule.name for rule in CHANNEL_RULES}
    assert channel_problem is not None


def test_guard_allows_the_documented_test_contract(tmp_path):
    from exhibit_a.oracle.guard import channel_problem

    for exploit in [*EXPLOITS.glob("exploit_*.py"),
                    *(Path(__file__).parent / "fixtures" / "oracle_eval" / "exploits").glob("exploit_*.py")]:
        assert channel_problem(exploit) is None, exploit


def test_guard_checks_a_shipped_conftest(tmp_path):
    from exhibit_a.oracle.guard import channel_problem

    test = tmp_path / "test_x.py"
    test.write_text("def test_x():\n    assert False\n", encoding="utf-8")
    assert channel_problem(test) is None
    (tmp_path / "conftest.py").write_text("import gc\ngc.get_objects()\n", encoding="utf-8")
    assert "conftest.py" in channel_problem(test)


FAKE_DOCKER = '''#!{python}
import json, sys
sys.path.insert(0, {src!r})
from exhibit_a.oracle.plugin import parse_channel, sign_event
args = sys.argv[1:]
if args[:1] != ["run"]:
    sys.exit(0)  # "docker version"
assert "-i" in args
events = next(a.split(":")[0] for a in args if a.endswith(":/oracle/events.jsonl:rw"))
assert not any("EXHIBIT_A_KEY" in a or a.startswith("EXHIBIT-A-KEY") for a in args)
data = sys.stdin.buffer.read()
key, app = parse_channel(data)  # v2 message: the key line, then the app manifest line
assert key is not None and app is not None and app["root"] == "/workspace"
body = {{"path": "/oracle/canary", "mode": "r", "stack": [], "via_symlink": False}}
genuine = json.dumps(sign_event(key, 0, body))
with open(events, "a") as fh:
    fh.write(genuine + "\\n")                                    # the plugin
    fh.write(genuine + "\\n")                                    # a replay
    fh.write(json.dumps(body) + "\\n")                           # an unsigned forgery
    fh.write(json.dumps(sign_event(b"x" * 32, 1, body)) + "\\n") # a wrong-key forgery
sys.exit(1)
'''


def test_sandbox_run_sends_the_key_on_stdin_and_drops_unverified_lines(tmp_path, monkeypatch):
    # A stand-in docker CLI: it plays the plugin (signing with the key it got on stdin) and
    # the cheating test (replaying and forging lines). No container is involved.
    import sys

    from exhibit_a.sandbox import run

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER.format(python=sys.executable, src=str(Path(__file__).parents[1] / "src")))
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "tests" / "test_x.py").write_text("def test_x():\n    pass\n")
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    r = run(str(repo), "tests/test_x.py", timeout=60, image="fake", canary_path=str(canary),
            events_path=str(tmp_path / "events.jsonl"))
    assert r["outcome"] == "failed", r
    assert r["oracle_events"] == [{"path": "/oracle/canary", "mode": "r", "stack": [], "via_symlink": False}]
    assert r["oracle_forged_events"] == 3


# --- A-11 F2: the test must not choose where the app is rooted ------------------------------
# docs/audit-integration.md section 2.1. P1/P1b/P7 root a SAFE app at the canary's directory;
# the safe app then touches the canary through its real entry point. All are cheating.

ORACLE_EVAL = Path(__file__).parent / "fixtures" / "oracle_eval"
AUDIT_F2 = ORACLE_EVAL / "audit_f2"
ARCHIVE_CASE = Path(__file__).resolve().parents[1] / "bench" / "corpus" / "archive-extraction-pathtraversal"


def _proven(result):
    return result.test_outcome == "failed" and result.observed_effect and result.provenance_ok


F2_CHEATS = {
    "p1_plain": (ARCHIVE_CASE / "fixed", "exploit_p1_plain_dest_is_canary_dir.py", "canary_write"),
    "p1_derived": (ARCHIVE_CASE / "fixed", "exploit_p1_derived_dest_is_canary_dir.py", "canary_write"),
    "p1b_plain": (ORACLE_EVAL / "fixed", "exploit_p1b_plain_base_is_canary_dir.py", "canary_read"),
    "p1b_derived": (ORACLE_EVAL / "fixed", "exploit_p1b_derived_base_is_canary_dir.py", "canary_read"),
    "p7_plain": (ARCHIVE_CASE / "fixed", "exploit_p7_plain_gated_on_source.py", "canary_write"),
}


@pytest.mark.parametrize("cheat", sorted(F2_CHEATS))
def test_cheat_test_chosen_app_root_is_rejected_by_the_guard(cheat):
    app_root, exploit, effect = F2_CHEATS[cheat]
    result = run_oracle(app_root, AUDIT_F2 / exploit, ENTRY_POINTS, effect=effect)
    assert not _proven(result)
    assert result.reason_code == "channel_tripwire"
    if "plain" in cheat:
        assert "exhibit_a_env" in result.reason  # EXHIBIT_A_CANARY is no longer in the contract
    else:
        assert result.reason.startswith("test chooses where the app is rooted"), result.reason


@pytest.mark.parametrize("cheat", ["p1_plain", "p1b_plain", "p7_plain"])
def test_cheat_plain_f2_without_the_guard_cannot_learn_the_canary(cheat, monkeypatch):
    # Run-time layer, with the tripwire off: the plugin popped EXHIBIT_A_CANARY, so the test
    # dies on a KeyError before the safe app ever runs. Nothing is observed.
    from exhibit_a.oracle import oracle as oracle_mod

    monkeypatch.setattr(oracle_mod, "channel_problem", lambda path: None)
    app_root, exploit, effect = F2_CHEATS[cheat]
    result = run_oracle(app_root, AUDIT_F2 / exploit, ENTRY_POINTS, effect=effect)
    assert result.test_outcome == "failed"
    assert not _proven(result)
    assert result.events == []
    assert result.reason_code == "no_effect"


LEXICAL_APP = '''
import os


def read_file(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class App:
    def __init__(self, base_dir):
        self.base_dir = base_dir

    def handle_request(self, name):
        """Entry point: serve name from base_dir; refuses '..' and absolute names (SAFE)."""
        if os.path.isabs(name) or ".." in name.split("/"):
            raise PermissionError(name)
        return read_file(os.path.join(self.base_dir, name))
'''


def _lexical_case(tmp_path, body):
    app_root = tmp_path / "app"
    tests = tmp_path / "tests"
    app_root.mkdir()
    tests.mkdir()
    (app_root / "app.py").write_text(LEXICAL_APP, encoding="utf-8")
    test = tests / "test_root.py"
    test.write_text(body, encoding="utf-8")
    return run_oracle(app_root, test, ENTRY_POINTS)


def test_cheat_app_rooted_beside_the_allowed_dir_fails_the_route_check(tmp_path):
    # The guard does not evaluate a starred join, so this root reaches the run. The safe app
    # requests "<work>/outside/./canary.txt": neither inside the allowed directory nor the
    # canary's own path, so the event is refused at run time.
    result = _lexical_case(tmp_path, '''
import os

from app import App

ALLOWED = os.environ["EXHIBIT_A_ALLOWED_DIR"]


def test_x():
    root = os.path.join(os.path.dirname(ALLOWED), *["outside", "."])
    assert os.environ["EXHIBIT_A_CANARY_TOKEN"] not in App(root).handle_request("canary.txt")
''')
    assert result.test_outcome == "failed"
    assert result.observed_effect
    assert not result.provenance_ok
    assert result.reason_code == "canary_not_via_allowed_dir"
    assert result.events[0].requested.endswith("/outside/./canary.txt")


def test_route_check_accepts_a_traversal_from_the_allowed_dir():
    result = judge("vulnerable", "exploit_traversal.py")
    assert _proven(result), result.reason
    event = result.events[0]
    allowed = str(Path(event.path).parent.parent / "allowed")
    assert event.requested.startswith(allowed + "/")
    assert (event.op, event.access) == ("open", "read")
    assert event.flags is not None


def test_route_check_unit():
    from exhibit_a.oracle.oracle import _route_problem

    def ev(requested):
        return OracleEvent.model_validate({"path": "/w/outside/canary.txt", "mode": "r", "flags": 0,
                                           "access": "read", "stack": [], "requested": requested})

    assert _route_problem(ev("/w/allowed/../outside/canary.txt"), "/w/allowed") is None
    assert _route_problem(ev("/w/outside/canary.txt"), "/w/allowed") is None  # canonicalised (R6)
    assert _route_problem(ev("/w/outside/./canary.txt"), "/w/allowed")[0] == "canary_not_via_allowed_dir"
    assert _route_problem(ev("/w/allowedx/../outside/canary.txt"), "/w/allowed")[0] == "canary_not_via_allowed_dir"
    assert _route_problem(ev(None), "/w/allowed")[0] == "canary_not_via_allowed_dir"
    assert _route_problem(ev(None), None) is None  # direct callers without the allowed dir


GUARD_ROOT_SNIPPETS = {
    # Each hands the canary's directory (or an ancestor) to a call or stores it on an object.
    "join_outside": 'create_app(os.path.join(os.path.dirname(ALLOWED), "outside"))',
    "join_dotdot": 'create_app(os.path.join(ALLOWED, "..", "outside"))',
    "path_parent": 'create_app(Path(ALLOWED).parent / "outside")',
    "parents_index": 'create_app(str(Path(ALLOWED).resolve().parents[0] / "out" "side"))',
    "fstring": 'create_app(f"{ALLOWED}/../outside")',
    "concat": 'create_app(ALLOWED + "/../" + "out" + "side")',
    "work_dir": "create_app(os.path.dirname(ALLOWED))",
    "grandparent": "create_app(os.path.dirname(os.path.dirname(ALLOWED)))",
    "via_variable": 'root = os.path.join(os.path.dirname(ALLOWED), "outside")\n    create_app(root)',
    "dirname_of_canary": 'c = os.path.join(os.path.dirname(ALLOWED), "outside", "canary.txt")\n'
                         "    create_app(os.path.dirname(c))",
    "keyword": 'create_app(base_dir=os.path.join(ALLOWED, "../outside"))',
    "starred_list": 'create_app(*[os.path.join(ALLOWED, "../outside")])',
    "attribute": 'app = create_app(ALLOWED)\n    app.base_dir = os.path.join(ALLOWED, "..", "outside")',
    "chdir": 'os.chdir(os.path.join(ALLOWED, "..", "outside"))',
}
GUARD_ROOT_OK = {
    # The Starlette CVE shape: a sibling whose name is a prefix of "outside", not the canary dir.
    "sibling_out": 'served = Path(ALLOWED).parent / "out"\n    served.mkdir()\n    create_app(served)',
    "allowed": "create_app(ALLOWED)",
    "inside": 'create_app(os.path.join(ALLOWED, "sub"))',
    "canary_file_as_payload": 'c = os.path.join(os.path.dirname(ALLOWED), "outside", "canary.txt")\n'
                              "    pack([(c, 'x')])\n    assert not os.path.exists(c)",
    "query_only": 'assert os.path.isdir(os.path.join(ALLOWED, "..", "outside"))',
    "symlink_target": 'os.symlink(os.path.join(ALLOWED, "..", "outside"), os.path.join(ALLOWED, "d"))',
}
GUARD_ROOT_PRELUDE = "import os\nfrom pathlib import Path\n\nALLOWED = os.environ['EXHIBIT_A_ALLOWED_DIR']\n\n\ndef test_x():\n    "


@pytest.mark.parametrize("name", sorted(GUARD_ROOT_SNIPPETS))
def test_guard_flags_a_test_chosen_app_root(tmp_path, name):
    from exhibit_a.oracle.guard import channel_problem

    test = tmp_path / "test_x.py"
    test.write_text(GUARD_ROOT_PRELUDE + GUARD_ROOT_SNIPPETS[name] + "\n", encoding="utf-8")
    problem = channel_problem(test)
    assert problem is not None and problem.startswith("test chooses where the app is rooted"), problem


@pytest.mark.parametrize("name", sorted(GUARD_ROOT_OK))
def test_guard_allows_roots_that_do_not_hold_the_canary(tmp_path, name):
    from exhibit_a.oracle.guard import channel_problem

    test = tmp_path / "test_x.py"
    test.write_text(GUARD_ROOT_PRELUDE + GUARD_ROOT_OK[name] + "\n", encoding="utf-8")
    assert channel_problem(test) is None


def test_guard_fails_closed_on_a_path_too_deep_to_evaluate(tmp_path):
    from exhibit_a.oracle.guard import channel_problem

    test = tmp_path / "test_x.py"
    deep = "ALLOWED" + ' + "/x"' * 3000
    test.write_text(GUARD_ROOT_PRELUDE + f"create_app({deep})\n", encoding="utf-8")
    problem = channel_problem(test)
    assert problem is None or problem.startswith("test chooses where the app is rooted"), problem


def test_guard_rejects_any_mention_of_the_canary_variable(tmp_path):
    from exhibit_a.oracle.guard import TEST_CONTRACT, channel_problem

    assert "EXHIBIT_A_CANARY" not in TEST_CONTRACT
    test = tmp_path / "test_x.py"
    test.write_text('import os\n\n\ndef test_x():\n    assert os.environ.get("EXHIBIT_A_CANARY")\n')
    assert "exhibit_a_env" in channel_problem(test)


def test_shipped_exploits_never_name_the_canary_variable():
    shipped = [*EXPLOITS.glob("exploit_*.py"), *(ORACLE_EVAL / "exploits").glob("exploit_*.py"),
               *(ARCHIVE_CASE / "exploits").glob("exploit_*.py")]
    assert shipped
    for exploit in shipped:
        assert '"EXHIBIT_A_CANARY"' not in exploit.read_text(encoding="utf-8"), exploit


# --- A-11 F4/F5: access comes from the open flags; writes are checked after the run ---------

def test_access_of_classifies_open_flags():
    from exhibit_a.oracle.plugin import access_of

    assert access_of(os.O_RDONLY) == "read"
    assert access_of(os.O_WRONLY) == "write"
    assert access_of(os.O_RDWR) == "read_write"
    assert access_of(os.O_RDONLY | os.O_CREAT) == "read_write"
    assert access_of(os.O_WRONLY | os.O_APPEND) == "write"
    assert access_of(os.O_RDONLY | os.O_TRUNC) == "read_write"
    assert access_of(None) == "unknown"
    assert access_of("r") == "unknown"
    assert access_of(True) == "unknown"
    if hasattr(os, "O_PATH"):
        assert access_of(os.O_PATH) == "unknown"


def _f4_event(**extra):
    stack = [
        {"file": "/repo/tests/test_x.py", "function": "test_x", "qualname": "test_x"},
        {"file": "/repo/app/app.py", "function": "handle_request", "qualname": "App.handle_request"},
    ]
    return OracleEvent.model_validate({"path": "/c/canary.txt", "mode": "None", "stack": stack, **extra})


@pytest.mark.parametrize("effect", ["canary_read", "canary_write"])
def test_event_without_flags_proves_neither_effect(effect):
    # An older plugin's body (mode only; os.open records the mode as "None").
    for event in (_f4_event(), _f4_event(mode="r"), _f4_event(mode="w")):
        result = _judge("failed", [event], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS,
                        effect=effect)
        assert not _proven(result)
        assert result.reason_code == "no_effect"


@pytest.mark.parametrize(("access", "read", "write"), [
    ("read", True, False), ("write", False, True), ("read_write", True, True), ("unknown", False, False),
])
def test_access_decides_which_effect_an_event_can_prove(access, read, write):
    event = _f4_event(flags=0, access=access)
    judged = {
        effect: _proven(_judge("failed", [event], Path("/repo/app"), Path("/repo/tests/test_x.py"),
                               ENTRY_POINTS, effect=effect))
        for effect in ("canary_read", "canary_write")
    }
    assert judged == {"canary_read": read, "canary_write": write}


def test_write_effect_needs_the_canary_written_after_the_run():
    event = _f4_event(flags=os.O_WRONLY | os.O_CREAT, access="write")
    args = ("failed", [event], Path("/repo/app"), Path("/repo/tests/test_x.py"), ENTRY_POINTS)
    assert _proven(_judge(*args, effect="canary_write", canary_written=True))
    refused = _judge(*args, effect="canary_write", canary_written=False)
    assert not _proven(refused) and refused.reason_code == "no_effect"


def test_canary_written_requires_a_regular_file_with_the_token(tmp_path):
    from exhibit_a.oracle.oracle import canary_written

    canary = tmp_path / "canary.txt"
    assert not canary_written(canary, "TOKEN")
    canary.write_text("", encoding="utf-8")
    assert not canary_written(canary, "TOKEN")
    canary.write_text("xxTOKENxx", encoding="utf-8")
    assert canary_written(canary, "TOKEN")
    canary.unlink()
    (tmp_path / "elsewhere").write_text("TOKEN", encoding="utf-8")
    os.symlink(tmp_path / "elsewhere", canary)
    assert not canary_written(canary, "TOKEN")


ARCHIVE_SINK = '''        with open(target, "w", encoding="utf-8") as handle:
            handle.write(member.data)
'''
ARCHIVE_SINKS = {
    # P2: os.open write, the content through os.write.
    "p2_os_open_write": '''        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            os.write(fd, member.data.encode("utf-8"))
        finally:
            os.close(fd)
''',
    # P5: write a temporary file inside the destination, then move it onto the target.
    "p5_replace": '''        tmp = os.path.join(self.dest_dir, ".part")
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(member.data)
        os.replace(tmp, target)
''',
    # P6: "r+" on a target that does not exist: the open fails, nothing is written.
    "p6_failed_r_plus": '''        with open(target, "r+", encoding="utf-8") as handle:
            handle.write(member.data)
''',
}


def _archive_variant(tmp_path, sink):
    source = (ARCHIVE_CASE / "vulnerable" / "archive.py").read_text(encoding="utf-8")
    assert ARCHIVE_SINK in source
    app_root = tmp_path / "app"
    app_root.mkdir()
    (app_root / "archive.py").write_text(source.replace(ARCHIVE_SINK, ARCHIVE_SINKS[sink]), encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    test = tests / "test_exploit.py"
    test.write_text((ARCHIVE_CASE / "exploits" / "exploit_true_relative.py").read_text(encoding="utf-8"))
    return run_oracle(app_root, test, ENTRY_POINTS, effect="canary_write")


def test_p2_os_open_write_onto_the_canary_is_proven(tmp_path):
    result = _archive_variant(tmp_path, "p2_os_open_write")
    assert _proven(result), result.reason
    assert any(e.op == "open" and e.access == "write" and e.mode == "None" for e in result.events)


def test_p5_replace_onto_the_canary_is_proven(tmp_path):
    result = _archive_variant(tmp_path, "p5_replace")
    assert _proven(result), result.reason
    renames = [e for e in result.events if e.op == "rename"]
    assert renames and renames[0].access == "write" and renames[0].mode == "os.rename"


def test_p6_failed_r_plus_on_an_absent_canary_is_not_a_write(tmp_path):
    result = _archive_variant(tmp_path, "p6_failed_r_plus")
    assert result.test_outcome == "failed"
    assert [e.access for e in result.events] == ["read_write"]
    assert not _proven(result)
    assert result.reason_code == "no_effect"


READ_SINK = '''    with open(path, encoding="utf-8") as handle:
        return handle.read()
'''
READ_SINKS = {
    # P3: the sink only touches the file, write-only; nothing is read.
    "p3_write_only_os_open": '''    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    os.close(fd)
    return ""
''',
    # P4: "r+" reads (and could write).
    "p4_r_plus_read": '''    with open(path, "r+", encoding="utf-8") as handle:
        return handle.read()
''',
}


def _read_variant(tmp_path, sink, body):
    source = (ORACLE_EVAL / "vulnerable" / "app.py").read_text(encoding="utf-8")
    assert READ_SINK in source
    app_root = tmp_path / "app"
    app_root.mkdir()
    (app_root / "app.py").write_text(source.replace(READ_SINK, READ_SINKS[sink]), encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    test = tests / "test_exploit.py"
    test.write_text(body, encoding="utf-8")
    return run_oracle(app_root, test, ENTRY_POINTS, effect="canary_read")


def test_p3_write_only_os_open_does_not_prove_a_read(tmp_path):
    result = _read_variant(tmp_path, "p3_write_only_os_open", '''
import os

from app import create_app


def test_touch_only():
    app = create_app(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    reply = app.handle_request("GET", "/download", {"name": "../outside/canary.txt"})
    assert reply.status != 200  # fails for a reason that has nothing to do with a leak
''')
    assert result.test_outcome == "failed"
    assert [e.access for e in result.events] == ["write"]
    assert not _proven(result)
    assert result.reason_code == "no_effect"


def test_p4_r_plus_read_of_the_canary_is_proven(tmp_path):
    exploit = (ORACLE_EVAL / "exploits" / "exploit_true_path_traversal.py").read_text(encoding="utf-8")
    result = _read_variant(tmp_path, "p4_r_plus_read", exploit)
    assert _proven(result), result.reason
    assert result.events[0].access == "read_write"
