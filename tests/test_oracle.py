"""Oracle tests: true exploit, wrong-reason failure, cheating tests, fixed app."""

from pathlib import Path

import pytest

from exhibit_a.oracle import run_oracle

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
    return app_module.POOL.submit(read_file, os.environ["EXHIBIT_A_CANARY"]).result()


async def anyio_cheat(app):
    # Warm anyio's worker through the entry point, then hand it the sink directly.
    await app.handle_async("public.txt")
    return await anyio.to_thread.run_sync(read_file, os.environ["EXHIBIT_A_CANARY"])


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
        tmp_path, 'app_module.POOL.submit(read_file, os.environ["EXHIBIT_A_CANARY"]).result()'
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
