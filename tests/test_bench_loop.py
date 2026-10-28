"""Tests for the real-loop pipeline adapter using a replay provider and the oracle fixtures."""

import sys
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.corpus import Case  # noqa: E402
from bench.runner import run_benchmark  # noqa: E402
from bench.flags import select  # noqa: E402
from bench.loop_pipeline import make_pipeline  # noqa: E402
from exhibit_a.models import ReplayProvider, Completion, ModelRole, Role  # noqa: E402
from exhibit_a.models.cost import Pricing  # noqa: E402
from exhibit_a.ledger import Ledger  # noqa: E402
from exhibit_a.oracle import run_oracle  # noqa: E402
from exhibit_a.schemas import EventType  # noqa: E402


BASELINE_TEST = '''\
from app import create_app


def test_known_file_is_served(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    app = create_app(str(tmp_path))
    assert app.handle_request("GET", "/download", {"name": "a.txt"}).body == "hello"
'''

TRAVERSAL = '''\
import os
from app import create_app


def test_download_cannot_escape_base_dir():
    app = create_app(os.environ["EXHIBIT_A_ALLOWED_DIR"])
    token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
    response = app.handle_request("GET", "/download", {"name": "%s"})
    assert token not in response.body
'''


def make_clone(root: Path):
    clone = root / "clone"
    if not clone.exists():
        fixtures = Path(__file__).parent / "fixtures" / "oracle" / "vulnerable"
        shutil.copytree(fixtures, clone)
        (clone / "test_baseline.py").write_text(BASELINE_TEST)
    return clone


class Scripted:
    """Simple scripted recorder for model answers used by the tests."""

    name = "scripted"
    pricing = Pricing()

    def __init__(self, counter: Path):
        self.counter = counter

    def complete(self, role: Role, prompt: str, schema: dict):
        if role == Role.ADVERSARY:
            body = {
                "suspicions": [
                    {
                        "id": "S-PROVEN",
                        "class": "path_traversal",
                        "location": {"file": "app.py", "line": 1},
                        "entry_point": "App.handle_request",
                        "hypothesis": "h",
                        "source": "diff",
                    },
                    {
                        "id": "S-DROP",
                        "class": "xss",
                        "location": {"file": "views.py", "line": 1},
                        "entry_point": "App.handle_request",
                        "hypothesis": "h",
                        "source": "diff",
                    },
                ]
            }
        elif role == Role.TEST_WRITER:
            if "S-PROVEN" in prompt:
                src = TRAVERSAL % "../outside/canary.txt"
            else:
                src = TRAVERSAL % "public.txt"
            body = {"test_source": src}
        elif role == Role.FIXER:
            # supply a trivial replacement for app.py (not used beyond writing a patch)
            fixed = (Path(__file__).parent / "fixtures" / "oracle" / "fixed" / "app.py").read_text()
            body = {"files": [{"path": "app.py", "content": fixed}]}
        else:
            body = {"variants": [{"name": "dot-segment", "test_source": TRAVERSAL % "./../outside/./canary.txt"}]}
        return Completion(text=__import__("json").dumps(body), tokens_in=10, tokens_out=10, latency_ms=1, model="scripted")


class FakeRunner:
    """Runner that executes the baseline via host pytest and exploits via the host oracle."""

    def __init__(self, baseline_outcome=None):
        self.baseline_outcome = baseline_outcome

    def run_baseline(self, clone, test_path, timeout):
        if self.baseline_outcome is not None:
            return {"outcome": self.baseline_outcome, "exit_code": 1, "stdout": "", "stderr": "", "oracle_events": []}
        env = {"PATH": __import__("os").environ.get("PATH", ""), "PYTHONPATH": clone, "PYTHONDONTWRITEBYTECODE": "1"}
        import subprocess, sys

        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path],
            cwd=clone,
            env=env,
            capture_output=True,
            timeout=30,
        )
        return {"outcome": "passed" if proc.returncode == 0 else "failed", "exit_code": proc.returncode, "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode(), "oracle_events": []}

    def run_exploit(self, app_root, test_path, entry_points, *, timeout):
        return run_oracle(app_root, test_path, entry_points, timeout=timeout)


def test_loop_pipeline_records_and_replays(tmp_path):
    root = tmp_path
    clone = make_clone(root)

    case = Case(id="c1", kind="vulnerable", repo=str(clone), commit="r1", ground_truth=[{"class": "path_traversal", "file": "app.py"}])

    recording = root / "replay.jsonl"
    provider = ReplayProvider(recording, Scripted(root / "flaky.count"))

    ledger = Ledger(root / "ledger.jsonl")
    pipeline = make_pipeline(provider, runner=FakeRunner())

    # Record one run under the 'full' ablation.
    rows = run_benchmark([case], pipeline, ledger, ablations=select(["full"]))
    assert rows and rows[0].proven == 1

    # The ledger should contain a proven verdict for S-PROVEN and none for S-DROP.
    run_id = f"bench:full:{case.id}"
    verdicts = [e for e in ledger.replay(run_id) if e.type == EventType.VERDICT]
    proven_for = {e.payload.get("suspicion_id") for e in verdicts if e.payload.get("verdict") == "proven"}
    assert "S-PROVEN" in proven_for
    assert "S-DROP" not in proven_for

    # Re-run from the recording alone (pure replay).
    replay_pipeline = make_pipeline(ReplayProvider(recording), runner=FakeRunner())
    ledger2 = Ledger(root / "ledger2.jsonl")
    rows2 = run_benchmark([case], replay_pipeline, ledger2, ablations=select(["full"]))
    assert rows2[0].proven == rows[0].proven

