"""Tests for the real-loop pipeline adapter using a replay provider and the oracle fixtures."""

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import bench.loop_pipeline as loop_pipeline  # noqa: E402
from bench.corpus import Case, load_corpus  # noqa: E402
from bench.runner import run_benchmark  # noqa: E402
from bench.flags import select  # noqa: E402
from bench.loop_pipeline import CaseMaterialsProvider, make_pipeline  # noqa: E402
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
        self.seen_effects: list[str] = []

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

    def run_exploit(self, app_root, test_path, entry_points, *, timeout, effect="canary_read"):
        self.seen_effects.append(effect)
        return run_oracle(app_root, test_path, entry_points, timeout=timeout, effect=effect)


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


# --- Real corpus -----------------------------------------------------------

CORPUS_DIR = ROOT / "bench" / "corpus"
ARCHIVE_DIR = CORPUS_DIR / "archive-extraction-pathtraversal"
STARLETTE_DIR = CORPUS_DIR / "starlette-cve-2023-29159"
STARLETTE_FIXED_DIR = CORPUS_DIR / "starlette-cve-2023-29159-fixed"


def _by_id(cases):
    return {case.id: case for case in cases}


def test_load_corpus_accepts_directory_with_all_three_cases():
    cases = load_corpus(CORPUS_DIR)
    assert [c.id for c in cases] == [
        "archive-extraction-pathtraversal",
        "starlette-cve-2023-29159",
        "starlette-cve-2023-29159-fixed",
    ]
    by_id = _by_id(cases)

    archive = by_id["archive-extraction-pathtraversal"]
    assert archive.kind == "vulnerable"
    assert archive.tree == "vulnerable"
    assert archive.baseline_test == "baseline_test.py"
    assert archive.effect == "canary_write"
    assert archive.recording == ""
    assert archive.requirements == ()
    assert archive.source_file == "archive.py"
    assert archive.ground_truth == (
        {"class": "archive_extraction_path_traversal", "file": "vulnerable/archive.py"},
    )

    vuln = by_id["starlette-cve-2023-29159"]
    assert vuln.kind == "vulnerable"
    assert vuln.tree == "vulnerable"
    assert vuln.baseline_test == "baseline_test.py"
    assert vuln.recording == "replay.jsonl"
    assert vuln.effect == "canary_read"
    assert vuln.requirements == ("starlette==0.26.1", "anyio>=3.4,<5")
    assert vuln.source_file == "starlette/staticfiles.py"

    fixed = by_id["starlette-cve-2023-29159-fixed"]
    assert fixed.kind == "fixed"
    assert fixed.tree == "fixed"
    assert fixed.requirements == ("starlette==0.27.0", "anyio>=3.4,<5")
    assert fixed.recording == "replay.jsonl"
    assert fixed.effect == "canary_read"


def test_load_corpus_accepts_single_case_json_files():
    for directory, expected_id in [
        (ARCHIVE_DIR, "archive-extraction-pathtraversal"),
        (STARLETTE_DIR, "starlette-cve-2023-29159"),
        (STARLETTE_FIXED_DIR, "starlette-cve-2023-29159-fixed"),
    ]:
        from_file = load_corpus(directory / "case.json")
        from_dir = load_corpus(directory)
        assert [c.id for c in from_file] == [expected_id]
        assert [c.id for c in from_dir] == [expected_id]
        assert from_file[0] == from_dir[0]


def test_stage_never_resolves_repo_url_as_path(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    case = Case(
        id="bad",
        kind="vulnerable",
        repo="https://github.com/encode/starlette",
        commit="x",
        case_dir=str(tmp_path),
        tree="",
        requirements=(),
    )
    with pytest.raises(FileNotFoundError, match="bad"):
        loop_pipeline._stage_case(case, out)
    try:
        loop_pipeline._stage_case(case, out)
    except FileNotFoundError as exc:
        assert "https://github.com/encode/starlette" in str(exc)
        assert "run.tree" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected FileNotFoundError")


def test_stage_reports_unresolvable_tree_clearly(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (tmp_path / "baseline_test.py").write_text("def test_x(): pass\n")
    case = Case(
        id="no-tree",
        kind="vulnerable",
        repo="https://example.invalid/repo",
        commit="x",
        case_dir=str(tmp_path),
        tree="missing-dir",
        baseline_test="baseline_test.py",
        requirements=(),
    )
    with pytest.raises(FileNotFoundError, match="no-tree"):
        loop_pipeline._stage_case(case, out)


def test_pipeline_reports_setup_error_without_traceback(tmp_path, capsys):
    (tmp_path / "baseline_test.py").write_text("def test_x(): pass\n")
    case = Case(
        id="broken",
        kind="vulnerable",
        repo="https://example.invalid/repo",
        commit="x",
        case_dir=str(tmp_path),
        tree="missing-dir",
        requirements=(),
    )
    ledger = Ledger(tmp_path / "ledger.jsonl")
    pipeline = make_pipeline(_never_called_provider(), runner=FakeRunner())
    rows = run_benchmark([case], pipeline, ledger, ablations=select(["full"]))
    assert rows[0].proven == 0
    assert "broken" in capsys.readouterr().err
    baselines = [e for e in ledger.replay("bench:full:broken") if e.type == EventType.BASELINE_DONE]
    assert baselines and baselines[0].payload.get("ok") is False
    assert "setup_error" in baselines[0].payload.get("outcome", "")


def _never_called_provider():
    class NeverCalled:
        name = "never-called"
        pricing = Pricing()

        def complete(self, role, prompt, schema):
            raise AssertionError("provider must not be called for an unstaged case")

    return NeverCalled()


# --- Starlette stub installer ----------------------------------------------

STUB_EXCEPTIONS = '''\
class HTTPException(Exception):
    def __init__(self, status_code, detail=""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
'''

STUB_STATICFILES = '''\
"""Minimal StaticFiles stand-in mirroring the real lookup_path check under test."""

import os

from .exceptions import HTTPException


class StaticFiles:
    def __init__(self, directory):
        self.directories = [os.fspath(directory)]

    def lookup_path(self, path):
        for directory in self.directories:
            full_path = os.path.abspath(os.path.join(directory, path.lstrip("/")))
            if CHECK != directory:
                continue
            if os.path.isfile(full_path):
                return full_path
        return ""

    async def __call__(self, scope, receive, send):
        assert scope["type"] == "http"
        full_path = self.lookup_path(scope["path"])
        if not full_path:
            raise HTTPException(404)
        with open(full_path, "rb") as fh:
            body = fh.read()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})
'''

STARLETTE_EXPLOIT = '''\
import asyncio
import os
from pathlib import Path

from starlette.exceptions import HTTPException
from starlette.staticfiles import StaticFiles


def get(app, path):
    scope = {
        "type": "http", "method": "GET", "path": path, "raw_path": path.encode(),
        "query_string": b"", "headers": [], "root_path": "", "scheme": "http",
        "server": ("testserver", 80), "client": ("testclient", 5000),
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    try:
        asyncio.run(app(scope, receive, send))
    except HTTPException:
        return b""
    return b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def test_static_files_must_not_serve_a_sibling_directory():
    work = Path(os.environ["EXHIBIT_A_ALLOWED_DIR"]).parent
    token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
    served = work / "out"
    served.mkdir(exist_ok=True)
    body = get(StaticFiles(directory=served), "%s")
    assert token.encode() not in body
'''


def _stub_installer(monkeypatch, expected_requirements, *, vulnerable):
    """Replace the pip install with a local StaticFiles stub mirroring the CVE check."""
    check = (
        "os.path.commonprefix([full_path, directory])"
        if vulnerable
        else "os.path.commonpath([full_path, directory])"
    )

    def fake_install(target: Path, requirements):
        assert tuple(requirements) == tuple(expected_requirements)
        package = Path(target) / "starlette"
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text("")
        (package / "exceptions.py").write_text(STUB_EXCEPTIONS)
        (package / "staticfiles.py").write_text(
            STUB_STATICFILES.replace("CHECK", check)
        )

    monkeypatch.setattr(loop_pipeline, "_install_requirements", fake_install)


class StarletteScripted:
    """Model answers for the Starlette cases: one suspicion, traversal exploit, fix."""

    name = "starlette-scripted"
    pricing = Pricing()

    def __init__(self, fixed_source: str):
        self.fixed_source = fixed_source

    def complete(self, role: Role, prompt: str, schema: dict):
        if role == Role.ADVERSARY:
            body = {
                "suspicions": [
                    {
                        "id": "S-STAR",
                        "class": "path_traversal",
                        "location": {"file": "starlette/staticfiles.py", "line": 1},
                        "entry_point": "StaticFiles.__call__",
                        "hypothesis": "lookup_path compares paths as characters",
                        "source": "scope['path']",
                    }
                ]
            }
        elif role == Role.TEST_WRITER:
            body = {"test_source": STARLETTE_EXPLOIT % "/../outside/canary.txt"}
        elif role == Role.FIXER:
            body = {"files": [{"path": "starlette/staticfiles.py", "content": self.fixed_source}]}
        else:
            body = {
                "variants": [
                    {"name": "double-slash", "test_source": STARLETTE_EXPLOIT % "//../outside/canary.txt"}
                ]
            }
        return Completion(text=json.dumps(body), tokens_in=10, tokens_out=10, latency_ms=1, model="starlette-scripted")


def _fixed_stub_source() -> str:
    return STUB_STATICFILES.replace(
        "CHECK", "os.path.commonpath([full_path, directory])"
    )


def _proven_verdicts(ledger: Ledger, run_id: str) -> set[str]:
    verdicts = [e for e in ledger.replay(run_id) if e.type == EventType.VERDICT]
    return {e.payload.get("suspicion_id") for e in verdicts if e.payload.get("verdict") == "proven"}


def _evidence_fix_verified(out_dir: Path) -> bool:
    flags = []
    for evidence in sorted((out_dir).rglob("evidence.json")):
        flags.append(json.loads(evidence.read_text()).get("fix_verified", False))
    return any(flags)


def test_starlette_vuln_case_proves_with_fake_runner(tmp_path, monkeypatch):
    cases = _by_id(load_corpus(STARLETTE_DIR / "case.json"))
    case = cases["starlette-cve-2023-29159"]
    _stub_installer(monkeypatch, case.requirements, vulnerable=True)

    runner = FakeRunner()
    ledger = Ledger(tmp_path / "ledger.jsonl")
    pipeline = make_pipeline(StarletteScripted(_fixed_stub_source()), runner=runner)
    rows = run_benchmark([case], pipeline, ledger, ablations=select(["full"]))

    assert rows and rows[0].proven == 1
    assert _proven_verdicts(ledger, "bench:full:starlette-cve-2023-29159") == {"S-STAR"}
    assert runner.seen_effects and set(runner.seen_effects) == {"canary_read"}
    assert _evidence_fix_verified(tmp_path / "out")


def test_starlette_fixed_case_discards_unproven(tmp_path, monkeypatch):
    cases = _by_id(load_corpus(STARLETTE_FIXED_DIR / "case.json"))
    case = cases["starlette-cve-2023-29159-fixed"]
    _stub_installer(monkeypatch, case.requirements, vulnerable=False)

    runner = FakeRunner()
    ledger = Ledger(tmp_path / "ledger.jsonl")
    pipeline = make_pipeline(StarletteScripted(_fixed_stub_source()), runner=runner)
    rows = run_benchmark([case], pipeline, ledger, ablations=select(["full"]))

    assert rows and rows[0].proven == 0
    assert _proven_verdicts(ledger, "bench:full:starlette-cve-2023-29159-fixed") == set()
    verdicts = [e for e in ledger.replay("bench:full:starlette-cve-2023-29159-fixed") if e.type == EventType.VERDICT]
    assert verdicts and all(v.payload.get("verdict") == "discarded_unproven" for v in verdicts)


def test_archive_case_proves_canary_write_through_materials_provider(tmp_path):
    cases = _by_id(load_corpus(ARCHIVE_DIR / "case.json"))
    case = cases["archive-extraction-pathtraversal"]

    runner = FakeRunner()
    ledger = Ledger(tmp_path / "ledger.jsonl")
    pipeline = make_pipeline(CaseMaterialsProvider(case), runner=runner)
    rows = run_benchmark([case], pipeline, ledger, ablations=select(["full"]))

    assert rows and rows[0].proven == 1
    run_id = "bench:full:archive-extraction-pathtraversal"
    assert _proven_verdicts(ledger, run_id) == {"archive-extraction-unchecked-member-path"}
    assert runner.seen_effects and set(runner.seen_effects) == {"canary_write"}
    assert _evidence_fix_verified(tmp_path / "out")
