"""No CLI mode executes untrusted test code on the host (audit finding F8, T099).

Every CLI mode (``--case``, ``--case --replay``, ``--pr-diff``, ``--pr-diff --replay``,
``--case --slice``, ``--pr-diff --slice``) and the default benchmark pipeline must route
both baseline and exploit runs through ``SandboxRunner``. A host execution path
(``HostRunner`` / ``run_oracle``) exists only behind the explicit, documented, test-only
switch ``allow_host_execution=True`` that the CLI never sets.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from bench.corpus import Case, load_corpus
from bench.flags import select
from bench.loop_pipeline import CaseMaterialsProvider, make_pipeline
from bench.runner import run_benchmark
from exhibit_a.cli import main as cli_main
from exhibit_a.cli import run as run_mod
from exhibit_a.cli.parser import build_parser
from exhibit_a.ledger import Ledger
from exhibit_a.loop import HostRunner, Roles, SandboxRunner, VerificationLoop
from exhibit_a.loop import pipeline as loop_pipeline_mod
from exhibit_a.loop import runner as loop_runner_mod
from exhibit_a.models import Completion, ModelRole, ReplayProvider, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import Judgement, OracleEvent
from exhibit_a.schemas import EventType, VerdictValue

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "bench" / "corpus"
ARCHIVE_CASE = CORPUS_DIR / "archive-extraction-pathtraversal"
STARLETTE_CASE = CORPUS_DIR / "starlette-cve-2023-29159"
STARLETTE_FIXED_CASE = CORPUS_DIR / "starlette-cve-2023-29159-fixed"


def _is_pytest_command(cmd: Any) -> bool:
    """Return True if a subprocess command attempts to invoke pytest on the host (not via docker)."""
    if isinstance(cmd, (str, bytes)):
        text = cmd.decode("utf-8", "replace") if isinstance(cmd, bytes) else cmd
        tokens = text.split()
    else:
        tokens = [str(part) for part in cmd]
    if not tokens:
        return False
    # `docker run ... pytest ...` executes pytest inside the container, not on the host.
    if Path(tokens[0]).name.lower() == "docker":
        return False
    for idx, tok in enumerate(tokens):
        base = Path(tok).name.lower()
        if base in {"pytest", "py.test"} or base.startswith("pytest-"):
            return True
        if tok == "-m" and idx + 1 < len(tokens) and tokens[idx + 1] == "pytest":
            return True
    return False


@pytest.fixture
def forbid_host_test_execution(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Fail immediately if any code spawns host pytest or calls the host oracle."""
    seen_subprocesses: list[list[str]] = []
    real_run = subprocess.run
    real_popen = subprocess.Popen

    def guarded_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
        argv = [str(x) for x in cmd] if not isinstance(cmd, (str, bytes)) else [str(cmd)]
        seen_subprocesses.append(argv)
        if _is_pytest_command(cmd):
            raise AssertionError(f"Forbidden host pytest execution via subprocess.run: {argv}")
        return real_run(cmd, *args, **kwargs)

    class GuardedPopen(real_popen):  # type: ignore[misc]
        def __init__(self, cmd: Any, *args: Any, **kwargs: Any) -> None:
            argv = [str(x) for x in cmd] if not isinstance(cmd, (str, bytes)) else [str(cmd)]
            seen_subprocesses.append(argv)
            if _is_pytest_command(cmd):
                raise AssertionError(f"Forbidden host pytest execution via subprocess.Popen: {argv}")
            super().__init__(cmd, *args, **kwargs)

    def forbidden_oracle(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Forbidden host oracle execution (run_oracle / _run_test called on host)")

    monkeypatch.setattr(subprocess, "run", guarded_run)
    monkeypatch.setattr(subprocess, "Popen", GuardedPopen)
    monkeypatch.setattr("exhibit_a.oracle.run_oracle", forbidden_oracle)
    monkeypatch.setattr("exhibit_a.oracle.oracle.run_oracle", forbidden_oracle)
    monkeypatch.setattr("exhibit_a.oracle.oracle._run_test", forbidden_oracle)
    monkeypatch.setattr(loop_runner_mod, "run_oracle", forbidden_oracle)
    return seen_subprocesses


class SpySandboxRunner:
    """Deterministic stand-in for SandboxRunner that never touches the host process table."""

    instances: list["SpySandboxRunner"] = []

    def __init__(
        self,
        requirements: tuple[str, ...] | list[str] = (),
        image: str | None = None,
        sql_db: str | None = None,
        access_db: str | None = None,
        access: dict[str, str] | None = None,
        redirect_meta: bool = False,
    ) -> None:
        self.requirements = tuple(requirements)
        self.image = image
        self.sql_db = sql_db
        self.access_db = access_db
        self.access = access
        self.redirect_meta = redirect_meta
        self.baselines: list[tuple[str, str, float]] = []
        self.exploits: list[tuple[Path, Path, set[str], float, str]] = []
        SpySandboxRunner.instances.append(self)

    def run_baseline(self, clone_path: str, test_path: str, timeout: float) -> dict[str, Any]:
        self.baselines.append((clone_path, test_path, timeout))
        return {
            "outcome": "passed",
            "exit_code": 0,
            "stdout": "1 passed",
            "stderr": "",
            "oracle_events": [],
        }

    def run_exploit(
        self,
        app_root: Path,
        test_path: Path,
        entry_points: Any,
        *,
        timeout: float,
        effect: str = "canary_read",
    ) -> Judgement:
        ep_set = set(entry_points)
        self.exploits.append((Path(app_root), Path(test_path), ep_set, timeout, effect))
        on_fixed = Path(app_root).name == "fixed"
        if on_fixed:
            return Judgement(
                observed_effect=False,
                provenance_ok=False,
                reason="exploit passed on fixed code",
                test_outcome="passed",
                events=[],
            )
        ep = next(iter(ep_set), "App.handle_request")
        event = OracleEvent.model_validate(
            {
                "path": "/tmp/exhibit_a_oracle/outside/canary.txt",
                "mode": "w" if effect == "canary_write" else "r",
                "flags": 0,
                "access": "write" if effect == "canary_write" else "read",
                "requested": "/tmp/exhibit_a_oracle/outside/canary.txt",
                "stack": [
                    {
                        "file": "/workspace/_exhibit_a_oracle/test_exploit.py",
                        "line": 10,
                        "function": "test_exploit",
                        "qualname": "test_exploit",
                    },
                    {
                        "file": "/workspace/archive.py",
                        "line": 20,
                        "function": ep.split(".")[-1],
                        "qualname": ep,
                        "admitted": True,
                    },
                    {
                        "file": "/workspace/archive.py",
                        "line": 63,
                        "function": "_target",
                        "qualname": "Extractor._target",
                        "admitted": True,
                    },
                ],
            }
        )
        return Judgement(
            observed_effect=True,
            provenance_ok=True,
            reason="observed canary effect from entry point",
            test_outcome="failed",
            events=[event],
        )


def _archive_materials_provider() -> CaseMaterialsProvider:
    return CaseMaterialsProvider(load_corpus(ARCHIVE_CASE / "case.json")[0])


def _archive_roles() -> Roles:
    provider = _archive_materials_provider()
    return Roles(
        *(
            ModelRole(role, provider)
            for role in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)
        )
    )


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _stage_pr_diff_repo(root: Path) -> tuple[Path, str, str, Path]:
    """Create a Git repo with a base..head diff on archive.py and a matching replay recording."""
    repo = root / "repo"
    shutil.copytree(ARCHIVE_CASE / "vulnerable", repo)
    shutil.copyfile(ARCHIVE_CASE / "baseline_test.py", repo / "test_baseline.py")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    archive_py = repo / "archive.py"
    archive_py.write_text(
        archive_py.read_text(encoding="utf-8").replace(
            "return os.path.join(self.dest_dir, name)",
            "return os.path.join(self.dest_dir, str(name))",
        ),
        encoding="utf-8",
    )
    _git(repo, "commit", "-q", "-am", "head")
    head = _git(repo, "rev-parse", "HEAD")

    # Record a replay file for the modified archive.py using SpySandboxRunner (no host execution).
    rec_dir = root / "record_work"
    clone = rec_dir / "clone"
    shutil.copytree(repo, clone, ignore=shutil.ignore_patterns(".git"))
    recording = root / "pr_replay.jsonl"
    replay_provider = ReplayProvider(recording, recorder=_archive_materials_provider())
    roles = Roles(
        *(
            ModelRole(role, replay_provider)
            for role in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)
        )
    )
    loop = VerificationLoop(
        clone,
        rec_dir / "out",
        Ledger(rec_dir / "ledger.jsonl"),
        roles,
        ".",
        run_id="record-pr",
        runner=SpySandboxRunner(),
        effect="canary_write",
    )
    loop.run("archive.py")
    SpySandboxRunner.instances.clear()
    return repo, base, head, recording


def test_cli_run_has_no_local_baseline_or_host_switch() -> None:
    """_local_baseline is gone and the CLI parser exposes no host-execution switch."""
    assert not hasattr(run_mod, "_local_baseline")
    parser = build_parser()
    option_strings: set[str] = set()
    for action in parser._actions:
        option_strings.update(action.option_strings)
        if hasattr(action, "choices") and isinstance(action.choices, dict):
            for subparser in action.choices.values():
                for sub_action in subparser._actions:
                    option_strings.update(sub_action.option_strings)
    assert "--allow-host-execution" not in option_strings
    assert "--host-runner" not in option_strings


def test_host_runner_requires_explicit_test_only_switch(tmp_path: Path) -> None:
    """HostRunner fails closed unless allow_host_execution=True is explicitly passed."""
    with pytest.raises(PermissionError, match="allow_host_execution=True"):
        HostRunner()
    with pytest.raises(PermissionError, match="allow_host_execution=True"):
        HostRunner(allow_host_execution=False)

    runner = HostRunner(allow_host_execution=True, requirements=("pytest",), sql_db="data/app.db")
    assert runner.allow_host_execution is True
    assert runner.requirements == ("pytest",)
    assert runner.sql_db == "data/app.db"

    clone = tmp_path / "clone"
    clone.mkdir()
    ledger = Ledger(tmp_path / "ledger.jsonl")

    default_loop = VerificationLoop(clone, tmp_path / "out1", ledger, None, "test_baseline.py")  # type: ignore[arg-type]
    assert isinstance(default_loop.runner, SandboxRunner)
    assert default_loop.allow_host_execution is False

    host_loop = VerificationLoop(
        clone,
        tmp_path / "out2",
        ledger,
        None,  # type: ignore[arg-type]
        "test_baseline.py",
        allow_host_execution=True,
    )
    assert isinstance(host_loop.runner, HostRunner)
    assert host_loop.allow_host_execution is True

    # Verify the test-only HostRunner executes a baseline when allow_host_execution=True.
    (clone / "test_baseline.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n", encoding="utf-8")
    base_res = runner.run_baseline(str(clone), "test_baseline.py", 30.0)
    assert base_res["outcome"] == "passed"
    assert base_res["exit_code"] == 0


@pytest.mark.parametrize(
    "mode",
    [
        "case_live",
        "case_replay",
        "case_slice",
        "pr_diff_live",
        "pr_diff_replay",
        "pr_diff_slice",
    ],
)
def test_cli_never_spawns_host_test_or_oracle_in_any_mode(
    mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    forbid_host_test_execution: list[list[str]],
) -> None:
    """Every CLI mode routes baseline and exploit runs through SandboxRunner, never the host."""
    SpySandboxRunner.instances.clear()
    monkeypatch.setattr(run_mod, "SandboxRunner", SpySandboxRunner)
    monkeypatch.setattr(loop_pipeline_mod, "SandboxRunner", SpySandboxRunner)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(run_mod, "_live_roles", lambda args, meter: _archive_roles())

    out = tmp_path / "out"
    if mode == "case_live":
        code = cli_main(["run", "--case", str(ARCHIVE_CASE), "--out", str(out)])
        expected_code = 0
    elif mode == "case_replay":
        code = cli_main(["run", "--case", str(ARCHIVE_CASE), "--replay", "--out", str(out)])
        expected_code = 0
    elif mode == "case_slice":
        code = cli_main(["run", "--case", str(ARCHIVE_CASE), "--slice", "--out", str(out)])
        expected_code = 0
    else:
        repo, base, head, recording = _stage_pr_diff_repo(tmp_path)
        argv = [
            "run",
            "--repo",
            str(repo),
            "--pr-diff",
            f"{base}..{head}",
            "--effect",
            "canary_write",
            "--out",
            str(out),
        ]
        if mode == "pr_diff_replay":
            argv.extend(["--replay", "--recording", str(recording)])
        elif mode == "pr_diff_slice":
            argv.append("--slice")
        code = cli_main(argv)
        expected_code = 10  # PR-diff exit code 10 means at least one proven finding

    assert code == expected_code
    assert SpySandboxRunner.instances, f"expected SandboxRunner to be instantiated in mode={mode}"
    runner = SpySandboxRunner.instances[-1]
    # Baseline runs at least twice (initial baseline + post-fix baseline in VERIFY).
    assert len(runner.baselines) >= 2
    # Exploits run at least 4 times (3 x vulnerable + 1 x fixed + bypass variant).
    assert len(runner.exploits) >= 4
    # Confirm no host subprocess ever invoked pytest.
    assert not any(_is_pytest_command(cmd) for cmd in forbid_host_test_execution)


def test_bench_make_pipeline_uses_sandbox_runner_and_never_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    forbid_host_test_execution: list[list[str]],
) -> None:
    """bench.loop_pipeline.make_pipeline uses SandboxRunner by default and never runs on the host."""
    SpySandboxRunner.instances.clear()
    monkeypatch.setattr("bench.loop_pipeline.SandboxRunner", SpySandboxRunner)

    cases = load_corpus(ARCHIVE_CASE / "case.json")
    providers = {cases[0].id: CaseMaterialsProvider(cases[0])}
    ledger = Ledger(tmp_path / "ledger.jsonl")
    pipeline = make_pipeline(providers)
    rows = run_benchmark(cases, pipeline, ledger, ablations=select(["full"]))

    assert rows and rows[0].proven == 1
    assert len(SpySandboxRunner.instances) == 1
    runner = SpySandboxRunner.instances[0]
    assert len(runner.baselines) >= 2
    assert len(runner.exploits) >= 4
    assert not any(_is_pytest_command(cmd) for cmd in forbid_host_test_execution)


@pytest.mark.docker
@pytest.mark.parametrize(
    "case_name, expected_code, expected_verdict, expected_fix_verified",
    [
        ("starlette-cve-2023-29159", 0, VerdictValue.PROVEN.value, True),
        ("starlette-cve-2023-29159-fixed", 1, VerdictValue.DISCARDED_UNPROVEN.value, False),
        ("archive-extraction-pathtraversal", 0, VerdictValue.PROVEN.value, True),
        ("command-injection-shell", 0, VerdictValue.PROVEN.value, True),
        ("unsafe-deserialization-pickle", 0, VerdictValue.PROVEN.value, True),
        ("sql-injection-login", 0, VerdictValue.PROVEN.value, True),
        ("sql-injection-search", 0, VerdictValue.PROVEN.value, True),
    ],
)
def test_docker_cli_replay_corpus_cases_preserve_verdicts_without_host_execution(
    case_name: str,
    expected_code: int,
    expected_verdict: str,
    expected_fix_verified: bool,
    tmp_path: Path,
    forbid_host_test_execution: list[list[str]],
) -> None:
    """Replaying every corpus case through the CLI runs inside Docker and preserves verdicts."""
    out = tmp_path / case_name
    case_path = CORPUS_DIR / case_name
    code = cli_main(["run", "--case", str(case_path), "--replay", "--out", str(out)])
    assert code == expected_code

    ledger = Ledger(out / "ledger.jsonl")
    events = list(ledger.replay(case_name))
    baselines = [e for e in events if e.type == EventType.BASELINE_DONE]
    assert baselines and baselines[0].payload.get("ok") is True

    verdicts = [e for e in events if e.type == EventType.VERDICT]
    assert verdicts, f"expected at least one verdict for {case_name}"
    assert [v.payload.get("verdict") for v in verdicts] == [expected_verdict]
    assert [bool(v.payload.get("fix_verified")) for v in verdicts] == [expected_fix_verified]

    if expected_verdict == VerdictValue.PROVEN.value:
        packages = list((out / "packages").iterdir())
        assert len(packages) == 1
        verdict_data = json.loads((packages[0] / "verdict.json").read_text(encoding="utf-8"))
        assert verdict_data["verdict"] == "proven"
        assert verdict_data["evidence"]["fails_on"] == "vulnerable"
        assert verdict_data["evidence"]["passes_on"] == "fixed"
    else:
        assert not (out / "packages").exists()

    assert not any(_is_pytest_command(cmd) for cmd in forbid_host_test_execution)
