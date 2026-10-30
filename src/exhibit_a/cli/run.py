"""Implementation of the ``run`` CLI subcommand."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import io
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..ci.summary import build_result
from ..ledger import Ledger, append_run
from ..loop import Roles, SandboxRunner, VerificationLoop
from ..models import BudgetExceeded, CostMeter, ModelError, ModelRole, ReplayProvider, Role
from ..models.config import RoleConfig, build_roles
from ..schemas import Event, EventType, RunRecord, VerdictCounts

#: Provider and model used for live runs when the caller names none. They are
#: dev defaults (a local Ollama model); pass explicit values once the argument
#: parser exposes --provider/--model flags.
LIVE_PROVIDER_DEFAULT = "ollama"
LIVE_MODEL_DEFAULT = "llama3.1:8b"

PR_MAX_FILES = 100
PR_MAX_FILE_BYTES = 1_000_000
PR_MAX_TOTAL_BYTES = 10_000_000
PR_MAX_DIFF_BYTES = 20_000_000


@dataclass(frozen=True)
class DiffEntry:
    status: str
    path: str
    old_path: str | None = None
    binary: bool = False


def _validate_changed_path(raw: str, repo: Path) -> Path:
    """Validate a Git path before it is opened as untrusted PR data."""
    path = Path(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe changed path: {raw!r}")
    candidate = (repo / path)
    resolved_repo = repo.resolve()
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(resolved_repo):
        raise ValueError(f"changed path escapes repository: {raw!r}")
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"changed path is not a regular file: {raw!r}")
    if path.suffix.lower() != ".py":
        raise ValueError(f"changed path is not Python: {raw!r}")
    if candidate.stat().st_size > PR_MAX_FILE_BYTES:
        raise ValueError(f"changed file is too large: {raw!r}")
    try:
        data = candidate.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read changed file {raw!r}: {exc}") from exc
    if b"\x00" in data:
        raise ValueError(f"changed file is binary: {raw!r}")
    return resolved


def _validate_path_shape(raw: str) -> None:
    path = Path(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe changed path: {raw!r}")


def parse_name_status(data: bytes, *, max_bytes: int = PR_MAX_DIFF_BYTES) -> list[DiffEntry]:
    """Parse `git diff --name-status -z` without interpreting PR-controlled text."""
    if len(data) > max_bytes:
        raise ValueError("git diff is too large")
    fields = data.split(b"\0")
    entries: list[DiffEntry] = []
    i = 0
    while i < len(fields) and fields[i]:
        try:
            status = fields[i].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ValueError("git diff contains a non-UTF-8 status") from exc
        i += 1
        if not status or status[0] not in "AMCDRTUXB":
            raise ValueError(f"unsupported git diff status: {status!r}")
        count = 2 if status[0] == "R" or status[0] == "C" else 1
        names: list[str] = []
        for _ in range(count):
            if i >= len(fields) or not fields[i]:
                raise ValueError("truncated git diff name-status record")
            try:
                names.append(fields[i].decode("utf-8", "strict"))
            except UnicodeDecodeError as exc:
                raise ValueError("git diff contains a non-UTF-8 path") from exc
            i += 1
        entries.append(DiffEntry(status[0], names[-1], names[0] if count == 2 else None))
    return entries


def _git_diff(repo: Path, spec: str) -> list[DiffEntry]:
    if spec.count("..") != 1:
        raise ValueError("--pr-diff must be BASE..HEAD")
    base, head = spec.split("..")
    if not base or not head or any(c.isspace() for c in (base + head)):
        raise ValueError("--pr-diff must contain non-empty commit names")
    cmd = [
        "git", "-C", str(repo), "diff", "--name-status", "-z",
        "--no-ext-diff", "--no-textconv", f"{base}..{head}", "--",
    ]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"could not compute PR diff: {exc}") from exc
    if proc.returncode:
        detail = proc.stderr.decode("utf-8", "replace")[-500:]
        raise ValueError(f"could not compute PR diff: {detail}")
    return parse_name_status(proc.stdout)


def _stage_head(repo: Path, head: str, out: Path) -> Path:
    """Materialize exactly HEAD from Git, never the caller's mutable worktree."""
    clone = out / "clone"
    if clone.exists():
        shutil.rmtree(clone)
    clone.mkdir(parents=True)
    proc = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", head],
        check=False, capture_output=True, timeout=60,
    )
    if proc.returncode:
        raise ValueError(f"could not stage head commit: {proc.stderr.decode('utf-8', 'replace')[-500:]}")
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as archive:
        root = clone.resolve()
        for member in archive.getmembers():
            target = (clone / member.name).resolve()
            if not target.is_relative_to(root):
                raise ValueError("Git archive contains a path outside the repository")
            archive.extract(member, clone)
    return clone


def _pr_roles(args: argparse.Namespace) -> Roles:
    recording = getattr(args, "recording", None) or os.environ.get("EXHIBIT_A_REPLAY_RECORDING")
    if not recording:
        raise ValueError("PR-diff runs require --recording or EXHIBIT_A_REPLAY_RECORDING")
    provider = ReplayProvider(recording)
    return Roles(*(ModelRole(role, provider) for role in (
        Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))


def _write_result(out: Path, ledger: Ledger, run_id: str, code: int) -> dict[str, Any]:
    result = build_result(ledger.read_all(), run_id=run_id, engine_exit=code)
    (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _append_run_index(out: Path, result: dict[str, Any], repo: Path, head: str, started: float) -> None:
    verdicts = result["verdicts"]
    status = "completed" if result["status"] == "completed" else "aborted"
    record = RunRecord(
        run_id=result["run_id"], repo=str(repo), commit=head,
        ts=datetime.now(timezone.utc),
        status=status,
        verdict_counts=VerdictCounts(
            proven=int(verdicts.get("proven", 0)),
            discarded_unproven=int(verdicts.get("discarded_unproven", 0)),
            invalid_test=int(verdicts.get("invalid_test", 0)),
            flaky=int(verdicts.get("flaky", 0)),
            env_failure=int(verdicts.get("env_failure", 0)),
        ),
        severity="high" if result["proven"] else None,
        discarded_suspicions=int(result["dropped"]),
        tokens_in=int(result["tokens_in"]), tokens_out=int(result["tokens_out"]),
        cost_usd=float(result["cost_usd"]), duration_s=max(0.0, time.monotonic() - started),
        ledger_path="ledger.jsonl",
    )
    append_run(out / "runs.jsonl", record)


def _run_pr_diff(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not repo.is_dir():
        print(f"run: repository does not exist: {repo}", file=sys.stderr)
        return 2
    started = time.monotonic()
    try:
        spec = str(args.pr_diff)
        head = spec.rsplit("..", 1)[1]
        entries = _git_diff(repo, spec)
        candidates: list[str] = []
        for entry in entries:
            # Deletions have no head file to verify; renames use the new path.
            if entry.status == "D":
                continue
            if entry.status in {"R", "C"}:
                old = entry.old_path or ""
                if old == entry.path:
                    continue
            if entry.path not in candidates:
                candidates.append(entry.path)
        if len(candidates) > PR_MAX_FILES:
            raise ValueError("PR changes too many files")
        changed: list[str] = []
        total = 0
        for path in candidates:
            _validate_path_shape(path)
            if Path(path).suffix.lower() != ".py":
                continue
            changed.append(path)
        if len(changed) > PR_MAX_FILES:
            raise ValueError("PR changes too many Python files")
        clone = _stage_head(repo, head, out)
        safe_changed: list[str] = []
        total = 0
        for path in changed:
            resolved = _validate_changed_path(path, clone)
            total += resolved.stat().st_size
            if total > PR_MAX_TOTAL_BYTES:
                raise ValueError("changed Python files exceed the total size cap")
            safe_changed.append(path)
        changed = safe_changed
        ledger = Ledger(out / "ledger.jsonl")
        run_id = f"pr-{head[:12]}"
        if not changed:
            ledger.append(Event(
                ts=datetime.now(timezone.utc).isoformat(),
                run_id=run_id, type=EventType.SCAN_DONE,
                payload={"status": "not_applicable", "reason": "no changed regular Python files",
                         "entries": len(entries)},
            ))
            result = _write_result(out, ledger, run_id, 0)
            _append_run_index(out, result, repo, head, started)
            return 0
        roles = _pr_roles(args) if args.replay else _live_roles(args, _cost_meter(args))
        runner = SandboxRunner()
        baseline = "."
        any_proven = False
        incomplete = False
        for source in changed:
            loop = VerificationLoop(
                clone, out, ledger, roles, baseline, run_id=run_id,
                runner=runner, prompt_profile=_profile(args),
            )
            try:
                result_loop = loop.run(source)
            except (BudgetExceeded, ModelError, OSError) as exc:
                print(f"run: PR-diff incomplete: {exc}", file=sys.stderr)
                incomplete = True
                break
            any_proven = any_proven or bool(result_loop.proven)
            incomplete = incomplete or bool(result_loop.aborted)
        code = 20 if incomplete else (10 if any_proven else 0)
        result = _write_result(out, ledger, run_id, code)
        _append_run_index(out, result, repo, head, started)
        print(json.dumps({"status": result["status"], "proven": result["proven"]}, sort_keys=True))
        return code
    except ValueError as exc:
        print(f"run: invalid PR diff: {exc}", file=sys.stderr)
        return 2


def _live_roles(args: argparse.Namespace, meter: CostMeter | None) -> Roles:
    """Build one role per model backend through the provider registry.

    The provider/model pair comes from the parsed args when present and falls
    back to the dev defaults otherwise, so this keeps working before and after
    the parser gains explicit flags. Every role shares one cost meter, which
    enforces the --budget-usd hard stop.
    """
    # Precedence: explicit CLI flags > environment variables > built-in defaults.
    provider_name = getattr(args, "provider", None)
    if not provider_name:
        provider_name = os.environ.get("EXHIBIT_A_PROVIDER") or LIVE_PROVIDER_DEFAULT
    model = getattr(args, "model", None)
    if not model:
        model = os.environ.get("EXHIBIT_A_MODEL") or LIVE_MODEL_DEFAULT
    config = {
        role: RoleConfig(provider=provider_name, model=model, **_generation(args, role))
        for role in Role
    }
    by_role = build_roles(config, meter)
    return Roles(
        by_role[Role.ADVERSARY],
        by_role[Role.TEST_WRITER],
        by_role[Role.FIXER],
        by_role[Role.DEFENDER],
    )


#: Output-token ceilings per role for --profile compact. They are ceilings, not targets:
#: reasoning tokens count against them, so they stay well above a normal answer.
COMPACT_MAX_OUTPUT_TOKENS: dict[Role, int] = {
    Role.ADVERSARY: 6000,
    Role.TEST_WRITER: 8000,
    Role.FIXER: 6000,
    Role.DEFENDER: 10000,
}


def _profile(args: argparse.Namespace) -> str:
    return getattr(args, "profile", None) or "standard"


def _generation(args: argparse.Namespace, role: Role) -> dict[str, object]:
    """Reasoning effort and output cap for one role (explicit flags win over the profile)."""
    compact = _profile(args) == "compact"
    effort = getattr(args, "reasoning_effort", None) or ("minimal" if compact else "")
    cap = getattr(args, "max_output_tokens", None)
    if cap is None:
        cap = COMPACT_MAX_OUTPUT_TOKENS[role] if compact else 0
    if cap < 0:
        raise ValueError("--max-output-tokens must be >= 0")
    return {"reasoning_effort": effort, "max_output_tokens": cap}


def _cost_meter(args: argparse.Namespace) -> CostMeter | None:
    """Wrap --budget-usd in a CostMeter; None means spending is unbounded."""
    if args.budget_usd is None:
        return None
    return CostMeter(args.budget_usd)


def _local_baseline(clone: str, test_path: str, timeout: float) -> dict[str, Any]:
    """Run the project's own tests in a scrubbed child process on the host."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": clone,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path]
    try:
        proc = subprocess.run(cmd, cwd=clone, env=env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {
            "outcome": "timeout",
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "oracle_events": [],
        }
    return {
        "outcome": "passed" if proc.returncode == 0 else "failed",
        "exit_code": proc.returncode,
        "stdout": proc.stdout.decode(errors="replace"),
        "stderr": proc.stderr.decode(errors="replace"),
        "oracle_events": [],
    }


def _install_requirements(target: Path, requirements: list[str]) -> None:
    """Install the case's pinned dependencies into a local app root for the host and sandbox."""
    # This helper is kept for backwards-compatibility but must not leak host secrets.
    # Prefer installing inside the sandbox (SandboxRunner) instead of running pip on the host.
    if not requirements:
        return
    from ..install import safe_pip_install

    safe_pip_install(target=str(target), requirements=requirements)


def _run_case(args: argparse.Namespace) -> int:
    """Run the verification loop on one benchmark case.

    With --replay the roles answer from the case recording; without it they
    call real providers (built through the provider registry) and every test
    runs in the sandbox-backed runner.
    """
    if os.environ.get("GITHUB_ACTIONS") and not args.replay:
        print("run: --case requires --replay; live case execution is disabled", file=sys.stderr)
        return 2
    case_file = Path(args.case)
    if case_file.is_dir():
        case_file /= "case.json"
    try:
        spec = json.loads(case_file.read_text(encoding="utf-8"))
        settings = spec["run"]
        case_id = spec["cases"][0]["id"]
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f"run: cannot read case {case_file}: {exc}", file=sys.stderr)
        return 1
    root = case_file.parent
    out = Path(args.out).resolve()
    clone = out / "clone"
    if clone.exists():
        shutil.rmtree(clone)
    clone.mkdir(parents=True, exist_ok=True)
    # Support either a single "tree" key or the newer "trees" mapping.
    if "trees" in settings and isinstance(settings["trees"], dict):
        tree_name = settings["trees"].get("vulnerable") or next(iter(settings["trees"].values()))
        source_tree = root / tree_name
    else:
        source_tree = root / settings.get("tree", ".")
    if source_tree.exists():
        shutil.copytree(source_tree, clone, dirs_exist_ok=True)
    requirements = [str(item) for item in settings.get("requirements", [])]
    if requirements:
        try:
            _install_requirements(clone, requirements)
        except RuntimeError as exc:
            print(f"run: cannot install case requirements: {exc}", file=sys.stderr)
            return 1
    shutil.copyfile(root / settings["baseline_test"], clone / "test_baseline.py")

    ledger = Ledger(out / "ledger.jsonl")
    if args.replay:
        if "recording" in settings:
            provider = ReplayProvider(root / settings["recording"])
        else:
            # A case without a recording (archive extraction) answers from its own labelled
            # materials, the same deterministic provider the benchmark uses for it.
            try:
                from bench.corpus import load_corpus
                from bench.loop_pipeline import CaseMaterialsProvider

                provider = CaseMaterialsProvider(load_corpus(case_file)[0])
            except (ImportError, ValueError, OSError, IndexError) as exc:
                print(f"run: case {case_file} has no replay recording and its materials "
                      f"cannot be used: {exc}", file=sys.stderr)
                return 1
        roles = Roles(*(ModelRole(r, provider) for r in (
            Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
        loop = VerificationLoop(
            clone, out, ledger, roles, "test_baseline.py",
            run_id=case_id, baseline_runner=_local_baseline,
            requirements=requirements,
            effect=settings.get("effect", "canary_read"),
            prompt_profile=_profile(args),
        )
    else:
        try:
            meter = _cost_meter(args)
        except ValueError as exc:
            print(f"run: invalid --budget-usd: {exc}", file=sys.stderr)
            return 1
        try:
            roles = _live_roles(args, meter)
        except ValueError as exc:
            print(f"run: cannot build live roles: {exc}", file=sys.stderr)
            return 1
        loop = VerificationLoop(
            clone, out, ledger, roles, "test_baseline.py",
            run_id=case_id,
            runner=SandboxRunner(
                requirements=tuple(settings.get("requirements", ()))
            ),
            requirements=tuple(settings.get("requirements", ())),
            effect=settings.get("effect", "canary_read"),
            prompt_profile=_profile(args),
        )
    try:
        result = loop.run(settings["source_file"])
    except BudgetExceeded as exc:
        # The ledger appends every event with fsync, so events emitted
        # before the abort are already on disk; report and exit non-zero.
        print(f"run: budget exceeded: {exc}", file=sys.stderr)
        return 1
    except ModelError as exc:
        print(f"run: model step failed: {exc}", file=sys.stderr)
        return 1
    if result.aborted:
        print(f"run: aborted: {result.aborted}", file=sys.stderr)
        return 1

    print(f"run {result.run_id}: {json.dumps(result.counts())} dropped={result.dropped}")
    totals = ledger.totals(result.run_id)
    print(f"run {result.run_id} totals: {json.dumps(totals, sort_keys=True)}")
    packaged = [r for r in result.proven if r.package_dir is not None]
    for r in packaged:
        print(f"PACKAGE {r.package_dir} fix_verified={r.fix_verified}")
    print(f"ledger {out / 'ledger.jsonl'}")
    return 0 if any(r.fix_verified for r in packaged) else 1


def cmd_run(args: argparse.Namespace) -> int:
    """Run a benchmark case or a bounded PR-diff verification."""
    if _profile(args) == "compact" and getattr(args, "replay", False):
        # Replay keys hash the prompt and schema (models/replay.py); every recording was
        # made with the standard profile, so compact prompts can never hit them.
        print("run: --profile compact cannot be combined with --replay "
              "(the recordings were made with the standard profile)", file=sys.stderr)
        return 2
    if args.case:
        return _run_case(args)
    if getattr(args, "pr_diff", None):
        return _run_pr_diff(args)
    print(
        f"run: the core loop is not wired yet "
        f"(repo={args.repo!r}, diff={args.diff!r}, "
        f"replay={args.replay!r}, budget_usd={args.budget_usd!r})"
    )
    return 0
