"""Real pipeline adapter: run the VerificationLoop over one Case and append its events.

The case's source tree is resolved from the case directory (``run.tree``) or by
installing ``run.requirements``; ``repo`` is never treated as a path when it is a
URL. The baseline test, recording and requirements all come from ``case.json``,
and the oracle effect (``canary_read``/``canary_write``) reaches the judge from
``case.json``/``profile.json`` instead of being hard-coded.
"""
from __future__ import annotations

import inspect
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any, Callable, Iterator

from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, SandboxRunner, VerificationLoop
from exhibit_a.models import Completion, ModelRole, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.oracle import run_oracle
from exhibit_a.schemas import Event, EventType
from datetime import datetime, timezone

from .corpus import Case
from .flags import Flags

Pipeline = Callable[[Case, Flags, Ledger, str], None]

#: File the baseline test is staged as inside the clone (the loop convention).
STAGED_BASELINE = "test_baseline.py"

_STAGED_OK = ".staged-ok"


def _looks_like_url(value: str) -> bool:
    return "://" in value


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value).strip(".") or "case"


def _pick_source_file(clone: Path, case: Case) -> str:
    """Choose a source file for the adversary to inspect.

    Prefer the case's declared ``source_file``, else the first declared
    ground-truth file, else ``app.py`` if present, else the first top-level
    ``.py`` file in the clone.
    """
    if case.source_file:
        return case.source_file
    if case.ground_truth:
        return case.ground_truth[0]["file"]
    app = clone / "app.py"
    if app.exists():
        return "app.py"
    for p in sorted(clone.iterdir()):
        if p.is_file() and p.suffix == ".py":
            return p.name
    # Fallback to the baseline test; VerificationLoop will raise if it cannot read it.
    return STAGED_BASELINE


def _install_requirements(target: Path, requirements: Collection[str]) -> None:
    """Install the case's pinned requirements into the staged clone directory."""
    if not requirements:
        return
    cmd = [
        sys.executable, "-m", "pip", "install",
        "--timeout", "10", "--retries", "1",
        "--target", str(target), *requirements,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"pip install timed out after 180s: {exc}") from exc
    if proc.returncode != 0:
        tail = (proc.stderr.strip() or proc.stdout.strip() or "pip install failed")[-2000:]
        raise RuntimeError(f"pip install failed: {tail}")


def _stage_case(case: Case, out_dir: Path) -> Path:
    """Stage a hermetic clone directory for one case and return it.

    The corpus itself is never mutated: a tree directory is copied, otherwise
    the requirements are installed into a fresh directory. Raises
    ``FileNotFoundError``/``RuntimeError`` with a clear message when the source
    cannot be resolved.
    """
    if not case.case_dir:
        clone = Path(case.repo)
        if clone.is_dir():
            return clone
        raise FileNotFoundError(
            f"case {case.id!r}: cannot resolve its source tree: repo {case.repo!r} "
            "is not a local directory (and this case has no case directory with "
            "run.tree to resolve it from)"
        )
    case_dir = Path(case.case_dir)
    clone = out_dir / "clones" / _slug(case.id)
    if (clone / _STAGED_OK).is_file():
        return clone
    if clone.exists():
        shutil.rmtree(clone)
    clone.mkdir(parents=True, exist_ok=True)
    tree_dir = case_dir / case.tree if case.tree else None
    if tree_dir is not None and tree_dir.is_dir():
        shutil.copytree(tree_dir, clone, dirs_exist_ok=True)
    else:
        if not case.requirements:
            detail = (
                f"run.tree {case.tree!r} does not exist under {case_dir}"
                if case.tree
                else f"case.json declares no run.tree under {case_dir}"
            )
            repo_note = f"repo is {case.repo!r} (not a local directory)" if _looks_like_url(case.repo) else f"repo is {case.repo!r}"
            raise FileNotFoundError(
                f"case {case.id!r}: cannot resolve its source tree: {detail}; "
                f"{repo_note}; provide run.tree or run.requirements"
            )
        try:
            _install_requirements(clone, case.requirements)
        except RuntimeError as exc:
            raise RuntimeError(
                f"case {case.id!r}: cannot resolve its source tree: {exc}"
            ) from exc
    baseline_src = case_dir / case.baseline_test
    if not baseline_src.is_file():
        raise FileNotFoundError(
            f"case {case.id!r}: baseline test {case.baseline_test!r} not found in {case_dir}"
        )
    shutil.copyfile(baseline_src, clone / STAGED_BASELINE)
    (clone / _STAGED_OK).write_text("ok\n", encoding="utf-8")
    return clone


def _make_judge(runner: Any, effect: str) -> Callable[..., Any]:
    """Return the loop judge for one case, honouring the case's oracle effect.

    Runners whose ``run_exploit`` accepts an ``effect`` keyword (such as test
    fakes) receive it directly. Otherwise a ``canary_read`` case uses the
    runner as-is, and any other effect falls back to the host oracle with that
    effect: the same judge code and proof standard, host-executed. (The
    sandbox-backed runner only supports the read effect; teaching it the write
    effect is follow-up work outside this adapter.)
    """
    base = runner.run_exploit
    if effect == "canary_read":
        try:
            params = inspect.signature(base).parameters
        except (TypeError, ValueError):
            return base
        if "effect" not in params:
            return base
    else:
        try:
            params = inspect.signature(base).parameters
        except (TypeError, ValueError):
            params = {}
        if "effect" not in params:
            def judge(app_root: Path, test_path: Path, entry_points: Collection[str], *, timeout: float) -> Any:
                return run_oracle(
                    Path(app_root), Path(test_path), set(entry_points),
                    timeout=timeout, effect=effect,  # type: ignore[arg-type]
                )

            return judge
    def judge(app_root: Path, test_path: Path, entry_points: Collection[str], *, timeout: float) -> Any:
        return base(app_root, test_path, entry_points, timeout=timeout, effect=effect)

    return judge


def _tree_relative(location: str, tree: str) -> str:
    """Rewrite a case-relative suspicion path as tree-relative for the loop clone."""
    if tree and location == tree:
        return "."
    if tree and location.startswith(tree + "/"):
        return location[len(tree) + 1:]
    return location


class CaseMaterialsProvider:
    """Deterministic provider built from a case's own materials.

    Used for cases with no replay recording (e.g. the archive-extraction
    case): the adversary answer comes from the case's ``suspicion.json``
    (rewritten tree-relative, as a model inspecting the staged clone would
    report it), the exploit/fix/defender answers from the labelled exploits
    and the fixed tree declared in ``run``. Every answer is case data, never
    a hard-coded effect: the write effect still flows through the judge.
    """

    name = "case-materials"
    pricing = Pricing()

    def __init__(self, case: Case) -> None:
        case_dir = Path(case.case_dir)
        try:
            run = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))["run"]
        except (OSError, ValueError, KeyError) as exc:
            raise ValueError(f"case {case.id!r}: cannot read run section: {exc}") from exc
        try:
            suspicion = json.loads((case_dir / "suspicion.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"case {case.id!r}: cannot read suspicion.json: {exc}") from exc
        suspicion = dict(suspicion)
        location = dict(suspicion.get("location", {}))
        if "file" in location:
            location["file"] = _tree_relative(str(location["file"]), case.tree)
        suspicion["location"] = location
        self._suspicion = suspicion
        self._exploit = self._read_material(case, case_dir, self._pick_exploit(run))
        trees = run.get("trees") or {}
        fixed_tree = trees.get("fixed", "fixed")
        source_file = case.source_file or run.get("source_file", "")
        if not source_file:
            raise ValueError(f"case {case.id!r}: no source_file to build the fixer answer from")
        self._fix_path = source_file
        self._fixed = self._read_material(case, case_dir, f"{fixed_tree}/{source_file}")
        bypass = (run.get("bypass") or {}).get("exploit", "")
        self._variant_name = Path(bypass).stem if bypass else "bypass"
        self._variant = self._read_material(case, case_dir, bypass) if bypass else ""

    @staticmethod
    def _pick_exploit(run: dict[str, Any]) -> str:
        exploits = run.get("exploits") or []
        for item in exploits:
            if isinstance(item, dict) and item.get("label") == "true-exploit":
                return str(item.get("file", ""))
        if exploits and isinstance(exploits[0], dict):
            return str(exploits[0].get("file", ""))
        raise ValueError("no exploits listed in the run section")

    @staticmethod
    def _read_material(case: Case, case_dir: Path, rel: str) -> str:
        if not rel:
            raise ValueError(f"case {case.id!r}: empty material path in run section")
        path = case_dir / rel
        if not path.is_file():
            raise ValueError(f"case {case.id!r}: material {rel!r} not found in {case_dir}")
        return path.read_text(encoding="utf-8")

    def complete(self, role: Role, prompt: str, schema: dict) -> Completion:
        if role == Role.ADVERSARY:
            body = {"suspicions": [self._suspicion]}
        elif role == Role.TEST_WRITER:
            body = {"test_source": self._exploit}
        elif role == Role.FIXER:
            body = {"files": [{"path": self._fix_path, "content": self._fixed}]}
        else:
            variants = (
                [{"name": self._variant_name, "test_source": self._variant}]
                if self._variant
                else []
            )
            body = {"variants": variants}
        return Completion(
            text=json.dumps(body), tokens_in=10, tokens_out=10, latency_ms=1,
            model="case-materials",
        )


def make_pipeline(providers: Any, *, runner: Any = None) -> Pipeline:
    """Return a pipeline that runs the real VerificationLoop for one Case.

    ``providers`` is either a single provider used for every case or a mapping
    of case id to provider. ``runner`` (a TestRunner) may be injected for
    tests to avoid the Docker-backed SandboxRunner; without it each case gets
    a SandboxRunner built from its own ``run.requirements``.
    """

    def provider_for(case: Case) -> Any:
        if isinstance(providers, Mapping):
            try:
                return providers[case.id]
            except KeyError:
                raise KeyError(f"no provider configured for case {case.id!r}") from None
        return providers

    def pipeline(case: Case, flags: Flags, ledger: Ledger, run_id: str) -> None:
        # Announce the PR / case so metrics tooling and consumers see it.
        ledger.append(
            Event(
                ts=datetime.now(timezone.utc).isoformat(),
                run_id=run_id,
                type=EventType.PR_OPENED,
                payload={"case": case.id, "kind": case.kind},
            )
        )

        try:
            out_dir = ledger.path.parent / "out"
            clone = _stage_case(case, out_dir)
            effective_runner = (
                runner
                if runner is not None
                else SandboxRunner(requirements=tuple(case.requirements))
            )
            # The VerificationLoop emits SUSPICION_RAISED events with a nested "suspicion"
            # key; the benchmark metrics expect the suspicion fields at top level. Wrap
            # the ledger to normalize those events when the loop appends them.
            proxy_ledger = _ProxyLedger(ledger)
            roles = Roles(
                adversary=ModelRole(Role.ADVERSARY, provider_for(case)),
                test_writer=ModelRole(Role.TEST_WRITER, provider_for(case)),
                fixer=ModelRole(Role.FIXER, provider_for(case)),
                defender=ModelRole(Role.DEFENDER, provider_for(case)),
            )
            loop = VerificationLoop(
                clone,
                out_dir,
                proxy_ledger,
                roles,
                STAGED_BASELINE,
                run_id=run_id,
                runner=effective_runner,
                requirements=tuple(case.requirements),
                judge=_make_judge(effective_runner, case.effect),
                flags=flags,
            )

            source = _pick_source_file(clone, case)
            loop.run(source)
        except Exception as exc:  # noqa: BLE001 - one broken case must not kill the corpus run
            print(f"bench: case {case.id} failed: {exc}", file=sys.stderr)
            ledger.append(
                Event(
                    ts=datetime.now(timezone.utc).isoformat(),
                    run_id=run_id,
                    type=EventType.BASELINE_DONE,
                    payload={
                        "ok": False,
                        "outcome": f"setup_error: {exc}",
                        "case": case.id,
                    },
                )
            )

    return pipeline


class _ProxyLedger:
    def __init__(self, inner: Ledger):
        self._inner = inner

    @property
    def path(self) -> Path:
        return self._inner.path

    def append(self, event: Event | dict[str, Any]) -> None:  # type: ignore[name-defined]
        ev = event if isinstance(event, Event) else Event.model_validate(event)
        if ev.type == EventType.SUSPICION_RAISED and isinstance(ev.payload, dict) and "suspicion" in ev.payload:
            payload = ev.payload["suspicion"]
            ev = Event(
                ts=ev.ts,
                run_id=ev.run_id,
                type=ev.type,
                role=ev.role,
                model=ev.model,
                tokens_in=ev.tokens_in,
                tokens_out=ev.tokens_out,
                cost_usd=ev.cost_usd,
                latency_ms=ev.latency_ms,
                payload=payload,
            )
        self._inner.append(ev)

    def replay(self, run_id: str) -> Iterator[Event]:
        return self._inner.replay(run_id)

    def totals(self, run_id: str) -> dict[str, Any]:
        return self._inner.totals(run_id)

    def read_all(self) -> list[Event]:
        return self._inner.read_all()
