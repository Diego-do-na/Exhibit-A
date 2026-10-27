"""The verification loop: BASELINE, SUSPECT, EXPLOIT, RUN, VERDICT, FIX, VERIFY, PACKAGE.

Every step appends events to the ledger. A suspicion is `proven` only when the exploit test
fails on the vulnerable code with the intended effect and valid provenance, and does so on
every one of N repeated runs. Anything else is dropped with a non-proven verdict, which is
counted. A green result means "nothing could be proven", never "safe".

Execution goes through an injected ``TestRunner`` (see runner.py) so it can be swapped or
faked. The default, ``SandboxRunner``, runs the project's own tests inside the hardened
sandbox with the case's requirements, and exploit tests through the oracle. The older
per-step seams still override one step each:

* ``baseline_runner`` runs the project's own tests;
* ``judge`` runs an exploit test and decides what its failure means.
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import uuid
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from exhibit_a.ledger import Ledger
from exhibit_a.loop import prompts
from exhibit_a.models import ModelRole, RoleResult, SchemaValidationError
from exhibit_a.loop.runner import SandboxRunner, TestRunner
from exhibit_a.oracle import Judgement
from exhibit_a.schemas import (
    BypassAttempts,
    Evidence,
    Event,
    EventType,
    Fix,
    Suspicion,
    Verdict,
    VerdictValue,
)

BaselineRunner = Callable[[str, str, float], dict[str, Any]]
Judge = Callable[..., Judgement]

_MAX_FIX_FILES = 1_000
_MAX_FIX_FILE_BYTES = 1_000_000
_MAX_FIX_TOTAL_BYTES = 10_000_000


@dataclass
class Roles:
    adversary: ModelRole
    test_writer: ModelRole
    fixer: ModelRole
    defender: ModelRole


@dataclass
class SuspicionResult:
    suspicion: Suspicion
    verdict: Verdict
    reason: str
    package_dir: Path | None = None
    fix_verified: bool = False


@dataclass
class LoopResult:
    run_id: str
    baseline_ok: bool
    results: list[SuspicionResult] = field(default_factory=list)
    aborted: str = ""

    @property
    def proven(self) -> list[SuspicionResult]:
        return [r for r in self.results if r.verdict.verdict == VerdictValue.PROVEN]

    @property
    def dropped(self) -> int:
        """Suspicions that ended without proof, whatever the reason."""
        return len(self.results) - len(self.proven)

    def counts(self) -> dict[str, int]:
        counts = {value.value: 0 for value in VerdictValue}
        for r in self.results:
            counts[r.verdict.verdict.value] += 1
        return counts


def classify(judgement: Judgement) -> VerdictValue:
    """Map one oracle judgement to the verdict it supports on its own."""
    outcome = judgement.test_outcome
    if outcome == "failed" and judgement.observed_effect and judgement.provenance_ok:
        return VerdictValue.PROVEN
    if outcome == "passed":
        return VerdictValue.DISCARDED_UNPROVEN  # the suspicion did not materialise
    return VerdictValue.INVALID_TEST  # crashed, hung, wrong-reason failure or cheating


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value).strip(".") or uuid.uuid4().hex[:8]


class VerificationLoop:
    def __init__(
        self,
        clone_path: str | Path,
        out_dir: str | Path,
        ledger: Ledger,
        roles: Roles,
        baseline_test: str | Path,
        *,
        runs: int = 3,
        timeout: float = 60.0,
        run_id: str | None = None,
        runner: TestRunner | None = None,
        requirements: Sequence[str] = (),
        baseline_runner: BaselineRunner | None = None,
        judge: Judge | None = None,
    ) -> None:
        if runs < 1:
            raise ValueError("runs must be at least 1")
        self.clone = Path(clone_path).resolve()
        self.out = Path(out_dir).resolve()
        self.ledger = ledger
        self.roles = roles
        self.baseline_test = str(baseline_test)
        self.runs = runs
        self.timeout = timeout
        self.run_id = run_id or uuid.uuid4().hex[:12]
        # ``requirements`` only shape the default runner; an injected one carries its own.
        self.runner = runner if runner is not None else SandboxRunner(requirements=tuple(requirements))
        self.baseline_runner = baseline_runner or self.runner.run_baseline
        self.judge = judge or self.runner.run_exploit

    # -- ledger -----------------------------------------------------------------------

    def _emit(self, type_: EventType, result: RoleResult | None = None, **payload: Any) -> None:
        usage: dict[str, Any] = {}
        if result is not None:
            usage = {
                "role": result.role.value,
                "model": result.model,
                "tokens_in": result.tokens_in,
                "tokens_out": result.tokens_out,
                "cost_usd": result.cost_usd,
                "latency_ms": result.latency_ms,
            }
        self.ledger.append(
            Event(
                ts=datetime.now(timezone.utc).isoformat(),
                run_id=self.run_id,
                type=type_,
                payload=payload,
                **usage,
            )
        )

    # -- the loop ---------------------------------------------------------------------

    def run(self, source_file: str) -> LoopResult:
        """Run the whole loop over one source file of the clone."""
        result = LoopResult(run_id=self.run_id, baseline_ok=False)

        base = self.baseline_runner(str(self.clone), self.baseline_test, self.timeout)
        result.baseline_ok = base.get("outcome") == "passed"
        self._emit(EventType.BASELINE_DONE, ok=result.baseline_ok, outcome=base.get("outcome"))
        if not result.baseline_ok:
            result.aborted = f"baseline did not pass ({base.get('outcome')})"
            return result

        source = (self.clone / source_file).read_text(encoding="utf-8")
        try:
            raised = self.roles.adversary.run(
                prompts.adversary_prompt(source, source_file), prompts.SUSPICIONS_SCHEMA
            )
        except SchemaValidationError as exc:
            result.aborted = f"adversary output rejected: {exc}"
            return result

        seen: set[str] = set()
        for raw in raised.output["suspicions"]:
            try:
                suspicion = Suspicion.model_validate(raw)
            except ValueError:
                continue  # malformed suspicion: never became a candidate
            if suspicion.id in seen:
                continue
            seen.add(suspicion.id)
            self._emit(EventType.SUSPICION_RAISED, raised, suspicion=json.loads(suspicion.to_json()))
            result.results.append(self._process(suspicion))
        return result

    def _process(self, suspicion: Suspicion) -> SuspicionResult:
        work = self.out / "work" / _slug(suspicion.id)
        work.mkdir(parents=True, exist_ok=True)
        entry_points = {suspicion.entry_point}

        def done(value: VerdictValue, reason: str, evidence: Evidence | None = None) -> SuspicionResult:
            verdict = Verdict(suspicion_id=suspicion.id, verdict=value, evidence=evidence)
            self._emit(EventType.VERDICT, suspicion_id=suspicion.id, verdict=value.value, reason=reason)
            return SuspicionResult(suspicion, verdict, reason)

        # EXPLOIT
        try:
            source = (self.clone / suspicion.location.file).read_text(encoding="utf-8")
            written = self.roles.test_writer.run(
                prompts.writer_prompt(suspicion, source), prompts.EXPLOIT_SCHEMA
            )
        except (SchemaValidationError, OSError, UnicodeDecodeError) as exc:
            return done(VerdictValue.INVALID_TEST, f"no usable exploit test: {exc}")
        exploit_src = written.output["test_source"]
        exploit = work / "test_exploit.py"
        exploit.write_text(exploit_src, encoding="utf-8")
        self._emit(EventType.EXPLOIT_WRITTEN, written, suspicion_id=suspicion.id, test_path=str(exploit))

        # RUN x N, then VERDICT
        judgements: list[Judgement] = []
        for n in range(self.runs):
            self._emit(EventType.RUN_STARTED, suspicion_id=suspicion.id, run=n + 1, of=self.runs)
            try:
                judgement = self.judge(self.clone, exploit, entry_points, timeout=self.timeout)
            except OSError as exc:
                return done(VerdictValue.ENV_FAILURE, f"run {n + 1} could not execute: {exc}")
            judgements.append(judgement)
            for event in judgement.events:
                self._emit(EventType.ORACLE_EVENT, suspicion_id=suspicion.id, run=n + 1, event=event.model_dump())
            if classify(judgement) != VerdictValue.PROVEN:
                break  # nothing to stabilise: a non-proof on any run ends the attempt

        verdicts = [classify(j) for j in judgements]
        if verdicts[0] != VerdictValue.PROVEN:
            return done(verdicts[0], judgements[0].reason)
        if any(v != VerdictValue.PROVEN for v in verdicts):
            bad = next(j for j, v in zip(judgements, verdicts) if v != VerdictValue.PROVEN)
            return done(VerdictValue.FLAKY, f"unstable across runs: {bad.reason}")

        first = judgements[0]
        evidence = Evidence(
            test_path=str(exploit),
            fails_on="vulnerable",
            passes_on="",
            runs=self.runs,
            oracle={"reason": first.reason, "events": [e.model_dump() for e in first.events]},
            provenance={"ok": True, "entry_point": suspicion.entry_point},
        )
        outcome = done(VerdictValue.PROVEN, first.reason, evidence)
        self._fix_verify_package(outcome, source, exploit_src, exploit, entry_points, work)
        return outcome

    # -- FIX, VERIFY, PACKAGE ----------------------------------------------------------

    def _fix_verify_package(
        self,
        outcome: SuspicionResult,
        source: str,
        exploit_src: str,
        exploit: Path,
        entry_points: Collection[str],
        work: Path,
    ) -> None:
        suspicion, verdict = outcome.suspicion, outcome.verdict
        assert verdict.evidence is not None

        patch_text = ""
        fixed = work / "fixed"
        proposal = None
        try:
            proposal = self.roles.fixer.run(
                prompts.fixer_prompt(suspicion, source, exploit_src, outcome.reason), prompts.FIX_SCHEMA
            )
            patch_text = self._apply_fix(proposal.output["files"], fixed)
        except (SchemaValidationError, ValueError) as exc:
            self._emit(EventType.FIX_PROPOSED, suspicion_id=suspicion.id, applied=False, error=str(exc))
        else:
            self._emit(EventType.FIX_PROPOSED, proposal, suspicion_id=suspicion.id, applied=True)

        tried = succeeded = 0
        if patch_text:
            exploit_passes = self._exploit_passes_on_fixed(exploit, fixed, entry_points, suspicion.id)
            baseline = self.baseline_runner(str(fixed), self.baseline_test, self.timeout)
            baseline_ok = baseline.get("outcome") == "passed"
            self._emit(EventType.BASELINE_DONE, suspicion_id=suspicion.id, on="fixed", ok=baseline_ok)
            tried, succeeded = self._defend(suspicion, fixed, exploit_src, entry_points, work)
            outcome.fix_verified = exploit_passes and baseline_ok
            if outcome.fix_verified:
                verdict.evidence.passes_on = "fixed"

        verdict.bypass_attempts = BypassAttempts(tried=tried, succeeded=succeeded)
        outcome.package_dir = self._package(outcome, exploit, patch_text)

    def _apply_fix(self, files: list[dict[str, str]], fixed: Path) -> str:
        """Copy the clone, write the proposed files, return a unified diff."""
        if not files:
            raise ValueError("fixer proposed no files")
        if len(files) > _MAX_FIX_FILES:
            raise ValueError(f"fixer proposed too many files: {len(files)}")
        total_bytes = 0
        for item in files:
            content_bytes = len(item["content"].encode("utf-8"))
            if content_bytes > _MAX_FIX_FILE_BYTES:
                raise ValueError(f"fix content exceeds limit: {item['path']!r}")
            total_bytes += content_bytes
        if total_bytes > _MAX_FIX_TOTAL_BYTES:
            raise ValueError("fix content exceeds total limit")
        clone_root = self.clone.resolve()
        for item in files:
            rel = Path(item["path"])
            if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
                raise ValueError(f"invalid fix path: {item['path']!r}")
            current = self.clone
            for part in rel.parts[:-1]:
                current /= part
                if current.is_symlink():
                    raise ValueError(f"fix path traverses symlink: {item['path']!r}")
                if current.exists() and not current.is_dir():
                    raise ValueError(f"fix path crosses a non-directory: {item['path']!r}")
        if fixed.exists():
            shutil.rmtree(fixed)
        shutil.copytree(self.clone, fixed)
        diffs = []
        for item in files:
            rel = Path(item["path"])
            target = (fixed / rel).resolve()
            if not target.is_relative_to(fixed.resolve()) or not (self.clone / rel).resolve().is_relative_to(clone_root):
                raise ValueError(f"fix path escapes the clone: {item['path']!r}")
            before = (self.clone / rel).read_text(encoding="utf-8") if (self.clone / rel).is_file() else ""
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(item["content"], encoding="utf-8")
            diffs.extend(
                difflib.unified_diff(
                    before.splitlines(keepends=True),
                    item["content"].splitlines(keepends=True),
                    fromfile=f"a/{rel.as_posix()}",
                    tofile=f"b/{rel.as_posix()}",
                )
            )
        return "".join(diffs)

    def _exploit_passes_on_fixed(
        self, exploit: Path, fixed: Path, entry_points: Collection[str], sid: str
    ) -> bool:
        for n in range(self.runs):
            self._emit(EventType.RUN_STARTED, suspicion_id=sid, on="fixed", run=n + 1, of=self.runs)
            try:
                judgement = self.judge(fixed, exploit, entry_points, timeout=self.timeout)
            except OSError:
                return False
            if judgement.test_outcome != "passed":
                return False
        return True

    def _defend(
        self, suspicion: Suspicion, fixed: Path, exploit_src: str, entry_points: Collection[str], work: Path
    ) -> tuple[int, int]:
        """Run the defender's bypass variants against the fixed code: (tried, succeeded)."""
        patched = (fixed / suspicion.location.file).read_text(encoding="utf-8")
        try:
            proposal = self.roles.defender.run(
                prompts.defender_prompt(suspicion, patched, exploit_src), prompts.VARIANTS_SCHEMA
            )
        except SchemaValidationError:
            return 0, 0
        tried = succeeded = 0
        for i, variant in enumerate(proposal.output["variants"]):
            path = work / f"variant_{i}.py"
            path.write_text(variant["test_source"], encoding="utf-8")
            self._emit(
                EventType.BYPASS_ATTEMPT, proposal if i == 0 else None,
                suspicion_id=suspicion.id, name=variant["name"],
            )
            tried += 1
            try:
                judgement = self.judge(fixed, path, entry_points, timeout=self.timeout)
            except OSError:
                self._emit(EventType.BYPASS_RESULT, suspicion_id=suspicion.id, name=variant["name"], bypassed=False, error=True)
                continue
            bypassed = classify(judgement) == VerdictValue.PROVEN
            succeeded += bypassed
            self._emit(EventType.BYPASS_RESULT, suspicion_id=suspicion.id, name=variant["name"], bypassed=bypassed)
        return tried, succeeded

    def _package(self, outcome: SuspicionResult, exploit: Path, patch_text: str) -> Path:
        verdict = outcome.verdict
        pkg = self.out / "packages" / _slug(outcome.suspicion.id)
        pkg.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(exploit, pkg / "test_exploit.py")
        if outcome.fix_verified:
            (pkg / "fix.patch").write_text(patch_text, encoding="utf-8")
            verdict.fix = Fix(patch_path=str(pkg / "fix.patch"))
        if verdict.evidence is not None:
            verdict.evidence.test_path = str(pkg / "test_exploit.py")
        (pkg / "verdict.json").write_text(verdict.model_dump_json(indent=2), encoding="utf-8")
        evidence = {
            "suspicion": json.loads(outcome.suspicion.to_json()),
            "reason": outcome.reason,
            "fix_verified": outcome.fix_verified,
            "bypass_attempts": verdict.bypass_attempts.model_dump() if verdict.bypass_attempts else {},
            "evidence": verdict.evidence.model_dump() if verdict.evidence else {},
        }
        (pkg / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        self._emit(EventType.PACKAGED, suspicion_id=outcome.suspicion.id, path=str(pkg), fix_verified=outcome.fix_verified)
        return pkg
