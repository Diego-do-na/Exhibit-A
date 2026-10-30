"""The verification loop: BASELINE, SUSPECT, EXPLOIT, RUN, VERDICT, FIX, VERIFY, PACKAGE.

Every step appends events to the ledger. A suspicion is `proven` only when the exploit test
fails on the vulnerable code with the intended effect and valid provenance, and does so on
every one of N repeated runs. Anything else is dropped with a non-proven verdict, which is
counted. A green result means "nothing could be proven", never "safe".

Execution goes through an injected ``TestRunner`` (see runner.py) so it can be swapped or
faked. The default, ``SandboxRunner``, runs the project's own tests, the exploit runs on the
vulnerable and fixed code, and the defender's bypass variants inside the isolated,
resource-limited sandbox with the case's requirements; the oracle judges the events
collected from inside the container. A sandbox that cannot run at all surfaces as
``OSError`` and becomes ``env_failure``. The older per-step seams still override one step
each:

* ``baseline_runner`` runs the project's own tests;
* ``judge`` runs an exploit test and decides what its failure means.

Every verification module sits behind a flag so the loop can be ablated (SPEC section 11),
with the same switches as ``bench/flags.py``: ``naive`` reports every suspicion without any
exploit or verdict, ``oracle`` off accepts a plain failing test, ``differential`` off skips
the exploit re-run on the fixed code, and ``defender`` off skips the bypass variants. Only the
full system (the default) meets the proof standard; the others exist to be measured.
"""

from __future__ import annotations

import difflib
import json
import json
import re
import shutil
import uuid
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

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
_MAX_FIX_EDITS = 10


class LoopFlags(Protocol):
    """Ablation switches; ``bench.flags.Flags`` satisfies this as it is."""

    @property
    def naive(self) -> bool: ...  # report every suspicion: no exploit test, no verdicts

    @property
    def oracle(self) -> bool: ...  # the exploit must fail for the intended reason

    @property
    def differential(self) -> bool: ...  # the exploit must pass again after the fix

    @property
    def defender(self) -> bool: ...  # the defender tries bypass variants of the fix


@dataclass(frozen=True)
class FullSystem:
    """Every module switched on: the only setting that meets the proof standard."""

    naive: bool = False
    oracle: bool = True
    differential: bool = True
    defender: bool = True


def _flags_payload(flags: LoopFlags) -> dict[str, bool]:
    return {
        "naive": flags.naive,
        "oracle": flags.oracle,
        "differential": flags.differential,
        "defender": flags.defender,
    }


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
    # A bypass variant still proves the flaw against the fixed code. The verdict
    # stays `proven` (SPEC section 4 condition 5: the surviving one is reported).
    fix_incomplete: bool = False


@dataclass
class LoopResult:
    run_id: str
    baseline_ok: bool
    results: list[SuspicionResult] = field(default_factory=list)
    aborted: str = ""
    naive: bool = False
    suspicions: list[Suspicion] = field(default_factory=list)  # every valid one raised

    @property
    def reported(self) -> list[Suspicion]:
        """What this run reports: every suspicion when naive, otherwise only proven ones."""
        if self.naive:
            return list(self.suspicions)
        return [r.suspicion for r in self.proven]

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


def classify(judgement: Judgement, *, oracle: bool = True) -> VerdictValue:
    """Map one oracle judgement to the verdict it supports on its own.

    With ``oracle`` off (an ablation) any plain test failure counts, whatever its reason.
    """
    outcome = judgement.test_outcome
    if not oracle and outcome == "failed":
        return VerdictValue.PROVEN
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
        flags: LoopFlags | None = None,
        effect: str = "canary_read",
        prompt_profile: str = "standard",
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
        # The judge is a callable that must accept the `effect` keyword so the loop
        # can call it uniformly as `self.judge(..., effect=self.effect)`.
        self.judge = judge or self.runner.run_exploit
        self.flags: LoopFlags = flags if flags is not None else FullSystem()
        # Which oracle effect the judge proves ("canary_read" or "canary_write").
        # Recorded on the verdict payload (audit F7); the signed oracle-event
        # channel itself is unchanged.
        self.effect = effect
        # Which prompt builders and output schemas the roles get ("standard" or "compact").
        # The standard profile is the one every recorded replay key was made with.
        self.prompts = prompts.profile(prompt_profile)
        # Packages the sandbox installs for this case; the compact contract lists them so a
        # model does not write tests that die on an import the sandbox never provides.
        self.requirements = tuple(requirements)

    def _classify(self, judgement: Judgement) -> VerdictValue:
        return classify(judgement, oracle=self.flags.oracle)

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
        result = LoopResult(run_id=self.run_id, baseline_ok=False, naive=self.flags.naive)

        base = self.baseline_runner(str(self.clone), self.baseline_test, self.timeout)
        result.baseline_ok = base.get("outcome") == "passed"
        self._emit(
            EventType.BASELINE_DONE, ok=result.baseline_ok, outcome=base.get("outcome"),
            flags=_flags_payload(self.flags),
        )
        if not result.baseline_ok:
            result.aborted = f"baseline did not pass ({base.get('outcome')})"
            return result

        source = (self.clone / source_file).read_text(encoding="utf-8")
        try:
            raised = self.roles.adversary.run(
                self.prompts.adversary_prompt(source, source_file), self.prompts.suspicions_schema
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
            result.suspicions.append(suspicion)
            if not self.flags.naive:  # naive reports what was raised: no exploit, no verdict
                result.results.append(self._process(suspicion))
        return result

    def _process(self, suspicion: Suspicion) -> SuspicionResult:
        work = self.out / "work" / _slug(suspicion.id)
        # The exploit and the bypass variants live in work/tests/, a sibling of
        # work/fixed: the judge lets the test directory win over the app root,
        # so tests staged inside the same directory as the fixed tree would
        # label every app frame as test code and no bypass could ever be proven.
        tests_dir = work / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        entry_points = {suspicion.entry_point}

        def done(
            value: VerdictValue,
            reason: str,
            evidence: Evidence | None = None,
            *,
            reason_code: str = "",
            fix_verified: bool = False,
            fix_incomplete: bool = False,
            tried: int = 0,
            succeeded: int = 0,
            fix_detail: str = "",
        ) -> SuspicionResult:
            verdict = Verdict(
                suspicion_id=suspicion.id,
                verdict=value,
                evidence=evidence,
                bypass_attempts=BypassAttempts(tried=tried, succeeded=succeeded),
            )
            self._emit(
                EventType.VERDICT,
                suspicion_id=suspicion.id,
                verdict=value.value,
                reason=reason,
                reason_code=reason_code,
                effect=self.effect,
                fix_verified=fix_verified,
                fix_incomplete=fix_incomplete,
                fix_detail=fix_detail,
            )
            return SuspicionResult(suspicion, verdict, reason, fix_verified=fix_verified,
                                   fix_incomplete=fix_incomplete)

        # EXPLOIT
        try:
            source = (self.clone / suspicion.location.file).read_text(encoding="utf-8")
            written = self.roles.test_writer.run(
                self.prompts.writer_prompt(suspicion, source, **self._contract()),
                self.prompts.exploit_schema,
            )
        except (SchemaValidationError, OSError, UnicodeDecodeError) as exc:
            return done(VerdictValue.INVALID_TEST, f"no usable exploit test: {exc}",
                        reason_code="no_usable_exploit")
        exploit_src = written.output["test_source"]
        exploit = tests_dir / "test_exploit.py"
        exploit.write_text(exploit_src, encoding="utf-8")
        self._emit(EventType.EXPLOIT_WRITTEN, written, suspicion_id=suspicion.id, test_path=str(exploit))

        # RUN x N: a stable proof on the vulnerable code is necessary but not
        # sufficient; the single VERDICT event is emitted only after FIX/VERIFY.
        judgements: list[Judgement] = []
        for n in range(self.runs):
            self._emit(EventType.RUN_STARTED, suspicion_id=suspicion.id, run=n + 1, of=self.runs)
            try:
                judgement = self.judge(self.clone, exploit, entry_points, timeout=self.timeout, effect=self.effect)
            except OSError as exc:
                return done(VerdictValue.ENV_FAILURE, f"run {n + 1} could not execute: {exc}",
                            reason_code="run_error")
            judgements.append(judgement)
            for event in judgement.events:
                self._emit(EventType.ORACLE_EVENT, suspicion_id=suspicion.id, run=n + 1, event=event.model_dump())
            if self._classify(judgement) != VerdictValue.PROVEN:
                break  # nothing to stabilise: a non-proof on any run ends the attempt

        verdicts = [self._classify(j) for j in judgements]
        if verdicts[0] != VerdictValue.PROVEN:
            return done(verdicts[0], judgements[0].reason, reason_code=judgements[0].reason_code)
        if any(v != VerdictValue.PROVEN for v in verdicts):
            bad = next(j for j, v in zip(judgements, verdicts) if v != VerdictValue.PROVEN)
            return done(VerdictValue.FLAKY, f"unstable across runs: {bad.reason}",
                        reason_code=bad.reason_code)

        first = judgements[0]
        evidence = Evidence(
            test_path=str(exploit),
            fails_on="vulnerable",
            passes_on="",
            runs=self.runs,
            oracle={
                "reason": first.reason,
                "reason_code": first.reason_code,
                "effect": self.effect,
                "events": [e.model_dump() for e in first.events],
                "checked": self.flags.oracle,
            },
            provenance={
                "ok": first.provenance_ok,
                "checked": self.flags.oracle,
                "entry_point": suspicion.entry_point,
            },
        )

        # FIX / VERIFY / DEFEND run before the verdict, so SPEC section 4
        # condition 5 gates every `proven`.
        patch_text, fix_verified, tried, succeeded, fix_detail = self._verify_fix(
            suspicion, source, exploit_src, first.reason, exploit, entry_points, work, tests_dir
        )
        if fix_verified:
            evidence.passes_on = "fixed"
        fix_incomplete = succeeded > 0
        # Ablations that skip verification cannot show the fix works; they keep
        # their measured semantics and are marked ablated by the run flags.
        verify_gates = self.flags.oracle and self.flags.differential
        if verify_gates and not fix_verified:
            return done(
                VerdictValue.DISCARDED_UNPROVEN,
                "exploit proven but no verified fix",
                evidence,
                reason_code=first.reason_code,
                tried=tried,
                succeeded=succeeded,
                fix_detail=fix_detail,
            )
        outcome = done(
            VerdictValue.PROVEN,
            first.reason,
            evidence,
            reason_code=first.reason_code,
            fix_verified=fix_verified,
            fix_incomplete=fix_incomplete,
            tried=tried,
            succeeded=succeeded,
            fix_detail=fix_detail,
        )
        outcome.package_dir = self._package(outcome, exploit, patch_text)
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
        """Legacy seam: fix, verify and package an already-judged outcome.

        New code runs `_verify_fix` before emitting the verdict instead; this
        wrapper keeps the seam used by tests that drive the fix stage directly.
        """
        suspicion, verdict = outcome.suspicion, outcome.verdict
        assert verdict.evidence is not None
        tests_dir = work / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        patch_text, fix_verified, tried, succeeded, _ = self._verify_fix(
            suspicion, source, exploit_src, outcome.reason, exploit, entry_points, work, tests_dir
        )
        outcome.fix_verified = fix_verified
        outcome.fix_incomplete = succeeded > 0
        if fix_verified:
            verdict.evidence.passes_on = "fixed"

        verdict.bypass_attempts = BypassAttempts(tried=tried, succeeded=succeeded)
        outcome.package_dir = self._package(outcome, exploit, patch_text)

    def _verify_fix(
        self,
        suspicion: Suspicion,
        source: str,
        exploit_src: str,
        proof_reason: str,
        exploit: Path,
        entry_points: Collection[str],
        work: Path,
        tests_dir: Path,
    ) -> tuple[str, bool, int, int, str]:
        """Propose a fix and check it: (patch, fix_verified, tried, succeeded, detail).

        Emits the FIX_PROPOSED, fixed-code RUN_STARTED, BASELINE_DONE and
        bypass events, but never the verdict: the caller emits the single
        VERDICT event after this returns.
        """
        patch_text = ""
        fixed = work / "fixed"
        proposal = None
        try:
            proposal = self.roles.fixer.run(
                self.prompts.fixer_prompt(suspicion, source, exploit_src, proof_reason),
                self.prompts.fix_schema,
            )
            if self.prompts.fix_format == "edits":
                files = self._edits_to_files(proposal.output["edits"])
            else:
                files = proposal.output["files"]
            patch_text = self._apply_fix(files, fixed)
        except (SchemaValidationError, ValueError) as exc:
            self._emit(EventType.FIX_PROPOSED, suspicion_id=suspicion.id, applied=False, error=str(exc))
            return "", False, 0, 0, f"no usable fix: {exc}"
        else:
            self._emit(EventType.FIX_PROPOSED, proposal, suspicion_id=suspicion.id, applied=True)

        tried = succeeded = 0
        if patch_text:
            # Without differential verification nothing shows the fix stops the exploit.
            exploit_passes = self.flags.differential and self._exploit_passes_on_fixed(
                exploit, fixed, entry_points, suspicion.id
            )
            baseline = self.baseline_runner(str(fixed), self.baseline_test, self.timeout)
            baseline_ok = baseline.get("outcome") == "passed"
            self._emit(EventType.BASELINE_DONE, suspicion_id=suspicion.id, on="fixed", ok=baseline_ok)
            if self.flags.defender:
                tried, succeeded = self._defend(suspicion, fixed, exploit_src, entry_points, tests_dir)
            fix_verified = exploit_passes and baseline_ok
            if not self.flags.differential:
                detail = "differential verification off: the exploit was not re-run on the fixed code"
            elif not exploit_passes:
                detail = "the exploit does not pass on the fixed code"
            elif not baseline_ok:
                detail = "the fixed baseline does not pass"
            else:
                detail = ""
            return patch_text, fix_verified, tried, succeeded, detail
        return "", False, 0, 0, "the fixer proposed an empty patch"

    def _contract(self) -> dict[str, str]:
        """``contract=`` for profiles whose test prompts spell out the proof contract."""
        if not self.prompts.takes_contract:
            return {}
        return {"contract": prompts.test_contract(self.effect, self.requirements)}

    def _edits_to_files(self, edits: list[dict[str, str]]) -> list[dict[str, str]]:
        """Turn compact search/replace edits into whole files for ``_apply_fix``.

        Model output is untrusted. An edit may only change an existing regular file of the
        clone (no new files, no symlinks), and its ``find`` text must occur exactly once in
        that file as it stands after the earlier edits. Path containment, symlink and size
        checks are then repeated by ``_apply_fix`` on the resulting files.
        """
        if not edits:
            raise ValueError("fixer proposed no edits")
        if len(edits) > _MAX_FIX_EDITS:
            raise ValueError(f"fixer proposed too many edits: {len(edits)}")
        clone_root = self.clone.resolve()
        contents: dict[str, str] = {}
        order: list[str] = []
        for edit in edits:
            raw, find, replace = edit["path"], edit["find"], edit["replace"]
            rel = Path(raw)
            if not raw or rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
                raise ValueError(f"invalid fix path: {raw!r}")
            # Key by the normalised path, so "app.py" and "./app.py" are one file whose
            # edits apply in order, never two copies where the last one wins.
            path = rel.as_posix()
            if path not in contents:
                current = self.clone
                for part in rel.parts:
                    current /= part
                    if current.is_symlink():
                        raise ValueError(f"fix path traverses symlink: {path!r}")
                if not current.is_file() or not current.resolve().is_relative_to(clone_root):
                    raise ValueError(f"edit target is not an existing file of the clone: {path!r}")
                try:
                    contents[path] = current.read_text(encoding="utf-8")
                except OSError as exc:  # UnicodeDecodeError is already a ValueError
                    raise ValueError(f"cannot read edit target {path!r}: {exc}") from exc
                order.append(path)
            if not find:
                raise ValueError(f"edit for {path!r} has an empty find text")
            occurrences = contents[path].count(find)
            if occurrences != 1:
                raise ValueError(f"edit find text occurs {occurrences} times in {path!r}, expected exactly 1")
            contents[path] = contents[path].replace(find, replace, 1)
        return [{"path": path, "content": contents[path]} for path in order]

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
                judgement = self.judge(fixed, exploit, entry_points, timeout=self.timeout, effect=self.effect)
            except OSError:
                return False
            if judgement.test_outcome != "passed":
                return False
        return True

    def _defend(
        self, suspicion: Suspicion, fixed: Path, exploit_src: str, entry_points: Collection[str], tests_dir: Path
    ) -> tuple[int, int]:
        """Run the defender's bypass variants against the fixed code: (tried, succeeded)."""
        patched = (fixed / suspicion.location.file).read_text(encoding="utf-8")
        try:
            proposal = self.roles.defender.run(
                self.prompts.defender_prompt(suspicion, patched, exploit_src, **self._contract()),
                self.prompts.variants_schema,
            )
        except SchemaValidationError:
            return 0, 0
        tried = succeeded = 0
        for i, variant in enumerate(proposal.output["variants"]):
            path = tests_dir / f"variant_{i}.py"
            path.write_text(variant["test_source"], encoding="utf-8")
            self._emit(
                EventType.BYPASS_ATTEMPT, proposal if i == 0 else None,
                suspicion_id=suspicion.id, name=variant["name"],
            )
            tried += 1
            try:
                judgement = self.judge(fixed, path, entry_points, timeout=self.timeout, effect=self.effect)
            except OSError:
                self._emit(EventType.BYPASS_RESULT, suspicion_id=suspicion.id, name=variant["name"], bypassed=False, error=True)
                continue
            bypassed = self._classify(judgement) == VerdictValue.PROVEN
            succeeded += bypassed
            self._emit(EventType.BYPASS_RESULT, suspicion_id=suspicion.id, name=variant["name"], bypassed=bypassed)
        return tried, succeeded

    def _package(self, outcome: SuspicionResult, exploit: Path, patch_text: str) -> Path:
        verdict = outcome.verdict
        pkg = self.out / "packages" / _slug(outcome.suspicion.id)
        pkg.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(exploit, pkg / "test_exploit.py")
        source = (self.clone / outcome.suspicion.location.file).read_text(encoding="utf-8")
        # Paths inside the package are relative to the package dir so it can be moved or shared.
        if outcome.fix_verified:
            (pkg / "fix.patch").write_text(patch_text, encoding="utf-8")
            verdict.fix = Fix(patch_path="fix.patch")
        if verdict.evidence is not None:
            verdict.evidence.test_path = "test_exploit.py"
        roots = [str(self.out), str(self.clone)]
        verdict_json = _portable(verdict.model_dump(mode="json"), roots)
        (pkg / "verdict.json").write_text(json.dumps(verdict_json, indent=2), encoding="utf-8")
        evidence = {
            "suspicion": json.loads(outcome.suspicion.to_json()),
            "suspicious_code": {
                "file": outcome.suspicion.location.file,
                "line": outcome.suspicion.location.line,
                "content": source,
            },
            "reason": outcome.reason,
            "fix_verified": outcome.fix_verified,
            "fix_incomplete": outcome.fix_incomplete,
            "flags": _flags_payload(self.flags),
            "bypass_attempts": verdict_json.get("bypass_attempts") or {},
            "evidence": verdict_json.get("evidence") or {},
            "discarded_suspicions": sum(
                1 for event in self.ledger.replay(self.run_id)
                if event.type == EventType.VERDICT and event.payload.get("verdict") != VerdictValue.PROVEN.value
            ),
            "usage": self.ledger.totals(self.run_id),
        }
        (pkg / "evidence.json").write_text(json.dumps(_portable(evidence, roots), indent=2), encoding="utf-8")
        self._emit(EventType.PACKAGED, suspicion_id=outcome.suspicion.id, path=str(pkg.relative_to(self.out)), fix_verified=outcome.fix_verified, fix_incomplete=outcome.fix_incomplete)
        return pkg


def _portable(value, roots: list[str]):
    """Strip host directory prefixes (longest first) from every string in a JSON-like value."""
    prefixes = sorted((r.rstrip("/") + "/" for r in roots), key=len, reverse=True)
    home = str(Path.home()).rstrip("/") + "/"

    def scrub(item):
        if isinstance(item, str):
            for prefix in prefixes:
                item = item.replace(prefix, "")
            return item.replace(home, "~/")
        if isinstance(item, list):
            return [scrub(i) for i in item]
        if isinstance(item, dict):
            return {k: scrub(v) for k, v in item.items()}
        return item

    return scrub(value)
