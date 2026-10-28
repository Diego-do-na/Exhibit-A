"""Real pipeline adapter: run the VerificationLoop over one Case and append its events.

This replaces the scripted `bench.synthetic` pipeline when benchmarking real corpora.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from exhibit_a.ledger import Ledger
from exhibit_a.models import ModelRole, Role
from exhibit_a.loop import Roles, VerificationLoop
from exhibit_a.schemas import EventType, Event
from datetime import datetime, timezone
from typing import Any, Iterator


from .corpus import Case
from .flags import Flags

Pipeline = Callable[[Case, Flags, Ledger, str], None]


def _pick_source_file(clone: Path, case: Case) -> str:
    """Choose a source file for the adversary to inspect.

    Prefer the first declared ground_truth file, else `app.py` if present, else
    the first top-level `.py` file in the clone.
    """
    if case.ground_truth:
        return case.ground_truth[0]["file"]
    app = clone / "app.py"
    if app.exists():
        return "app.py"
    for p in clone.iterdir():
        if p.is_file() and p.suffix == ".py":
            return p.name
    # Fallback to the baseline test; VerificationLoop will raise if it cannot read it.
    return "test_baseline.py"


def make_pipeline(provider, *, runner=None) -> Pipeline:
    """Return a pipeline that runs the real VerificationLoop for one Case.

    `provider` is passed to `ModelRole` for every role. An optional `runner`
    (TestRunner) may be injected for tests to avoid the Docker-backed SandboxRunner.
    """

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

        clone = Path(case.repo)
        # The VerificationLoop emits SUSPICION_RAISED events with a nested "suspicion"
        # key; the benchmark metrics expect the suspicion fields at top level. Wrap
        # the ledger to normalize those events when the loop appends them.
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

        proxy_ledger = _ProxyLedger(ledger)
        roles = Roles(
            adversary=ModelRole(Role.ADVERSARY, provider),
            test_writer=ModelRole(Role.TEST_WRITER, provider),
            fixer=ModelRole(Role.FIXER, provider),
            defender=ModelRole(Role.DEFENDER, provider),
        )
        out_dir = ledger.path.parent / "out"
        loop = VerificationLoop(
            clone,
            out_dir,
            proxy_ledger,
            roles,
            "test_baseline.py",
            run_id=run_id,
            runner=runner,
            flags=flags,
        )

        source = _pick_source_file(clone, case)
        loop.run(source)

    return pipeline

