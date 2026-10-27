"""A scripted stand-in pipeline for tests.

It exercises the harness, the ledger and the model-role plumbing. It does NOT verify
anything: the outcome of each exploit run is scripted in the corpus file, so its numbers
say nothing about the real system and must never appear in a benchmark or demo.
"""

import json
import re
from datetime import datetime, timezone
from typing import Any

from exhibit_a.ledger import Ledger
from exhibit_a.models import Completion, ModelRole, Pricing, Provider, Role
from exhibit_a.schemas import Event, EventType, Suspicion

from .corpus import Case
from .flags import Flags

PRICING = Pricing(input_per_mtok=1.0, output_per_mtok=2.0)
_USAGE = {  # (tokens_in, tokens_out) per call
    Role.ADVERSARY: (400, 200),
    Role.TEST_WRITER: (300, 150),
    Role.DEFENDER: (200, 100),
}
_SCHEMAS = {
    Role.ADVERSARY: {"type": "object", "required": ["suspicions"]},
    Role.TEST_WRITER: {"type": "object", "required": ["test"]},
    Role.DEFENDER: {"type": "object", "required": ["variants"]},
}


class ScriptedProvider:
    """Answers from the corpus script. Prompts carry ``case=<id>`` and ``suspicion=<id>``."""

    name = "scripted"
    pricing = PRICING

    def __init__(self, corpus: list[Case]) -> None:
        self._cases = {case.id: case for case in corpus}

    def complete(self, role: Role, prompt: str, schema: dict[str, Any]) -> Completion:
        case = self._cases[re.search(r"case=(\S+)", prompt).group(1)]
        if role == Role.ADVERSARY:
            body: dict[str, Any] = {"suspicions": [s["suspicion"] for s in _script(case)]}
        elif role == Role.TEST_WRITER:
            body = {"test": "def test_exploit(): ..."}
        else:
            body = {"variants": ["variant-1"]}
        tokens_in, tokens_out = _USAGE[role]
        return Completion(
            text=json.dumps(body),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=1,
            model="scripted",
            cost_usd=PRICING.cost(tokens_in, tokens_out),
        )


def _script(case: Case) -> list[dict[str, Any]]:
    return case.synthetic.get("suspicions", [])


def _emit(ledger: Ledger, run_id: str, event_type: EventType, result=None, **payload: Any) -> None:
    ledger.append(
        Event(
            ts=datetime.now(timezone.utc).isoformat(),
            run_id=run_id,
            type=event_type,
            role=str(result.role) if result else "",
            model=result.model if result else "",
            tokens_in=result.tokens_in if result else 0,
            tokens_out=result.tokens_out if result else 0,
            cost_usd=result.cost_usd if result else 0.0,
            latency_ms=result.latency_ms if result else 0,
            payload=payload,
        )
    )


def make_pipeline(provider: Provider):
    """Build a pipeline that routes every model call through `provider` (e.g. replay)."""

    def role(name: Role) -> ModelRole:
        return ModelRole(name, provider)

    def pipeline(case: Case, flags: Flags, ledger: Ledger, run_id: str) -> None:
        _emit(ledger, run_id, EventType.PR_OPENED, case=case.id, kind=case.kind)
        found = role(Role.ADVERSARY).run(
            f"case={case.id}\nlist suspicions", _SCHEMAS[Role.ADVERSARY]
        )
        scripted = {s["suspicion"]["id"]: s for s in _script(case)}
        for index, raw in enumerate(found.output["suspicions"]):
            suspicion = Suspicion.model_validate(raw)
            # The adversary's tokens are charged once, on its first suspicion event.
            _emit(
                ledger, run_id, EventType.SUSPICION_RAISED,
                found if index == 0 else None,
                **suspicion.model_dump(by_alias=True),
            )
        if flags.naive:
            return
        for raw in found.output["suspicions"]:
            _verify(role, scripted[raw["id"]], case, flags, ledger, run_id)

    return pipeline


def _verify(role, script, case: Case, flags: Flags, ledger: Ledger, run_id: str) -> None:
    sid = script["suspicion"]["id"]
    written = role(Role.TEST_WRITER).run(
        f"case={case.id}\nsuspicion={sid}\nwrite exploit", _SCHEMAS[Role.TEST_WRITER]
    )
    _emit(ledger, run_id, EventType.EXPLOIT_WRITTEN, written, suspicion_id=sid)

    outcome = script["outcome"]  # scripted: test_fails, oracle_effect, fix_passes, bypass
    if not outcome["test_fails"]:
        verdict = "discarded_unproven"
    elif flags.oracle and not outcome["oracle_effect"]:
        verdict = "invalid_test"
    elif flags.differential and not outcome["fix_passes"]:
        verdict = "discarded_unproven"
    else:
        verdict = "proven"

    if verdict == "proven" and flags.defender:
        attempt = role(Role.DEFENDER).run(
            f"case={case.id}\nsuspicion={sid}\nbypass the fix", _SCHEMAS[Role.DEFENDER]
        )
        _emit(ledger, run_id, EventType.BYPASS_ATTEMPT, attempt, suspicion_id=sid)
        _emit(ledger, run_id, EventType.BYPASS_RESULT,
              suspicion_id=sid, succeeded=bool(outcome.get("bypass", False)))
    _emit(ledger, run_id, EventType.VERDICT, suspicion_id=sid, verdict=verdict)
