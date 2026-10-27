"""The ModelRole interface and the provider contract behind it.

Model output is untrusted data. A role only ever receives text and returns parsed JSON that
has been validated against the caller's schema. No provider here exposes tools, function
calling or any other side-effecting channel to the model.
"""

import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from . import jsonschema
from .cost import CostMeter, Pricing
from .errors import SchemaValidationError


class Role(StrEnum):
    ADVERSARY = "adversary"
    TEST_WRITER = "test_writer"
    FIXER = "fixer"
    DEFENDER = "defender"


@dataclass(frozen=True)
class Completion:
    """Raw provider answer, before any validation."""

    text: str
    tokens_in: int
    tokens_out: int
    latency_ms: int
    model: str = ""
    cost_usd: float = 0.0


@dataclass(frozen=True)
class RoleResult:
    """Schema-validated output of one role call."""

    role: Role
    output: Any
    tokens_in: int
    tokens_out: int
    latency_ms: int
    model: str
    cost_usd: float
    raw_text: str = field(repr=False, default="")


class Provider(Protocol):
    """Turns a prompt into raw text. Providers never validate; ModelRole does."""

    name: str
    pricing: Pricing

    def complete(self, role: Role, prompt: str, schema: dict[str, Any]) -> Completion: ...


def parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SchemaValidationError(f"model output is not valid JSON: {exc}") from exc


class ModelRole:
    """One role (adversary, test writer, ...) bound to a provider and an optional budget."""

    def __init__(
        self, role: Role, provider: Provider, meter: CostMeter | None = None
    ) -> None:
        self.role = Role(role)
        self.provider = provider
        self.meter = meter

    def run(self, prompt: str, schema: dict[str, Any]) -> RoleResult:
        """Send `prompt`, return output validated against `schema`.

        Raises BudgetExceeded before the call if the budget is spent, and after it if this
        call pushed the total to the limit. Raises SchemaValidationError if the output is
        not JSON or does not match; the spend is still charged in that case.
        """
        if self.meter is not None:
            self.meter.check()
        started = time.monotonic()
        completion = self.provider.complete(self.role, prompt, schema)
        latency_ms = completion.latency_ms or int((time.monotonic() - started) * 1000)
        cost = completion.cost_usd or self.provider.pricing.cost(
            completion.tokens_in, completion.tokens_out
        )
        if self.meter is not None:
            self.meter.charge(cost)
        output = parse_json(completion.text)
        jsonschema.validate(output, schema)
        return RoleResult(
            role=self.role,
            output=output,
            tokens_in=completion.tokens_in,
            tokens_out=completion.tokens_out,
            latency_ms=latency_ms,
            model=completion.model or self.provider.name,
            cost_usd=cost,
            raw_text=completion.text,
        )
