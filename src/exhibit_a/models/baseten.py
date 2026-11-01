"""Baseten Model APIs provider (OpenAI-compatible chat completions).

Baseten Model APIs speak the OpenAI chat-completions request shape, so this
provider reuses :class:`~exhibit_a.models.openai_compat.OpenAICompatibleProvider`
and only adds Baseten-specific defaults: the API key env var, the base-URL
resolution, and a pricing gate.

Pricing is REQUIRED and explicit: every Baseten call must carry a known rate,
because a budget cap that cannot measure is not a cap. The rate comes from the
``BASETEN_PRICING`` table below (which the owner fills in per model slug) or,
failing that, from the ``EXHIBIT_A_PRICE_IN_PER_MTOK`` /
``EXHIBIT_A_PRICE_OUT_PER_MTOK`` environment variables (USD per one million
tokens). With no known price the provider refuses to run: the factory raises
``ValueError`` so ``exhibit-a run`` refuses to start, and ``complete`` raises
``ProviderError`` as a backstop.

The role's JSON schema is sent both as ``response_format`` (``json_schema``)
and inside the system message; ``ModelRole`` validates the answer either way,
so an answer that fails schema validation raises ``SchemaValidationError``
and can never become a proof.

The API key is never hardcoded and never logged: it is read from the
environment at call time via ``api_key_env`` (default ``BASETEN_API_KEY``),
sent only as the ``Authorization`` header, and excluded from every error
message, recording, and ledger event.
"""

import math
import os
from typing import Any

from .base import Completion, Role
from .cost import Pricing
from .errors import ProviderError
from .openai_compat import OpenAICompatibleProvider

#: Environment variable holding the Baseten API key (default name).
DEFAULT_API_KEY_ENV = "BASETEN_API_KEY"

#: Environment variable that overrides the API base URL.
BASE_URL_ENV = "BASETEN_BASE_URL"

#: Fallback base URL for Baseten Model APIs (OpenAI-compatible endpoint).
DEFAULT_BASE_URL = "https://inference.baseten.co/v1"

#: Environment variables for an explicit per-run rate (USD per million tokens).
PRICE_IN_ENV = "EXHIBIT_A_PRICE_IN_PER_MTOK"
PRICE_OUT_ENV = "EXHIBIT_A_PRICE_OUT_PER_MTOK"

#: USD per one million tokens, keyed by Baseten model slug. The owner fills
#: this in per model actually used; unknown slugs fall back to the
#: ``EXHIBIT_A_PRICE_*`` environment variables, and with neither known the
#: provider refuses to run.
#:
#: Add one line per model, for example (rates shown only as a shape example,
#: not a real quote):
#: ``"my-model-slug": Pricing(input_per_mtok=..., output_per_mtok=...),``
BASETEN_PRICING: dict[str, Pricing] = {}


def pricing_for(model: str) -> Pricing | None:
    """Return the pricing-table entry for `model`, or None when unknown."""
    return BASETEN_PRICING.get(model)


def pricing_from_env() -> Pricing | None:
    """Return the env-override rate, or None when absent or unusable."""
    raw_in = os.environ.get(PRICE_IN_ENV)
    raw_out = os.environ.get(PRICE_OUT_ENV)
    if raw_in is None or raw_out is None:
        return None
    try:
        price_in, price_out = float(raw_in), float(raw_out)
    except ValueError:
        return None
    if not (math.isfinite(price_in) and math.isfinite(price_out)):
        return None
    if price_in < 0 or price_out < 0:
        return None
    if price_in == 0.0 and price_out == 0.0:
        return None
    return Pricing(price_in, price_out)


def resolve_pricing(model: str, explicit: Pricing | None = None) -> Pricing | None:
    """Return the explicit rate, else the table entry, else the env override."""
    if explicit is not None and (
        explicit.input_per_mtok != 0.0 or explicit.output_per_mtok != 0.0
    ):
        return explicit
    return pricing_for(model) or pricing_from_env()


class BasetenProvider(OpenAICompatibleProvider):
    """Chat-completions provider targeting Baseten Model APIs."""

    name = "baseten"

    def __init__(
        self,
        model: str,
        base_url: str = "",
        api_key_env: str = "",
        pricing: Pricing | None = None,
        timeout: float = 120.0,
    ) -> None:
        if not model:
            raise ValueError("baseten provider needs a model name")
        resolved = resolve_pricing(model, pricing)
        if resolved is None:
            raise ValueError(
                f"baseten provider has no known price for model {model!r}; "
                f"add it to BASETEN_PRICING in src/exhibit_a/models/baseten.py or set "
                f"{PRICE_IN_ENV} and {PRICE_OUT_ENV} (USD per million tokens)"
            )
        resolved_base = base_url or os.environ.get(BASE_URL_ENV, "")
        super().__init__(
            resolved_base or DEFAULT_BASE_URL,
            model,
            api_key_env or DEFAULT_API_KEY_ENV,
            pricing=resolved,
            timeout=timeout,
        )

    def complete(
        self, role: Role, prompt: str, schema: dict[str, Any]
    ) -> Completion:
        # Backstop: refuse to run when no rate could be measured, so an
        # unpriced call can never slip past the budget cap.
        if (
            self.pricing.input_per_mtok == 0.0
            and self.pricing.output_per_mtok == 0.0
        ):
            raise ProviderError(
                f"baseten provider has no known price for model {self.model!r}; "
                "refusing to run without a measurable budget"
            )
        return super().complete(role, prompt, schema)
