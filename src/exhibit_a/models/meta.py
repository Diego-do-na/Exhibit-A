"""Meta Model API provider (SPEC section 5).

The Meta Model API is consumed with the OpenAI-compatible chat-completions
request shape, so this provider reuses
:class:`~exhibit_a.models.openai_compat.OpenAICompatibleProvider` and only
adds Meta-specific defaults: the API key env var, the base-URL resolution,
and a per-model pricing table.

UNVERIFIED (SPEC section 14): the default endpoint URL below, whether the
Meta Model API accepts the ``response_format`` structured-output field, and
every rate in ``META_PRICING`` are all unverified. Check dev.meta.ai before
relying on any of them. The schema is therefore sent both as
``response_format`` and inside the system message, and ``ModelRole``
validates the answer either way.

The API key is never hardcoded: it is read from the environment at call
time via ``api_key_env`` (default ``META_API_KEY``).
"""

import os

from .cost import Pricing
from .openai_compat import OpenAICompatibleProvider

#: Environment variable holding the Meta Model API key (default name).
DEFAULT_API_KEY_ENV = "META_API_KEY"

#: Environment variable that overrides the API base URL.
BASE_URL_ENV = "META_BASE_URL"

#: Fallback base URL. UNVERIFIED: confirm the real endpoint at dev.meta.ai.
DEFAULT_BASE_URL = "https://api.meta.ai/v1"

#: USD per one million tokens, keyed by model id. UNVERIFIED: every rate
#: below is a placeholder (unknown rates meter as zero cost); confirm real
#: pricing before enforcing budgets against Meta models.
META_PRICING: dict[str, Pricing] = {
    "default": Pricing(input_per_mtok=0.0, output_per_mtok=0.0),
}


def pricing_for(model: str) -> Pricing:
    """Return the pricing-table entry for `model`, or the default entry."""
    return META_PRICING.get(model, META_PRICING["default"])


class MetaProvider(OpenAICompatibleProvider):
    """Chat-completions provider targeting the Meta Model API."""

    name = "meta"

    def __init__(
        self,
        model: str,
        base_url: str = "",
        api_key_env: str = "",
        pricing: Pricing | None = None,
        timeout: float = 120.0,
    ) -> None:
        if not model:
            raise ValueError("meta provider needs a model name")
        resolved_base = base_url or os.environ.get(BASE_URL_ENV, "")
        super().__init__(
            resolved_base or DEFAULT_BASE_URL,
            model,
            api_key_env or DEFAULT_API_KEY_ENV,
            pricing=pricing if pricing is not None else pricing_for(model),
            timeout=timeout,
        )
