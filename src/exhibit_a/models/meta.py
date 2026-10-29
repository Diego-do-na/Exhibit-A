"""Meta Model API provider (SPEC section 5).

The Meta Model API is consumed with the OpenAI-compatible chat-completions
request shape, so this provider reuses
:class:`~exhibit_a.models.openai_compat.OpenAICompatibleProvider` and only
adds Meta-specific defaults: the API key env var, the base-URL resolution,
and a per-model pricing table.

Verified on 2026-10-29 with a real key, for model ``muse-wonder-1.0`` only:
the default endpoint below answers the exact chat-completions request this
provider sends (system + user messages + ``response_format`` json_schema, no
``max_tokens``) with HTTP 200 and the JSON answer in ``message.content``.
The model reasons, and its reasoning tokens count in ``completion_tokens``,
so never set a small ``max_tokens``. Its rates in ``META_PRICING`` were read
from the dev.meta.ai Models page on the same day.

UNVERIFIED (SPEC section 14): any other model id, and whether other models
honour ``response_format``. The schema is therefore still sent both as
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

#: USD per one million tokens, keyed by model id. Unknown models fall back to
#: the zero-cost "default" entry, which cannot enforce a budget.
#:
#: ``muse-wonder-1.0`` ("Muse Wonder"): input $4.00, output $20.00, from the
#: dev.meta.ai Models page (2026-10-29). Reasoning tokens are billed as output.
#: The page also lists cached input at $0.20; ``Pricing`` has no cached-input
#: rate, so every input token is metered at the full rate (slightly pessimistic).
META_PRICING: dict[str, Pricing] = {
    "default": Pricing(input_per_mtok=0.0, output_per_mtok=0.0),
    "muse-wonder-1.0": Pricing(input_per_mtok=4.0, output_per_mtok=20.0),
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
