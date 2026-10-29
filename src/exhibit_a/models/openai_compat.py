"""OpenAI-compatible chat-completions provider.

Meant for Meta Model API / Baseten / Modal endpoints. Whether the target supports
structured outputs is unverified (SPEC section 14), so the schema is sent both as
`response_format` and in the system message; ModelRole validates the result either way.
"""

import json
import os
import time
from typing import Any

from .base import Completion, Role
from .cost import Pricing
from .errors import ProviderError
from .http import post_json


#: Reasoning-effort levels. On 2026-10-29 the Meta Model API accepted minimal, low, medium
#: and max for muse-wonder-1.0 on /v1/responses ("reasoning": {"effort": ...}); "high" was
#: not tried. Whether /chat/completions honours the "reasoning_effort" field sent here is
#: UNVERIFIED until a live call shows fewer reasoning tokens with a lower level.
REASONING_EFFORTS = ("minimal", "low", "medium", "high", "max")


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str,
        pricing: Pricing | None = None,
        timeout: float = 120.0,
        reasoning_effort: str = "",
        max_output_tokens: int = 0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.pricing = pricing or Pricing()
        self.timeout = timeout
        self.configure_generation(reasoning_effort, max_output_tokens)

    def configure_generation(self, reasoning_effort: str = "", max_output_tokens: int = 0) -> None:
        """Set the optional cost controls sent with every request.

        Empty / zero means "not sent", so the request body stays exactly what it was
        before these controls existed. With reasoning models the reasoning tokens are
        billed as output, so a low effort is the main cost lever; ``max_output_tokens``
        is a ceiling, and an answer cut by it is reported as a ProviderError.
        """
        if reasoning_effort and reasoning_effort not in REASONING_EFFORTS:
            raise ValueError(
                f"unknown reasoning effort {reasoning_effort!r}; known: {list(REASONING_EFFORTS)}"
            )
        if max_output_tokens < 0:
            raise ValueError("max_output_tokens must be >= 0")
        self.reasoning_effort = reasoning_effort
        self.max_output_tokens = max_output_tokens

    def _api_key(self) -> str:
        key = os.environ.get(self.api_key_env)
        if not key:
            raise ProviderError(f"environment variable {self.api_key_env} is not set")
        return key

    def complete(self, role: Role, prompt: str, schema: dict[str, Any]) -> Completion:
        system = (
            "Answer with a single JSON value that conforms to this JSON schema. "
            "No prose, no code fences.\n" + json.dumps(schema, sort_keys=True)
        )
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": str(role), "schema": schema},
            },
        }
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        if self.max_output_tokens:
            body["max_tokens"] = self.max_output_tokens
        headers = {"Authorization": f"Bearer {self._api_key()}"}
        started = time.monotonic()
        data = post_json(f"{self.base_url}/chat/completions", body, headers, self.timeout)
        latency_ms = int((time.monotonic() - started) * 1000)
        try:
            text = data["choices"][0]["message"]["content"]
            usage = data.get("usage") or {}
            tokens_in = int(usage.get("prompt_tokens", 0))
            tokens_out = int(usage.get("completion_tokens", 0))
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ProviderError("unexpected chat-completions response shape") from exc
        if not isinstance(text, str):
            if data.get("choices", [{}])[0].get("finish_reason") == "length":
                raise ProviderError(
                    "model stopped at the output-token cap before answering; "
                    "raise max_output_tokens or lower the reasoning effort"
                )
            raise ProviderError("unexpected chat-completions response shape")
        model = data.get("model")
        return Completion(
            text,
            tokens_in,
            tokens_out,
            latency_ms,
            model if isinstance(model, str) else self.model,
            self.pricing.cost(tokens_in, tokens_out),
        )
