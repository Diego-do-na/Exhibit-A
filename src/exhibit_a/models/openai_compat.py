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


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str,
        pricing: Pricing | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.pricing = pricing or Pricing()
        self.timeout = timeout

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
