"""Ollama provider: HTTP to localhost, for plumbing and debugging only.

Benchmark and demo numbers must come from Meta models, never from this provider.
"""

import time
from typing import Any
from urllib.parse import urlparse

from .base import Completion, Role
from .cost import Pricing
from .errors import ProviderError
from .http import post_json

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class OllamaProvider:
    name = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,
    ) -> None:
        if urlparse(base_url).hostname not in _LOCAL_HOSTS:
            raise ValueError("OllamaProvider only talks to localhost")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.pricing = Pricing()

    def complete(self, role: Role, prompt: str, schema: dict[str, Any]) -> Completion:
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "format": schema,
        }
        started = time.monotonic()
        data = post_json(f"{self.base_url}/api/chat", body, {}, self.timeout)
        latency_ms = int((time.monotonic() - started) * 1000)
        try:
            text = data["message"]["content"]
            tokens_in = int(data.get("prompt_eval_count", 0))
            tokens_out = int(data.get("eval_count", 0))
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError("unexpected Ollama response shape") from exc
        if not isinstance(text, str):
            raise ProviderError("unexpected Ollama response shape")
        return Completion(text, tokens_in, tokens_out, latency_ms, self.model)
