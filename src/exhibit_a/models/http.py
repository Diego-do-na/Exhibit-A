"""Minimal JSON-over-HTTP POST helper (stdlib only)."""

import json
import time
import urllib.error
import urllib.request
from typing import Any

from .errors import ProviderError

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def post_json(
    url: str, body: dict[str, Any], headers: dict[str, str], timeout: float
) -> dict[str, Any]:
    """POST `body` as JSON and return the decoded JSON object.

    Error messages never include request headers, so API keys cannot leak through them.

    This function enforces a strict overall `timeout` (seconds) for the entire
    call and performs bounded retries with exponential backoff for transient
    failures only (network errors and HTTP 5xx). It never retries 4xx responses.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )

    max_attempts = 3
    backoff_base = 0.1
    deadline = time.monotonic() + timeout

    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        now = time.monotonic()
        remaining = deadline - now
        if remaining <= 0:
            raise ProviderError(f"request to {url} timed out")
        try:
            with urllib.request.urlopen(request, timeout=remaining) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            # Do not retry 4xx per requirement.
            code = getattr(exc, "code", None)
            if code is not None and 400 <= code < 500:
                raise ProviderError(f"HTTP {code} from {url}") from exc
            # Treat 5xx as transient and possibly retry.
            last_exc = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Transient network errors: retry.
            last_exc = exc
        else:
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ProviderError("response too large")
            try:
                data = json.loads(raw)
            except ValueError as exc:
                raise ProviderError("response is not JSON") from exc
            if not isinstance(data, dict):
                raise ProviderError("response is not a JSON object")
            return data

        # If we get here, we caught a transient error and may retry.
        if attempt == max_attempts:
            break
        # Backoff but never sleep past the overall deadline.
        sleep_for = backoff_base * (2 ** (attempt - 1))
        now = time.monotonic()
        remaining = deadline - now
        if remaining <= 0:
            break
        time.sleep(min(sleep_for, remaining))

    # Exhausted retries.
    if isinstance(last_exc, urllib.error.HTTPError):
        code = getattr(last_exc, "code", "unknown")
        raise ProviderError(f"HTTP {code} from {url}") from last_exc
    if last_exc is not None:
        raise ProviderError(f"request to {url} failed: {last_exc}") from last_exc
    raise ProviderError("request failed")
