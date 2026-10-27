"""Minimal JSON-over-HTTP POST helper (stdlib only)."""

import json
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
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ProviderError(f"HTTP {exc.code} from {url}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"request to {url} failed: {exc}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProviderError("response too large")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ProviderError("response is not JSON") from exc
    if not isinstance(data, dict):
        raise ProviderError("response is not a JSON object")
    return data
