"""Safe pip install helpers used by the CLI and recording scripts.

Installs use binary-only wheels and run with a minimal explicit environment so
host-side subprocesses never inherit API keys or tokens.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import Iterable


_NO_WHEEL_PATTERNS = [
    re.compile(r"No matching distribution found for", re.I),
    re.compile(r"Could not find a version that satisfies the requirement", re.I),
    re.compile(r"no binary", re.I),
]


# Only these pip settings reach the subprocess: names alone cannot tell a secret from a setting.
_PIP_ALLOWLIST = (
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "PIP_CACHE_DIR",
    "PIP_TIMEOUT",
    "PIP_RETRIES",
    "PIP_DISABLE_PIP_VERSION_CHECK",
    "PIP_NO_INDEX",
    "PIP_FIND_LINKS",
)
# '://user@' or '://user:pass@': credentials embedded in a URL (a space-separated list may hold several).
_URL_USERINFO = re.compile(r"://[^/\s?#]*@")


def _minimal_env() -> dict[str, str]:
    """Return a minimal env for subprocess installs without secret-bearing vars.

    Keep only safe keys so API keys and tokens are not visible to pip subprocesses.
    """
    env = {}
    env["PATH"] = os.environ.get("PATH", "")
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    # Keep allowlisted pip configuration, and never a value with credentials in a URL.
    for key in _PIP_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None and not _URL_USERINFO.search(value):
            env[key] = value
    # PYTHONPATH may be useful for local targets; keep only if present.
    if "PYTHONPATH" in os.environ:
        env["PYTHONPATH"] = os.environ["PYTHONPATH"]
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def safe_pip_install(*, target: str, requirements: Iterable[str], timeout: float = 300) -> None:
    """Run pip install into `target` using only wheels and a stripped env.

    Raises RuntimeError when pip fails or runs longer than `timeout` seconds. If the failure looks like "no wheel found"
    the message clarifies that the requirement has no wheel available.
    """
    reqs = list(requirements)
    if not reqs:
        return
    cmd = [sys.executable, "-m", "pip", "install", "--only-binary=:all:", "--target", target, *reqs]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=_minimal_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        # Deliberately no chaining or exception text: it would carry the command line.
        raise RuntimeError(f"pip install timed out after {timeout:g} s") from None
    if proc.returncode == 0:
        return
    stderr = proc.stderr or proc.stdout or ""
    for p in _NO_WHEEL_PATTERNS:
        if p.search(stderr):
            raise RuntimeError(f"pip install failed: a requirement appears to have no wheel: {stderr.strip()}")
    raise RuntimeError(f"pip install failed: {stderr.strip()}")

