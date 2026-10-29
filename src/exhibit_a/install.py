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


_SECRET_SUFFIXES = ("_KEY", "_TOKEN", "_SECRET")


def _minimal_env() -> dict[str, str]:
    """Return a minimal env for subprocess installs without secret-bearing vars.

    Keep only safe keys so API keys and tokens are not visible to pip subprocesses.
    """
    env = {}
    env["PATH"] = os.environ.get("PATH", "")
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    # Keep pip configuration (index URL, proxies) but never credential-like values.
    for key, value in os.environ.items():
        if key.startswith("PIP_") and not key.endswith(_SECRET_SUFFIXES):
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

