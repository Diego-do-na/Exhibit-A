"""Attestation key handling for proof-bundle manifests."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

#: Environment variable holding the attestation key as hex.
KEY_ENV_VAR = "EXHIBIT_A_ATTEST_KEY"
#: Directory holding the machine-local attestation key, next to no secrets.
_CONFIG_DIR_NAME = "exhibit-a"
_KEY_FILE_NAME = "attest.key"
#: Keys shorter than this are refused: a short key signs nothing meaningful.
_MIN_KEY_BYTES = 16


def default_key_path() -> Path:
    """Where the machine-local attestation key lives (never in the repo)."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / _CONFIG_DIR_NAME / _KEY_FILE_NAME


def load_key_file(path: Path) -> bytes:
    """Read a hex attestation key from ``path``; raise ``ValueError`` if unusable."""
    try:
        raw = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"cannot read attestation key file {path}: {exc}") from exc
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(f"attestation key file {path} is not hex") from exc
    if len(key) < _MIN_KEY_BYTES:
        raise ValueError(f"attestation key file {path} is too short")
    return key


def _from_env() -> bytes | None:
    raw = os.environ.get(KEY_ENV_VAR, "").strip()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(f"{KEY_ENV_VAR} is not hex") from exc
    if len(key) < _MIN_KEY_BYTES:
        raise ValueError(f"{KEY_ENV_VAR} is too short")
    return key


def resolve_key(explicit: bytes | None = None, *, create: bool = False) -> bytes | None:
    """Return the attestation key, or None when no key is available.

    Precedence: ``explicit``, the ``EXHIBIT_A_ATTEST_KEY`` environment
    variable, the machine-local key file. With ``create=True`` (the
    packaging path) a missing key file is generated and stored with mode
    0o600; the read-only ``verify`` path never creates one, so a missing
    key there stays a failed signature check instead of a fresh key that
    could never match.
    """
    if explicit is not None:
        if len(explicit) < _MIN_KEY_BYTES:
            raise ValueError("attestation key is too short")
        return explicit
    key = _from_env()
    if key is not None:
        return key
    path = default_key_path()
    if path.is_file():
        return load_key_file(path)
    if not create:
        return None
    key = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key.hex().encode("ascii"))
    finally:
        os.close(fd)
    return key
