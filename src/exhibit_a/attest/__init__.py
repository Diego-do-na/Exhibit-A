"""Re-verifiable proof bundles: manifest signing and checking.

A finding package (``test_exploit.py``, ``fix.patch``, ``evidence.json``,
``verdict.json``) is a claim a reader must otherwise take on trust. The
manifest (``manifest.json``) written next to those files lets a third party
check the claim without trusting the author:

* every file's SHA-256, so any single-byte change is detected;
* the Exhibit A version and engine commit, the case or repository identity,
  the effect, the entry point, the oracle verdict, and the ledger event
  references that support the proof;
* a signature over all of the above.

The signature uses the same construction as the signed oracle events
(``exhibit_a.oracle.plugin``): HMAC-SHA256 over a canonical JSON encoding,
compared with ``hmac.compare_digest``. (Ledger event lines themselves carry
no signature; the oracle plugin's per-run keyed events are the only signed
channel in the engine, so the manifest borrows that mechanism.)

The signature binds the manifest to whoever holds the attestation key. The
key is a producer secret, resolved as: an explicitly passed key, the
``EXHIBIT_A_ATTEST_KEY`` environment variable (hex), or a machine-local key
file. It is never stored in the bundle: anyone holding the bundle can check
the hashes, and anyone holding the producer's key can additionally check
that the manifest was written by the producer and not hand-assembled.
"""

from __future__ import annotations

from .keys import default_key_path, load_key_file, resolve_key
from .manifest import (
    MANIFEST_NAME,
    SCHEMA_VERSION,
    ManifestCheck,
    ManifestData,
    build_manifest,
    engine_commit,
    engine_version,
    sha256_file,
    sign_manifest,
    verify_package,
    write_manifest,
)

__all__ = [
    "MANIFEST_NAME",
    "SCHEMA_VERSION",
    "ManifestCheck",
    "ManifestData",
    "build_manifest",
    "default_key_path",
    "engine_commit",
    "engine_version",
    "load_key_file",
    "resolve_key",
    "sha256_file",
    "sign_manifest",
    "verify_package",
    "write_manifest",
]
