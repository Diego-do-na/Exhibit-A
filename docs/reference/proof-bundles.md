# Proof bundles: verify and reproduce

A finding package (`packages/<id>`: `test_exploit.py`, `fix.patch`,
`evidence.json`, `verdict.json`) is a claim the reader must otherwise take
on trust. Since T094 every package also carries a `manifest.json` that lets
a third party check the proof themselves, offline, with no model call:

- `exhibit-a verify <package>` checks the bundle offline: every file hash
  and the manifest signature. Any single-byte change in the bundle makes it
  fail. Exit 0 when every check passes, 1 otherwise.
- `exhibit-a reproduce <package> --repo <clone>` re-runs the bundled
  exploit test in the isolated, resource-limited sandbox against the
  vulnerable tree (which must be proven again for the same effect through
  the same entry point) and against the tree with `fix.patch` applied
  (which must not be proven). It makes no model call at all. Exit 0
  reproduced, 10 not reproduced, 20 incomplete (the bundle is unusable or
  the sandbox could not run, e.g. Docker is missing).

A green result means "nothing could be proven", never "safe".

## The manifest

`manifest.json` is written by the loop's PACKAGE step and lists:

- `files`: every file in the bundle with its SHA-256 digest;
- `exhibit_a_version` and `exhibit_a_commit`: the engine that produced it;
- `case_id`, `repo_commit`, `diff_hash`: what the proof is about (the last
  two are null when the run did not record them);
- `effect` and `entry_point`: what the oracle judged (`canary_read`,
  `canary_write` or `canary_exec`, taken from
  [oracle.py](../../src/exhibit_a/oracle/oracle.py), and the qualified entry
  point the proof went through);
- `oracle_verdict`: the verdict, reason, effect, evidence and fix status;
- `ledger_events`: the supporting ledger events as `{index, type}` pairs,
  where `index` is the line number in the run's `ledger.jsonl`;
- `requirements`: the pip requirements the sandbox runs were baked with;
- `signature`: HMAC-SHA256 over the canonical JSON of everything above.

The signature uses the same construction as the signed oracle events
(`src/exhibit_a/oracle/plugin.py`): HMAC-SHA256 over canonical JSON
(sorted keys, no whitespace), compared with `hmac.compare_digest`, under a
domain tag that keeps manifest signatures distinct from event signatures.
Ledger event lines themselves are unsigned; the oracle plugin's per-run
keyed events are the only signed channel, so the manifest borrows that
mechanism. (The task text said "the same signing mechanism as ledger
events"; the ledger has none, and this is the honest reading.)

## The attestation key

The signature binds the manifest to whoever holds the attestation key: a
producer secret, never stored in the bundle. Resolution order: `--key`
(resp. explicit bytes), `--key-file` (resp. a path), the
`EXHIBIT_A_ATTEST_KEY` environment variable (hex), then the machine-local
key file (`~/.config/exhibit-a/attest.key`, honouring `XDG_CONFIG_HOME`).

- The packaging path creates the machine-local key on first use (mode
  0600). CI producers should set `EXHIBIT_A_ATTEST_KEY` instead and publish
  the corresponding key to verifiers out of band.
- `verify` never creates a key: with no key available the signature check
  fails and the command exits 1.
- `reproduce` checks the signature when a key is available (a mismatch is
  INCOMPLETE); without a key it warns and continues on the file hashes,
  because the sandbox re-run itself re-establishes the proof: a forged
  manifest that misstates the effect or entry point simply fails to
  reproduce (exit 10).

## Examples

Illustrative output for a bundle from an offline replay run of the archive
case (exact lines depend on the bundle; the sandbox replay needs Docker):

```bash
exhibit-a run --case bench/corpus/archive-extraction-pathtraversal --replay --out runs/archive
exhibit-a verify runs/archive/packages/archive-extraction-pathtraversal
# PASS manifest readable
# PASS manifest schema
# PASS hash evidence.json
# PASS hash fix.patch
# PASS hash test_exploit.py
# PASS hash verdict.json
# PASS no unexpected files
# PASS signature

exhibit-a reproduce runs/archive/packages/archive-extraction-pathtraversal \
  --repo /tmp/archive-vulnerable
# PACKAGE runs/archive/packages/archive-extraction-pathtraversal
# PASS manifest readable
# ...
# MODEL CALLS 0
# VULNERABLE outcome=failed effect=yes provenance=ok verdict=proven
# FIX APPLIED git apply
# FIXED outcome=passed verdict=discarded_unproven
# REPRODUCED: canary_write via App.handle_request proven on the vulnerable
# tree, not proven with fix.patch applied, with no model call
```

A bundle whose fix does not stop the exploit (e.g. built against the
`fixed_incomplete` tree) ends with `NOT REPRODUCED` and exit 10.

## Limits

- The manifest is only as honest as the producer's key custody: anyone with
  the key can sign a hand-assembled bundle. Hashes still detect any later
  change, and `reproduce` replays the proof rather than trusting it.
- `repo_commit` and `diff_hash` are currently null: the loop does not yet
  thread repository identity into the packaging step. The fields are
  reserved in the schema for that wiring.
- The sandbox runs need Docker; without it `reproduce` reports INCOMPLETE
  (exit 20) instead of guessing.
