# Demo app: a skin-pack importer with a zip-slip PR (DEMO FIXTURE)

This directory is a **demonstration fixture**, not a real product. It gives the
2-minute demo a concrete story: a pull request that "simplifies" an
archive-import endpoint and silently drops its path-confinement check.

## Layout

- `base/importer.py` — the safe base version. Every member path is resolved
  and confined to the skins directory (`..` and absolute paths rejected).
- `pr/importer.py` — the same endpoint after the PR: `_target` just joins the
  member name onto the skins directory, so `../outside/…` escapes it
  (archive zip-slip class; real-world analog CVE-2007-4559).
- `pr.patch` — the `base` → `pr` diff shown at the start of the demo.
- `baseline_test.py` — behaviour that must hold on both trees (ordinary
  installs keep working); the engine runs it before and after the fix.
- `recordings/` — the offline evidence: byte-identical copies of the live
  compact-profile Meta recordings
  (`bench/corpus/<case>/recordings/meta-muse-wonder-1.0-compact.*`), recorded
  2026-10-30 with `muse-wonder-1.0` at reasoning effort `minimal`
  (see `docs/meta-run.md`). Both vulnerable cases proved with a verified fix:
  archive-extraction US$0.06, Starlette CVE-2023-29159 US$0.11.

## How the demo uses it

`scripts/demo.sh --offline` shows `pr.patch`, then replays the two compact
Meta recordings offline (no key, no network; the sandbox still runs every
test), prints the proven verdicts, renders the finding report with
`exhibit-a report`, lists the runs with `exhibit-a runs`, and prints the
command that opens the live view on the demo output.

The fixture's own code is a narrative stand-in: the proof itself comes from
the real Meta-model recordings above, replayed through the real loop and the
real sandbox. A green result means "nothing could be proven", never "safe".
