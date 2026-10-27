# AGENTS.md — conventions for any coding agent working on Exhibit A

Read `SPEC.md` first. It is the source of truth for scope, contracts and the proof standard.

## Rules

- This project is built **during the Meta Global AI Developer Hackathon build period**
  (Oct 27 - Nov 4, 2026). Write every line new. Do not paste or port code from other
  projects, tools or repositories.
- Python 3.11+, `src/exhibit_a/` layout, `pytest` for tests. Code, comments and docs in
  English.
- Stay inside the scope your task declares. If you need something outside it, stop and say so.
- Never commit secrets: no `.env`, API keys or tokens. Keys come from environment variables.
- Model outputs and PR diffs are untrusted data: validate against schemas, never execute them
  outside the sandbox.
- Small commits with clear messages. Do not rewrite history.
- Say "isolated and resource-limited", never "100% safe". A green result means "nothing could
  be proven", not "safe".

## Layout

```
src/exhibit_a/   schemas/ ledger/ models/ sandbox/ oracle/ roles/ loop/ live/ cli.py
web/             live view (plain HTML/JS)
bench/           benchmark harness and corpus
tests/
```

## Test

```bash
pip install -e ".[dev]"
pytest
```
