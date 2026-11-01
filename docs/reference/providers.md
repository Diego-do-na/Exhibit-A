# Providers — Meta (primary) and Baseten (comparison and fallback)

This document explains the two live model providers: Meta (primary) and
Baseten Model APIs (comparison and fallback). Both speak the OpenAI
chat-completions request shape through `models/openai_compat.py`.

Summary
- Meta is the primary provider for benchmark and demo numbers. Baseten is
  the comparison and fallback provider: the point is to show the proof
  standard holds across models — a weaker model should prove less, never
  prove falsely.
- Both providers send the role's JSON schema as `response_format`
  (`json_schema`) and inside the system message; `ModelRole` validates the
  answer either way. An answer that fails schema validation raises
  `SchemaValidationError` and ends as discarded/invalid, never as a proof.
- API keys live in environment variables only, read at call time, and never
  reach ledgers, logs, or recordings.

## Meta (primary)

- Module: `src/exhibit_a/models/meta.py` (`MetaProvider`, registry name `meta`).
- Base URL: `META_BASE_URL` env, else `https://api.meta.ai/v1` (UNVERIFIED:
  confirm at dev.meta.ai).
- Key: `META_API_KEY` env (default name, overridable per role config).
- Pricing: `META_PRICING` table (UNVERIFIED placeholders); only
  `muse-wonder-1.0` ($4 input / $20 output per million tokens, read
  2026-10-29) is verified against a live call.
- Unknown models fall back to the zero-cost default entry, which cannot
  enforce a budget: confirm the rate before enforcing budgets on them.

## Baseten (comparison and fallback)

- Module: `src/exhibit_a/models/baseten.py` (`BasetenProvider`, registry
  name `baseten`).
- Base URL: `BASETEN_BASE_URL` env, else `https://inference.baseten.co/v1`.
- Key: `BASETEN_API_KEY` env (default name, overridable per role config).
- Pricing is REQUIRED and explicit: per-model rates from the
  `BASETEN_PRICING` table (which the owner fills in per model slug), or
  `EXHIBIT_A_PRICE_IN_PER_MTOK` / `EXHIBIT_A_PRICE_OUT_PER_MTOK` (USD per
  one million tokens). With no known price the provider refuses to run —
  the factory raises `ValueError` so `exhibit-a run` refuses to start, and
  `complete` raises `ProviderError` as a backstop. A budget cap that
  cannot measure is not a cap.

## Selecting a provider

`exhibit-a run --provider <name> --model <slug>` builds every role through
the provider registry (`models/config.py`), so `--provider` accepts any
registered name (`replay`, `ollama`, `openai_compatible`, `meta`,
`baseten`) with no parser change. Flags beat `EXHIBIT_A_PROVIDER` /
`EXHIBIT_A_MODEL`, which beat the built-in Ollama dev defaults.

```bash
exhibit-a run --case bench/corpus/<case> --provider baseten --model <slug> --budget-usd 5
```

Without a key the run refuses to start:

```text
run: cannot build live roles: baseten provider needs the BASETEN_API_KEY environment variable to be set
```

With a key but no known price it refuses to start:

```text
run: cannot build live roles: baseten provider has no known price for model '<slug>'; add it to BASETEN_PRICING in src/exhibit_a/models/baseten.py or set EXHIBIT_A_PRICE_IN_PER_MTOK and EXHIBIT_A_PRICE_OUT_PER_MTOK (USD per million tokens)
```

## Listing Baseten models

Baseten Model APIs expose the OpenAI-compatible model list. Replace the
key placeholder with the real key (never commit it):

```bash
curl -s https://inference.baseten.co/v1/models \
  -H "Authorization: Bearer $BASETEN_API_KEY" | head -c 2000
```

Pick a slug from that list, add its rates to `BASETEN_PRICING` (or export
the `EXHIBIT_A_PRICE_*` overrides), and pass it as `--model`.

## Comparing models

Run the same case under each provider with the same `--budget-usd` and
compare `proven` counts, discarded-suspicion counts, and tokens/cost per
proven finding from the ledger totals. Expect a weaker model to prove
fewer findings at a lower cost per call — and treat any finding the
stronger model cannot also prove as a signal to inspect, not a win.
Do not send third-party code to a provider without checking its data
terms (free-credit terms may allow content to be used for product
improvement).

## References

- Interface and validation: `src/exhibit_a/models/base.py`,
  `src/exhibit_a/models/jsonschema.py`, `src/exhibit_a/models/errors.py`.
- Providers: `src/exhibit_a/models/openai_compat.py`,
  `src/exhibit_a/models/meta.py`, `src/exhibit_a/models/baseten.py`,
  `src/exhibit_a/models/http.py`.
- Config, pricing, budget: `src/exhibit_a/models/config.py`,
  `src/exhibit_a/models/cost.py`.
- Recording and replay: `src/exhibit_a/models/record.py`,
  `src/exhibit_a/models/replay.py`.
