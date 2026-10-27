# Models — roles, providers, budgets, and replay

This document explains the model layer: the `ModelRole` interface, the
providers (`replay`, `ollama`, `openai_compatible`, `meta`), per-role
configuration, the cost meter, recording/replay, and the rule that
benchmark and demo numbers must come from Meta models.

Summary
- Models are untrusted text generators behind one `ModelRole` interface.
  Text goes in, schema-validated JSON comes out. No provider exposes
  tools, function calling, or any other side-effecting channel.
- All model calls happen in the orchestrator, outside the sandbox. The
  sandbox holds no secrets and has no network.
- Every model call is recorded and replayable. A cost meter enforces a
  hard stop below the credit limit.
- **All benchmark and demo numbers must come from Meta models** (SPEC
  section 5), never from `replay` fixtures or `ollama`.

## `ModelRole` interface

`Role` (`models/base.py`) has four members: `adversary`, `test_writer`,
`fixer`, `defender`. Each loop stage binds one `ModelRole` to one role.

`Provider` (`models/base.py`) is a protocol with `name`, `pricing`, and:

```python
complete(role: Role, prompt: str, schema: dict[str, Any]) -> Completion
```

Providers return raw text only; they never validate. `ModelRole.run`
does the rest:

1. `meter.check()` raises `BudgetExceeded` before the call if the budget
   is already spent.
2. Calls `provider.complete`, derives latency and cost (provider-reported
   `cost_usd`, else `pricing.cost(tokens_in, tokens_out)`), and charges
   the meter. Crossing the limit raises `BudgetExceeded`.
3. Parses the text as JSON (`SchemaValidationError` if it is not JSON)
   and validates it with `models/jsonschema.py` (`SchemaValidationError`
   for hostile values, `UnsupportedSchemaError` for schemas using
   keywords the validator does not implement). Spend is still charged on
   validation failure.
4. Returns a `RoleResult` with the validated `output`, token counts,
   latency, model name, cost, and the `raw_text`.

Model outputs are untrusted data: they are never executed, only parsed
and validated.

## Providers

| Provider | Module | Use |
|---|---|---|
| `replay` | `models/replay.py` | Deterministic tests and demo replay mode |
| `ollama` | `models/ollama.py` | Plumbing and debugging only (localhost) |
| `openai_compatible` | `models/openai_compat.py` | Meta Model API and other chat-completions endpoints |
| `meta` | `models/meta.py` | Meta Model API with Meta defaults |

`replay` serves recorded completions from a JSONL file keyed by the
SHA-256 of `(role, prompt, schema)`. On a miss it asks its `recorder`
(a live provider) and appends the answer, or raises `ReplayMiss` when
no recorder is configured. `ollama` posts to `<base_url>/api/chat` with
the schema as `format`, and only talks to `localhost`, `127.0.0.1`, or
`::1`. `openai_compatible` posts to `<base_url>/chat/completions` and
sends the schema twice: as `response_format` (`json_schema`) and inside
the system message, because structured-output support on the target is
unverified (SPEC section 14); `ModelRole` validates either way. `meta`
reuses `OpenAICompatibleProvider` and only adds Meta defaults: key env
var (`META_API_KEY`, overridable per config), base URL resolution
(`META_BASE_URL` env, else `https://api.meta.ai/v1`, UNVERIFIED), and
the `META_PRICING` table (UNVERIFIED placeholders; confirm at
dev.meta.ai before enforcing budgets against Meta models).

HTTP goes through `models/http.py` (`post_json`, stdlib only): strict
overall timeout, at most 3 attempts with exponential backoff for
transient failures only (network errors and HTTP 5xx; 4xx is never
retried), an 8 MiB response cap, and error messages that never include
request headers, so API keys cannot leak through them.

## Per-role config

`models/config.py` binds each `Role` to one declarative `RoleConfig`:

```python
RoleConfig(provider="meta", model="<model-id>", base_url="",
           api_key_env="META_API_KEY", recording="", timeout=120.0,
           pricing=Pricing())
```

`build_roles(config, meter)` resolves each entry's `provider` through
`PROVIDER_REGISTRY` (`replay`, `ollama`, `openai_compatible`, `meta`;
extend via `register_provider`) and returns one `ModelRole` per role,
all sharing the optional meter. Factories validate their required
fields (`replay` needs `recording`, `ollama` and `meta` need `model`,
`openai_compatible` needs `base_url` and `model`) and raise `ValueError`
on unknown roles, unknown providers, or malformed specs. `meta` falls
back to `META_PRICING` only when no explicit pricing is configured.
`pricing` also accepts a plain mapping such as
`{"input_per_mtok": ..., "output_per_mtok": ...}`.

## Cost meter

`Pricing` (`models/cost.py`) holds USD per one million input/output
tokens; `cost(tokens_in, tokens_out)` is the charge for one call.
`CostMeter(limit_usd)` tracks cumulative spend (thread-safe) with a hard
stop: `check()` raises `BudgetExceeded` once the total reaches the
limit, and `charge()` adds a call's cost then checks, so the call that
hits the limit still raises. `limit_usd` must be positive; negative
charges are rejected. Ledger event fields (`tokens_in`, `tokens_out`,
`cost_usd`, `model`) feed the cost meter, the benchmark's
tokens-per-proven-finding metric, and the audit trail.

## Recording and replay

- `ReplayProvider(path, recorder=None)` loads every line of the JSONL
  file at `path` into memory keyed by `request_key`. `complete` returns
  the hit, else records via `recorder` (appending
  `{"key", "role", "text", "tokens_in", "tokens_out", "latency_ms",
  "model", "cost_usd"}` sorted by key) or raises `ReplayMiss`.
- `RecordingProvider(path, provider)` (alias `RecordProvider`) delegates
  every call to the wrapped provider and appends the same record shape.
  Use it to capture live Meta runs for deterministic fixtures and the
  demo replay mode.

## Meta-models rule

SPEC sections 5 and 15 require it: results, benchmark numbers, and the
demo must come from Meta models (the `meta` provider, or Meta
open-weight models through an OpenAI-compatible inference partner).
`replay` exists for deterministic tests and replaying recorded runs;
`ollama` exists for plumbing and debugging only. Probing a local model
with `bench/probe.py` measures prompt/schema health, never reported
results. The endpoint URL, structured-output support, and every
`META_PRICING` rate are UNVERIFIED: confirm them at dev.meta.ai before
relying on them.

## Secrets

API keys live in environment variables only, read at call time (for
example `META_API_KEY`). Never commit keys, `.env` files, or tokens.
Do not send third-party code to a provider without checking its data
terms (free-credit terms may allow content to be used for product
improvement).

## References

- Interface and validation: `src/exhibit_a/models/base.py`,
  `src/exhibit_a/models/jsonschema.py`, `src/exhibit_a/models/errors.py`.
- Providers: `src/exhibit_a/models/replay.py`,
  `src/exhibit_a/models/record.py`, `src/exhibit_a/models/ollama.py`,
  `src/exhibit_a/models/openai_compat.py`, `src/exhibit_a/models/meta.py`,
  `src/exhibit_a/models/http.py`.
- Config, pricing, budget: `src/exhibit_a/models/config.py`,
  `src/exhibit_a/models/cost.py`.
