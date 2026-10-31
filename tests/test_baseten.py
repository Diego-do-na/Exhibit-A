"""Tests for the Baseten Model APIs provider: fake HTTP layer, no real network.

The fake layer monkeypatches ``post_json`` in the ``openai_compat`` namespace
(the same seam ``tests/test_compact_profile.py`` uses), because a bound local
HTTP server is not available everywhere these tests run.
"""

import json

import pytest

from exhibit_a.ledger import Ledger
from exhibit_a.models import (
    BasetenProvider,
    CostMeter,
    ModelError,
    ModelRole,
    Pricing,
    ProviderError,
    Role,
    RoleConfig,
    SchemaValidationError,
    build_roles,
)
from exhibit_a.models import baseten as baseten_module
from exhibit_a.models import openai_compat
from exhibit_a.models.baseten import (
    BASE_URL_ENV,
    DEFAULT_API_KEY_ENV,
    BasetenProvider as DirectBasetenProvider,
)
from exhibit_a.models.record import RecordingProvider
from exhibit_a.schemas import Event, EventType

SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string", "enum": ["yes", "no"]}},
    "required": ["verdict"],
    "additionalProperties": False,
}

REPLY = {
    "model": "baseten-test-model",
    "choices": [{"message": {"content": '{"verdict": "yes"}'}}],
    "usage": {"prompt_tokens": 100, "completion_tokens": 50},
}

SECRET = "baseten-secret-value-for-test"

PRICED = Pricing(input_per_mtok=3.0, output_per_mtok=15.0)


@pytest.fixture
def priced_env(monkeypatch):
    """Give the suite a known price via the env override and a clean table."""
    monkeypatch.setenv("EXHIBIT_A_PRICE_IN_PER_MTOK", "3.0")
    monkeypatch.setenv("EXHIBIT_A_PRICE_OUT_PER_MTOK", "15.0")
    monkeypatch.delenv("BASETEN_API_KEY", raising=False)
    monkeypatch.delenv(BASE_URL_ENV, raising=False)
    return monkeypatch


def capture(monkeypatch, reply):
    """Replace post_json with a recorder returning `reply`; return what was sent."""
    sent = {}

    def fake_post_json(url, body, headers, timeout):
        sent["url"] = url
        sent["body"] = body
        sent["headers"] = headers
        return reply

    monkeypatch.setattr(openai_compat, "post_json", fake_post_json)
    return sent


def test_request_shape_is_openai_chat_completions(monkeypatch, priced_env):
    priced_env.setenv("BASETEN_API_KEY", "k")
    sent = capture(monkeypatch, REPLY)
    result = ModelRole(
        Role.ADVERSARY, BasetenProvider("some-model")
    ).run("hi", SCHEMA)
    assert sent["url"] == "https://inference.baseten.co/v1/chat/completions"
    body = sent["body"]
    assert body["model"] == "some-model"
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][1] == {"role": "user", "content": "hi"}
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA
    assert "tools" not in body and "functions" not in body
    assert result.output == {"verdict": "yes"}
    assert result.model == "baseten-test-model"
    assert (result.tokens_in, result.tokens_out) == (100, 50)


def test_auth_header_carries_the_key(monkeypatch, priced_env):
    priced_env.setenv("BASETEN_API_KEY", SECRET)
    sent = capture(monkeypatch, REPLY)
    ModelRole(Role.FIXER, BasetenProvider("some-model")).run("hi", SCHEMA)
    assert sent["headers"]["Authorization"] == f"Bearer {SECRET}"


def test_base_url_resolution_order(monkeypatch, priced_env):
    priced_env.setenv("BASETEN_API_KEY", "k")
    capture(monkeypatch, REPLY)
    # Explicit base_url wins over the env override.
    priced_env.setenv(BASE_URL_ENV, "http://127.0.0.1:9/unused")
    provider = BasetenProvider("m", base_url="https://example.com/v1")
    assert provider.base_url == "https://example.com/v1"
    ModelRole(Role.FIXER, provider).run("hi", SCHEMA)
    # Without an explicit base_url, the env override is used.
    priced_env.setenv(BASE_URL_ENV, "https://env-override.example/v1")
    assert BasetenProvider("m").base_url == "https://env-override.example/v1"
    # With neither, the Baseten default is used.
    priced_env.delenv(BASE_URL_ENV)
    assert BasetenProvider("m").base_url == "https://inference.baseten.co/v1"


def test_api_key_defaults_to_env_var_name_not_a_secret(priced_env):
    provider = BasetenProvider("m")
    assert provider.api_key_env == DEFAULT_API_KEY_ENV == "BASETEN_API_KEY"
    assert "sk-" not in provider.api_key_env


def test_missing_api_key_names_the_env_var(monkeypatch, priced_env):
    capture(monkeypatch, REPLY)
    provider = BasetenProvider("m")
    with pytest.raises(ProviderError, match="BASETEN_API_KEY"):
        ModelRole(Role.FIXER, provider).run("p", SCHEMA)


def test_missing_model_is_rejected(priced_env):
    with pytest.raises(ValueError, match="model name"):
        BasetenProvider("")
    with pytest.raises(ValueError, match="model name"):
        build_roles({Role.DEFENDER: RoleConfig(provider="baseten")})


def test_missing_price_refuses_to_build(monkeypatch):
    """With no table entry and no env override, building refuses (ValueError)."""
    monkeypatch.delenv("EXHIBIT_A_PRICE_IN_PER_MTOK", raising=False)
    monkeypatch.delenv("EXHIBIT_A_PRICE_OUT_PER_MTOK", raising=False)
    monkeypatch.setenv("BASETEN_API_KEY", "k")
    assert baseten_module.BASENTEN_PRICING.get("no-such-model") is None
    with pytest.raises(ValueError, match="no known price"):
        BasetenProvider("no-such-model")
    with pytest.raises(ValueError, match="no known price"):
        build_roles(
            {Role.DEFENDER: RoleConfig(provider="baseten", model="no-such-model")}
        )


def test_missing_price_refuses_to_run_even_if_constructed(monkeypatch, priced_env):
    """The complete-time backstop raises ProviderError on an unpriced provider."""
    priced_env.setenv("BASETEN_API_KEY", "k")
    capture(monkeypatch, REPLY)
    provider = BasetenProvider("m")
    provider.pricing = Pricing()
    with pytest.raises(ProviderError, match="no known price"):
        provider.complete(Role.FIXER, "p", SCHEMA)


def test_env_price_override_is_used(monkeypatch, priced_env):
    priced_env.setenv("BASETEN_API_KEY", "k")
    capture(monkeypatch, REPLY)
    meter = CostMeter(10.0)
    provider = BasetenProvider("unlisted-model")
    assert provider.pricing == PRICED
    result = ModelRole(Role.TEST_WRITER, provider, meter).run("hi", SCHEMA)
    assert result.cost_usd == pytest.approx(PRICED.cost(100, 50))
    assert meter.total_usd == pytest.approx(result.cost_usd)


def test_explicit_pricing_wins_over_env(monkeypatch, priced_env):
    priced_env.setenv("BASETEN_API_KEY", "k")
    capture(monkeypatch, REPLY)
    provider = BasetenProvider("m", pricing=Pricing(2.0, 4.0))
    assert provider.pricing == Pricing(2.0, 4.0)


def test_table_entry_is_used_when_present(monkeypatch, priced_env):
    priced_env.setenv("BASETEN_API_KEY", "k")
    monkeypatch.setitem(
        baseten_module.BASENTEN_PRICING, "listed-model", Pricing(1.0, 2.0)
    )
    monkeypatch.delenv("EXHIBIT_A_PRICE_IN_PER_MTOK")
    monkeypatch.delenv("EXHIBIT_A_PRICE_OUT_PER_MTOK")
    assert BasetenProvider("listed-model").pricing == Pricing(1.0, 2.0)


def test_malformed_env_price_is_no_price(monkeypatch):
    monkeypatch.setenv("BASETEN_API_KEY", "k")
    for raw_in, raw_out in [
        ("bogus", "15.0"),
        ("3.0", "bogus"),
        ("-1.0", "15.0"),
        ("0.0", "0.0"),
        ("nan", "15.0"),
    ]:
        monkeypatch.setenv("EXHIBIT_A_PRICE_IN_PER_MTOK", raw_in)
        monkeypatch.setenv("EXHIBIT_A_PRICE_OUT_PER_MTOK", raw_out)
        with pytest.raises(ValueError, match="no known price"):
            BasetenProvider("unlisted-model")


def test_build_roles_registers_baseten_by_name(monkeypatch, priced_env):
    priced_env.setenv("BASETEN_API_KEY", "k")
    capture(monkeypatch, REPLY)
    roles = build_roles(
        {
            Role.ADVERSARY: RoleConfig(provider="baseten", model="m1"),
            "fixer": {
                "provider": "baseten",
                "model": "m1",
                "pricing": {"input_per_mtok": 2.0, "output_per_mtok": 4.0},
            },
        }
    )
    assert isinstance(roles[Role.ADVERSARY].provider, DirectBasetenProvider)
    assert roles[Role.ADVERSARY].provider.model == "m1"
    # Explicit pricing in config wins over the env override.
    assert roles[Role.FIXER].provider.pricing == Pricing(2.0, 4.0)
    assert roles[Role.FIXER].run("hi", SCHEMA).output == {"verdict": "yes"}


def test_factory_without_key_refuses_to_start(monkeypatch):
    """build_roles fails fast without a key, before any model call."""
    monkeypatch.delenv("BASETEN_API_KEY", raising=False)
    monkeypatch.setenv("EXHIBIT_A_PRICE_IN_PER_MTOK", "3.0")
    monkeypatch.setenv("EXHIBIT_A_PRICE_OUT_PER_MTOK", "15.0")
    with pytest.raises(ValueError, match="BASETEN_API_KEY"):
        build_roles({Role.DEFENDER: RoleConfig(provider="baseten", model="m")})


def test_schema_invalid_answer_is_discarded_never_proven(monkeypatch, priced_env):
    """Answers that fail schema validation raise; ModelRole never returns them."""
    priced_env.setenv("BASETEN_API_KEY", "k")
    capture(monkeypatch, {"choices": [{"message": {"content": "not json"}}]})
    with pytest.raises(SchemaValidationError):
        ModelRole(Role.ADVERSARY, BasetenProvider("m")).run("hi", SCHEMA)
    capture(monkeypatch, {"choices": [{"message": {"content": '{"verdict": "maybe"}'}}]})
    with pytest.raises(SchemaValidationError):
        ModelRole(Role.ADVERSARY, BasetenProvider("m")).run("hi", SCHEMA)


def test_key_never_reaches_errors_recordings_or_ledger(
    monkeypatch, tmp_path, priced_env
):
    """The key value must not appear in errors, recordings, or ledger events."""
    priced_env.setenv("BASETEN_API_KEY", SECRET)

    def boom(url, body, headers, timeout):
        raise ProviderError("HTTP 500 from https://inference.baseten.co/v1")

    monkeypatch.setattr(openai_compat, "post_json", boom)
    provider = BasetenProvider("m")
    with pytest.raises(ProviderError) as info:
        ModelRole(Role.FIXER, provider).run("p", SCHEMA)
    assert SECRET not in str(info.value)

    capture(monkeypatch, REPLY)
    recording = tmp_path / "recording.jsonl"
    result = ModelRole(
        Role.FIXER, RecordingProvider(recording, BasetenProvider("m"))
    ).run("p", SCHEMA)
    assert result.output == {"verdict": "yes"}
    assert SECRET not in recording.read_text(encoding="utf-8")

    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append(
        Event(
            ts="2026-10-31T00:00:00+00:00",
            run_id="key-leak-probe",
            type=EventType.SUSPICION_RAISED,
            role=result.role.value,
            model=result.model,
            tokens_in=result.tokens_in,
            tokens_out=result.tokens_out,
            cost_usd=result.cost_usd,
            latency_ms=result.latency_ms,
            payload={"output": result.output},
        )
    )
    assert SECRET not in (tmp_path / "ledger.jsonl").read_text(encoding="utf-8")
    assert "Authorization" not in (tmp_path / "ledger.jsonl").read_text(
        encoding="utf-8"
    )


def test_run_refuses_to_start_without_key_or_price(tmp_path, monkeypatch, capsys):
    """`run --provider baseten` fails before any model call, with clear messages."""
    from exhibit_a.cli import run as run_mod

    case_dir = tmp_path / "case"
    (case_dir / "tree").mkdir(parents=True)
    (case_dir / "tree" / "app.py").write_text("x = 1\n")
    (case_dir / "baseline_test.py").write_text("def test_ok():\n    assert True\n")
    (case_dir / "case.json").write_text(
        json.dumps(
            {
                "cases": [{"id": "baseten-refusal"}],
                "run": {
                    "tree": "tree",
                    "source_file": "app.py",
                    "baseline_test": "baseline_test.py",
                },
            }
        )
    )

    def args(out):
        import argparse

        return argparse.Namespace(
            case=str(case_dir / "case.json"),
            out=str(out),
            replay=False,
            provider="baseten",
            model="some-model",
            budget_usd=10.0,
            repo=".",
            diff=None,
        )

    monkeypatch.delenv("BASETEN_API_KEY", raising=False)
    monkeypatch.delenv("EXHIBIT_A_PRICE_IN_PER_MTOK", raising=False)
    monkeypatch.delenv("EXHIBIT_A_PRICE_OUT_PER_MTOK", raising=False)
    assert run_mod.cmd_run(args(tmp_path / "out1")) == 1
    err = capsys.readouterr().err
    assert "baseten" in err and "BASETEN_API_KEY" in err

    monkeypatch.setenv("BASETEN_API_KEY", "k")
    assert run_mod.cmd_run(args(tmp_path / "out2")) == 1
    err = capsys.readouterr().err
    assert "baseten" in err and "no known price" in err

    # A priced key still reaches the registry as a Baseten provider (no network here).
    monkeypatch.setenv("EXHIBIT_A_PRICE_IN_PER_MTOK", "3.0")
    monkeypatch.setenv("EXHIBIT_A_PRICE_OUT_PER_MTOK", "15.0")
    roles = run_mod._live_roles(args(tmp_path / "out3"), None)
    for entry in (roles.adversary, roles.test_writer, roles.fixer, roles.defender):
        assert isinstance(entry.provider, DirectBasetenProvider)
        assert entry.provider.model == "some-model"


def test_provider_name_is_baseten_and_error_is_model_error(priced_env):
    assert DirectBasetenProvider.name == "baseten"
    assert issubclass(ProviderError, ModelError)
