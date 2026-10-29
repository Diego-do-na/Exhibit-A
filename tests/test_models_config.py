"""Tests for per-role provider/model configuration: registry, coercion, build_roles."""

import pytest

from exhibit_a.models import (
    PROVIDER_REGISTRY,
    Completion,
    CostMeter,
    ModelRole,
    OllamaProvider,
    OpenAICompatibleProvider,
    Pricing,
    ProviderError,
    ReplayProvider,
    Role,
    RoleConfig,
    build_roles,
    register_provider,
)
from exhibit_a.models.meta import MetaProvider

SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string", "enum": ["yes", "no"]}},
    "required": ["verdict"],
    "additionalProperties": False,
}


class FakeProvider:
    """Stands in for a real backend; returns canned JSON and records calls."""

    name = "test-fake"

    def __init__(self, pricing=None):
        self.pricing = pricing or Pricing()
        self.calls = []

    def complete(self, role, prompt, schema):
        self.calls.append((role, prompt))
        return Completion('{"verdict": "yes"}', 10, 5, 3, "fake-model")


@pytest.fixture
def fake_backend():
    """Register a fake provider and restore the registry afterwards."""
    made = []

    def factory(spec):
        provider = FakeProvider(spec.pricing)
        made.append((spec, provider))
        return provider

    saved = dict(PROVIDER_REGISTRY)
    register_provider("test-fake", factory)
    try:
        yield made
    finally:
        PROVIDER_REGISTRY.clear()
        PROVIDER_REGISTRY.update(saved)


def test_registry_lists_the_builtin_providers():
    assert {"replay", "ollama", "openai_compatible", "meta"} <= set(PROVIDER_REGISTRY)


def test_build_roles_returns_one_model_role_per_role(fake_backend):
    config = {role: RoleConfig(provider="test-fake", model="m") for role in Role}
    roles = build_roles(config)
    assert set(roles) == set(Role)
    assert all(isinstance(entry, ModelRole) for entry in roles.values())
    assert {entry.role for entry in roles.values()} == set(Role)


def test_built_roles_run_and_share_the_meter(fake_backend):
    meter = CostMeter(10.0)
    pricing = Pricing(input_per_mtok=1000.0, output_per_mtok=2000.0)
    config = {
        Role.ADVERSARY: RoleConfig(provider="test-fake", pricing=pricing),
        Role.FIXER: RoleConfig(provider="test-fake", pricing=pricing),
    }
    roles = build_roles(config, meter=meter)
    assert roles[Role.ADVERSARY].run("p", SCHEMA).output == {"verdict": "yes"}
    assert roles[Role.FIXER].run("p", SCHEMA).output == {"verdict": "yes"}
    # (10 * 1000 + 5 * 2000) / 1e6 = 0.02 per call, both roles share one meter.
    assert meter.total_usd == pytest.approx(0.04)


def test_string_keys_and_plain_dict_specs_are_coerced(fake_backend):
    roles = build_roles(
        {
            "adversary": {
                "provider": "test-fake",
                "model": "m",
                "pricing": {"input_per_mtok": 1.0, "output_per_mtok": 2.0},
            }
        }
    )
    assert roles[Role.ADVERSARY].provider.pricing == Pricing(1.0, 2.0)


def test_replay_entry_points_at_its_recording(tmp_path):
    path = tmp_path / "rec.jsonl"
    roles = build_roles({Role.TEST_WRITER: RoleConfig(provider="replay", recording=str(path))})
    provider = roles[Role.TEST_WRITER].provider
    assert isinstance(provider, ReplayProvider)
    assert str(provider.path) == str(path)


@pytest.mark.parametrize(
    "spec",
    [
        RoleConfig(provider="replay"),  # no recording
        RoleConfig(provider="ollama"),  # no model
        RoleConfig(provider="openai_compatible", model="m"),  # no base_url
        RoleConfig(provider="openai_compatible", base_url="http://127.0.0.1:9"),  # no model
    ],
)
def test_factories_reject_missing_fields(spec):
    with pytest.raises(ValueError):
        build_roles({Role.FIXER: spec})


def test_builtin_factories_build_without_network():
    roles = build_roles(
        {
            Role.ADVERSARY: RoleConfig(provider="ollama", model="llama3"),
            Role.FIXER: RoleConfig(
                provider="openai_compatible",
                base_url="http://127.0.0.1:9/v1",
                model="meta-model",
                api_key_env="MISSING_KEY_FOR_TEST",
                pricing=Pricing(2.0, 4.0),
            ),
        }
    )
    ollama = roles[Role.ADVERSARY].provider
    assert isinstance(ollama, OllamaProvider) and ollama.model == "llama3"
    compat = roles[Role.FIXER].provider
    assert isinstance(compat, OpenAICompatibleProvider)
    assert compat.pricing == Pricing(2.0, 4.0)


def test_unknown_provider_name_is_rejected():
    with pytest.raises(ValueError, match="unknown provider"):
        build_roles({Role.DEFENDER: RoleConfig(provider="smoke-signals")})


def test_meta_provider_builds_from_env_key_without_network(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "fake-key-for-test")
    monkeypatch.delenv("META_BASE_URL", raising=False)
    roles = build_roles({Role.DEFENDER: RoleConfig(provider="meta", model="meta-model")})
    provider = roles[Role.DEFENDER].provider
    assert isinstance(provider, MetaProvider)
    assert provider.name == "meta"
    assert provider.model == "meta-model"


def test_meta_provider_missing_key_error_is_clear_and_does_not_leak(monkeypatch):
    monkeypatch.delenv("META_API_KEY", raising=False)
    monkeypatch.delenv("META_BASE_URL", raising=False)
    provider = build_roles({Role.DEFENDER: RoleConfig(provider="meta", model="m")})[
        Role.DEFENDER
    ].provider
    with pytest.raises(ProviderError) as excinfo:
        provider.complete(Role.DEFENDER, "p", SCHEMA)
    message = str(excinfo.value)
    assert "META_API_KEY" in message
    assert "fake-key-for-test" not in message


def test_unknown_role_key_is_rejected(fake_backend):
    with pytest.raises(ValueError, match="unknown role"):
        build_roles({"janitor": RoleConfig(provider="test-fake")})


def test_invalid_specs_are_rejected(fake_backend):
    with pytest.raises(ValueError):
        build_roles({Role.FIXER: {"provider": "test-fake", "no_such_field": 1}})
    with pytest.raises(ValueError):
        build_roles({Role.FIXER: {"provider": "test-fake", "pricing": {"bogus": 1}}})
    with pytest.raises(ValueError):
        build_roles({Role.FIXER: "test-fake"})


def test_register_provider_rejects_bad_arguments():
    with pytest.raises(ValueError):
        register_provider("", lambda spec: FakeProvider())
    with pytest.raises(ValueError):
        register_provider("test-bad", "not-callable")
