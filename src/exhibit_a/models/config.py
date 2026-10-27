"""Per-role provider/model configuration (SPEC section 5).

Each Role gets one declarative entry naming a provider plus the model and pricing
to use with it. Providers are resolved by name through a small registry so new
backends (for example the Meta provider) can plug in without touching this file.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .base import ModelRole, Provider, Role
from .cost import CostMeter, Pricing
from .ollama import OllamaProvider
from .openai_compat import OpenAICompatibleProvider
from .replay import ReplayProvider

#: ModelRole instances keyed by Role, ready to run prompts.
Roles = dict[Role, ModelRole]


@dataclass(frozen=True)
class RoleConfig:
    """Declarative settings for one role: which provider, which model, at what price."""

    provider: str = "replay"
    model: str = ""
    base_url: str = ""
    api_key_env: str = ""
    recording: str = ""
    timeout: float = 120.0
    pricing: Pricing = field(default_factory=Pricing)


#: Builds a Provider from a validated RoleConfig.
ProviderFactory = Callable[[RoleConfig], Provider]

PROVIDER_REGISTRY: dict[str, ProviderFactory] = {}


def register_provider(name: str, factory: ProviderFactory) -> None:
    """Add (or replace) a provider factory under `name`."""
    if not name or not isinstance(name, str):
        raise ValueError("provider name must be a non-empty string")
    if not callable(factory):
        raise ValueError("provider factory must be callable")
    PROVIDER_REGISTRY[name] = factory


def _replay_factory(spec: RoleConfig) -> Provider:
    if not spec.recording:
        raise ValueError("replay provider needs a recording path")
    return ReplayProvider(spec.recording)


def _ollama_factory(spec: RoleConfig) -> Provider:
    if not spec.model:
        raise ValueError("ollama provider needs a model name")
    return OllamaProvider(
        spec.model,
        base_url=spec.base_url or "http://localhost:11434",
        timeout=spec.timeout,
    )


def _openai_compatible_factory(spec: RoleConfig) -> Provider:
    if not spec.base_url:
        raise ValueError("openai_compatible provider needs a base_url")
    if not spec.model:
        raise ValueError("openai_compatible provider needs a model name")
    return OpenAICompatibleProvider(
        spec.base_url,
        spec.model,
        spec.api_key_env,
        pricing=spec.pricing,
        timeout=spec.timeout,
    )


register_provider("replay", _replay_factory)
register_provider("ollama", _ollama_factory)
register_provider("openai_compatible", _openai_compatible_factory)


def _coerce_pricing(raw: Pricing | Mapping[str, Any]) -> Pricing:
    if isinstance(raw, Pricing):
        return raw
    if isinstance(raw, Mapping):
        try:
            return Pricing(**dict(raw))
        except TypeError as exc:
            raise ValueError(f"invalid pricing mapping: {exc}") from exc
    raise ValueError(f"pricing must be a Pricing or a mapping, got {type(raw).__name__}")


def _coerce_spec(raw: RoleConfig | Mapping[str, Any]) -> RoleConfig:
    if isinstance(raw, RoleConfig):
        return raw
    if isinstance(raw, Mapping):
        values = dict(raw)
        if "pricing" in values:
            values["pricing"] = _coerce_pricing(values["pricing"])
        try:
            return RoleConfig(**values)
        except TypeError as exc:
            raise ValueError(f"invalid role config: {exc}") from exc
    raise ValueError(f"role config must be a RoleConfig or a mapping, got {type(raw).__name__}")


def build_roles(
    config: Mapping[Role | str, RoleConfig | Mapping[str, Any]],
    meter: CostMeter | None = None,
) -> Roles:
    """Build one ModelRole per entry, all sharing the optional cost meter."""
    roles: Roles = {}
    for key, raw in config.items():
        try:
            role = key if isinstance(key, Role) else Role(str(key))
        except ValueError as exc:
            raise ValueError(f"unknown role {key!r}") from exc
        spec = _coerce_spec(raw)
        if spec.provider == "meta":
            raise ValueError("meta provider is planned but not built yet")
        try:
            factory = PROVIDER_REGISTRY[spec.provider]
        except KeyError:
            known = sorted(PROVIDER_REGISTRY)
            raise ValueError(
                f"unknown provider {spec.provider!r} for role {role.value}; "
                f"known providers: {known}"
            ) from None
        roles[role] = ModelRole(role, factory(spec), meter)
    return roles
