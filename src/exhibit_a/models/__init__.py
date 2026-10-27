"""Model roles and providers (SPEC section 5)."""

from .base import Completion, ModelRole, Provider, Role, RoleResult
from .config import (
    PROVIDER_REGISTRY,
    ProviderFactory,
    RoleConfig,
    Roles,
    build_roles,
    register_provider,
)
from .cost import CostMeter, Pricing
from .errors import (
    BudgetExceeded,
    ModelError,
    ProviderError,
    ReplayMiss,
    SchemaValidationError,
    UnsupportedSchemaError,
)
from .ollama import OllamaProvider
from .openai_compat import OpenAICompatibleProvider
from .replay import ReplayProvider

__all__ = [
    "BudgetExceeded",
    "Completion",
    "CostMeter",
    "ModelError",
    "ModelRole",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "Pricing",
    "PROVIDER_REGISTRY",
    "Provider",
    "ProviderError",
    "ProviderFactory",
    "ReplayMiss",
    "Role",
    "RoleConfig",
    "RoleResult",
    "Roles",
    "build_roles",
    "SchemaValidationError",
    "UnsupportedSchemaError",
    "ReplayProvider",
    "register_provider",
]
