"""Model roles and providers (SPEC section 5)."""

from .base import Completion, ModelRole, Provider, Role, RoleResult
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
    "Provider",
    "ProviderError",
    "ReplayMiss",
    "Role",
    "RoleResult",
    "SchemaValidationError",
    "UnsupportedSchemaError",
    "ReplayProvider",
]
