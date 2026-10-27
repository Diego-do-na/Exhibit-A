"""Exceptions raised by the model layer."""


class ModelError(Exception):
    """Base class for every model-layer failure."""


class ProviderError(ModelError):
    """The provider could not produce a completion (network, HTTP, bad envelope)."""


class SchemaValidationError(ModelError):
    """The model output is not valid JSON or does not satisfy the requested schema."""


class UnsupportedSchemaError(ModelError):
    """The requested JSON schema uses a keyword the validator does not implement."""


class ReplayMiss(ModelError):
    """The replay file has no recording for this request and no recorder is configured."""


class BudgetExceeded(ModelError):
    """Cumulative cost reached the configured hard limit."""
