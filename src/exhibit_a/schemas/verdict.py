"""verdict.json: the outcome of running an exploit test for a suspicion."""

from enum import Enum
from typing import Any

from pydantic import Field, model_serializer

from .base import StrictModel


class VerdictValue(str, Enum):
    PROVEN = "proven"
    DISCARDED_UNPROVEN = "discarded_unproven"
    INVALID_TEST = "invalid_test"
    FLAKY = "flaky"
    ENV_FAILURE = "env_failure"


class Evidence(StrictModel):
    test_path: str
    fails_on: str
    passes_on: str
    runs: int = Field(ge=1)
    oracle: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


class Fix(StrictModel):
    patch_path: str


class BypassAttempts(StrictModel):
    tried: int = Field(ge=0)
    succeeded: int = Field(ge=0)


class Verdict(StrictModel):
    suspicion_id: str
    verdict: VerdictValue
    evidence: Evidence | None = None
    fix: Fix | None = None
    bypass_attempts: BypassAttempts | None = None
    # Duplicate proofs of one effect (same entry point, same application frames to the sink,
    # see exhibit_a.findings): a primary lists the suspicions it absorbed, a duplicate names
    # its primary. Both stay empty for a finding of its own.
    duplicates: list[str] = Field(default_factory=list)
    duplicate_of: str | None = None

    @model_serializer(mode="wrap")
    def _omit_empty_grouping(self, handler):
        """Keep the documented verdict.json shape: the grouping keys appear only when set."""
        data = handler(self)
        for key in ("duplicates", "duplicate_of"):
            if not data.get(key):
                data.pop(key, None)
        return data
