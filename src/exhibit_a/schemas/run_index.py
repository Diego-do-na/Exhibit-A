"""One line of runs.jsonl: the append-only history of runs for the dashboard and CLI."""

from datetime import datetime, timedelta
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import Field, field_validator

from .base import StrictModel

RUN_INDEX_SCHEMA_VERSION = "1"


class VerdictCounts(StrictModel):
    proven: int = Field(ge=0)
    discarded_unproven: int = Field(ge=0)
    invalid_test: int = Field(ge=0)
    flaky: int = Field(ge=0)
    env_failure: int = Field(ge=0)


class RunRecord(StrictModel):
    schema_version: Literal["1"] = RUN_INDEX_SCHEMA_VERSION
    run_id: str = Field(min_length=1)
    repo: str
    pr: int | None = Field(default=None, ge=0)
    commit: str
    ts: datetime  # timezone-aware, UTC
    status: Literal["completed", "aborted", "error"]
    verdict_counts: VerdictCounts  # proven counts unique findings (duplicate proofs grouped)
    proven_raw: int | None = Field(default=None, ge=0)  # proven verdicts before grouping; None = not recorded
    severity: Literal["low", "medium", "high", "critical"] | None = None  # highest proven
    discarded_suspicions: int = Field(ge=0)
    tokens_in: int = Field(ge=0)
    tokens_out: int = Field(ge=0)
    cost_usd: float = Field(ge=0)
    duration_s: float = Field(ge=0)
    ledger_path: str  # relative to the directory that holds the index

    @field_validator("ts")
    @classmethod
    def _ts_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("ts must be a timezone-aware UTC timestamp")
        return value

    @field_validator("ledger_path")
    @classmethod
    def _ledger_path_is_relative(cls, value: str) -> str:
        posix, windows = PurePosixPath(value), PureWindowsPath(value)
        if not value or posix.is_absolute() or windows.is_absolute() or windows.drive:
            raise ValueError("ledger_path must be a non-empty relative path")
        if ".." in posix.parts or ".." in windows.parts:
            raise ValueError("ledger_path must not contain '..'")
        return value
