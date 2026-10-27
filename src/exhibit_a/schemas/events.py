"""Ledger event line: one JSON object per line in the append-only log."""

from enum import Enum
from typing import Any

from pydantic import Field

from .base import StrictModel


class EventType(str, Enum):
    PR_OPENED = "pr_opened"
    SCAN_DONE = "scan_done"
    BASELINE_DONE = "baseline_done"
    SUSPICION_RAISED = "suspicion_raised"
    EXPLOIT_WRITTEN = "exploit_written"
    RUN_STARTED = "run_started"
    ORACLE_EVENT = "oracle_event"
    VERDICT = "verdict"
    FIX_PROPOSED = "fix_proposed"
    BYPASS_ATTEMPT = "bypass_attempt"
    BYPASS_RESULT = "bypass_result"
    PACKAGED = "packaged"


class Event(StrictModel):
    ts: str
    run_id: str
    type: EventType
    role: str = ""
    model: str = ""
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0)
    latency_ms: int = Field(default=0, ge=0)
    payload: dict[str, Any] = Field(default_factory=dict)
