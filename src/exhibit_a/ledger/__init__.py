"""Append-only JSONL event log: the single source of truth (SPEC.md section 9).

Every line of the ledger file is one serialized Event. Lines are only ever
appended; this package offers no API to edit or delete them.
"""

from .ledger import Ledger

__all__ = ["Ledger"]
