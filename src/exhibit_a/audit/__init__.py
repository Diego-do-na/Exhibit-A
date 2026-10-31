"""Whole-repository audit: rank graph reach paths and prove the top targets.

The graph only proposes. Reachability is not exploitability: a path from an
entry point to a sink tells the loop where to look and which entry point the
oracle must see, but only sandboxed execution under the oracle proves anything.
A green audit means "nothing could be proven", never "safe".
"""

from .audit import collect_targets, run_audit
from .rank import AuditTarget, EFFECT_SEVERITY, ENTRY_EXPOSURE, group_by_sink, rank_key

__all__ = [
    "AuditTarget",
    "EFFECT_SEVERITY",
    "ENTRY_EXPOSURE",
    "collect_targets",
    "group_by_sink",
    "rank_key",
    "run_audit",
]
