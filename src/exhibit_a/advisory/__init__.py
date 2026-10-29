"""Known-advisory lookup for pinned PyPI dependencies (a second signal, never a proof).

See docs/advisory.md for what this can and cannot tell you.
"""

from .deps import (
    ParseResult,
    PinnedDependency,
    Unsupported,
    normalize_name,
    parse_pyproject,
    parse_requirement,
    parse_requirements,
)
from .osv import (
    Advisory,
    AdvisoryDataError,
    HttpOsvBackend,
    OsvBackend,
    RecordedOsvBackend,
    evaluate,
    parse_advisory,
)
from .reachability import reachability_hint
from .report import AdvisoryReport, lookup
from .version import InvalidVersion, Version, semver_key, upgrade_kind

__all__ = [
    "Advisory",
    "AdvisoryDataError",
    "AdvisoryReport",
    "HttpOsvBackend",
    "InvalidVersion",
    "OsvBackend",
    "ParseResult",
    "PinnedDependency",
    "RecordedOsvBackend",
    "Unsupported",
    "Version",
    "evaluate",
    "lookup",
    "normalize_name",
    "parse_advisory",
    "parse_pyproject",
    "parse_requirement",
    "parse_requirements",
    "reachability_hint",
    "semver_key",
    "upgrade_kind",
]
