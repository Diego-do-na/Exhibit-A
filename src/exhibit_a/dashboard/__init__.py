"""Local dashboard: what Exhibit A proved over time, served on 127.0.0.1 only.

The dashboard is a read-only viewer of recorded runs. Each run is a ledger
(the single source of truth, SPEC.md section 9) plus, optionally, the result
JSON written by ``exhibit_a.ci.summary``. Runs come from a ``RunSource``:

- ``LocalRunsSource`` reads a directory of run folders.
- ``GitHubSource`` lists and downloads the same artifacts from GitHub Actions
  through the user's own ``gh`` CLI.

Everything a source returns is untrusted: ledgers are validated against the
``Event`` schema, sizes are capped, and the browser renders every string with
``textContent``. See ``docs/dashboard.md`` for the threat model.
"""

from .model import (
    STAGES,
    TREND_VERDICTS,
    build_trends,
    run_detail,
    run_row,
)
from .server import DashboardServer, create_server, main, make_handler
from .sources import (
    GhError,
    GitHubSource,
    LocalRunsSource,
    RunData,
    RunRef,
    RunSource,
    SourceError,
    parse_source,
)

__all__ = [
    "STAGES",
    "TREND_VERDICTS",
    "DashboardServer",
    "GhError",
    "GitHubSource",
    "LocalRunsSource",
    "RunData",
    "RunRef",
    "RunSource",
    "SourceError",
    "build_trends",
    "create_server",
    "main",
    "make_handler",
    "parse_source",
    "run_detail",
    "run_row",
]
