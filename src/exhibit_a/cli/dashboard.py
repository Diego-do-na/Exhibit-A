"""Implementation of the ``dashboard`` CLI subcommand.

The live dashboard always opens on 127.0.0.1; it is never hosted. Source
defaults to ``local:runs`` when that folder exists, otherwise to
``github:<owner/repo>`` when the working directory is a git checkout with a
GitHub remote.
"""

from __future__ import annotations

import argparse
import importlib
import os
import subprocess
import sys
from pathlib import Path

from .style import kv, next_steps, section

USAGE_COMMANDS = (
    "  exhibit-a dashboard --source local:<dir>\n"
    "  exhibit-a dashboard --source github:<owner/repo>"
)


def parse_github_nwo(url: str) -> str | None:
    """Return ``owner/repo`` from a GitHub remote URL, or None."""
    raw = url.strip()
    if raw.endswith(".git"):
        raw = raw[: -len(".git")]
    raw = raw.rstrip("/")
    prefixes = (
        "https://github.com/",
        "https://www.github.com/",
        "http://github.com/",
        "http://www.github.com/",
        "git@github.com:",
        "ssh://git@github.com/",
        "git://github.com/",
    )
    lower = raw.lower()
    rest = None
    for prefix in prefixes:
        if lower.startswith(prefix):
            rest = raw[len(prefix) :]
            break
    if rest is None:
        return None
    parts = rest.split("/")
    if len(parts) != 2:
        return None
    owner, repo = parts
    if not owner or not repo or repo in {".", ".."}:
        return None
    if "/" in owner or "/" in repo:
        return None
    return f"{owner}/{repo}"


def github_source_from_cwd(cwd: Path) -> str | None:
    """Return ``github:owner/repo`` from git remotes of ``cwd``, preferring origin."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        done = subprocess.run(
            ["git", "remote", "-v"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0:
        return None
    urls: dict[str, str] = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, url = parts[0], parts[1]
        if name not in urls:
            urls[name] = url
    for name in ("origin", *tuple(urls)):
        nwo = parse_github_nwo(urls.get(name, ""))
        if nwo:
            return f"github:{nwo}"
    return None


def resolve_source(
    source: str | None,
    *,
    cwd: Path | None = None,
    export: bool = False,
) -> str | None:
    """Default the dashboard source to local runs, else a GitHub remote."""
    if source:
        return source
    root = cwd or Path.cwd()
    runs = root / "runs"
    if runs.is_dir() and any(child.is_dir() for child in runs.iterdir()):
        return "local:runs"
    if export:
        return None
    return github_source_from_cwd(root)


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Delegate to the optional local dashboard package."""
    try:
        importlib.import_module("exhibit_a.dashboard")
        server = importlib.import_module("exhibit_a.dashboard.server")
        dashboard_main = getattr(server, "main")
    except (ImportError, AttributeError):
        print("dashboard: dashboard not installed in this build", file=sys.stderr)
        return 2
    source = resolve_source(
        getattr(args, "source", None),
        export=bool(getattr(args, "export", None)),
    )
    if source is None:
        print(
            "dashboard: no runs found. The dashboard always opens on 127.0.0.1 "
            "(never hosted). Pass a source:\n"
            f"{USAGE_COMMANDS}",
            file=sys.stderr,
        )
        return 2
    if not getattr(args, "export", None):
        section("dashboard")
        kv("bind", "127.0.0.1 (never hosted)")
        kv("source", source)
        next_steps(
            (
                "exhibit-a dashboard --source local:<dir>",
                "exhibit-a dashboard --source github:<owner/repo>",
            )
        )
    forwarded = ["--source", source, "--port", str(getattr(args, "port", 0))]
    if getattr(args, "export", None):
        forwarded.extend(["--export", args.export])
    if getattr(args, "run", None):
        forwarded.extend(["--run", args.run])
    if getattr(args, "open", True):
        forwarded.append("--open")
    try:
        return int(dashboard_main(forwarded))
    except (OSError, ValueError) as exc:
        print(f"dashboard: {exc}", file=sys.stderr)
        return 1
