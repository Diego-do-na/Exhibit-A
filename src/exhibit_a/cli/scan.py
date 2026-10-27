"""Implementation of the ``scan`` CLI subcommand."""

from __future__ import annotations

import argparse

from ..schemas import Baseline, RepoProfile


def cmd_scan(args: argparse.Namespace) -> int:
    """Print a RepoProfile placeholder as JSON."""
    _ = args
    profile = RepoProfile(
        commit="unknown",
        language="unknown",
        interpreter="unknown",
        dependency_manager="unknown",
        install_cmd="unknown",
        test_cmd="unknown",
        framework="unknown",
        dependencies=[],
        baseline=Baseline(passed=0, failed=0, seconds=0.0),
    )
    print(profile.model_dump_json(indent=2))
    return 0
