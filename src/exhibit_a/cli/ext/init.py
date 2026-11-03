"""Implementation of the ``init`` CLI subcommand (extension module).

Writes a GitHub Actions workflow that runs the Exhibit A Action on pull
requests. No secret values are written: the workflow only references a
protected-environment secret by name.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..banner import print_banner

# Full commit SHAs (tags are mutable). Update these constants when bumping
# actions/checkout or the Exhibit A Action, then re-run ``exhibit-a init --force``.
CHECKOUT_ACTION = "actions/checkout"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"  # actions/checkout v7.0.1
EXHIBIT_A_ACTION = "diego-do-na/Exhibit-A"
EXHIBIT_A_ACTION_SHA = "8f0ac3ddcefb33edc15fc7f8b1126b9d3c683846"  # origin/main

DEFAULT_PATH = ".github/workflows/exhibit-a.yml"

# Placeholders are replaced after the string is built so GitHub ``${{ }}``
# expressions are not interpreted by str.format.
WORKFLOW_TEMPLATE = """\
# Exhibit A: prove vulnerabilities in this pull request before reporting them.
# Red only when a finding is proven in an isolated, resource-limited sandbox.
# Green means "nothing could be proven", never that the change is safe.
#
# Inert until the repository variable EXHIBIT_A_ENABLED is "true". Pins below
# are full commit SHAs. Update CHECKOUT_SHA / EXHIBIT_A_ACTION_SHA in
# src/exhibit_a/cli/ext/init.py and re-run `exhibit-a init --force`.
#
# The Action runs `exhibit-a run --pr-diff --profile compact --slice`.

name: Exhibit A

on:
  # Never pull_request_target: it runs with secrets in the base repository's
  # context and is the classic way to leak them to untrusted PR code.
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions: {}

concurrency:
  group: exhibit-a-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  verify:
    name: exhibit-a / verify
    if: >-
      vars.EXHIBIT_A_ENABLED == 'true' &&
      github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    timeout-minutes: 45
    environment: exhibit-a
    permissions:
      contents: read
      pull-requests: write
    steps:
      - name: Check out the PR head
        uses: __CHECKOUT_ACTION__@__CHECKOUT_SHA__
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Exhibit A
        uses: __EXHIBIT_A_ACTION__@__EXHIBIT_A_SHA__
        with:
          api-key: ${{ secrets.EXHIBIT_A_API_KEY }}
          profile: compact
          comment: "true"
          suggest-fixes: "true"

  fork-guard:
    name: exhibit-a / fork-guard
    if: >-
      vars.EXHIBIT_A_ENABLED == 'true' &&
      github.event.pull_request.head.repo.full_name != github.repository
    runs-on: ubuntu-latest
    timeout-minutes: 2
    permissions: {}
    steps:
      - name: Fork PRs are out of scope
        run: |
          {
            echo "## Exhibit A: fork PR not analysed"
            echo
            echo "Pull requests from forks are out of scope: they cannot receive the model"
            echo "API key safely. Nothing was verified, so nothing could be proven."
            echo "A maintainer must review this PR by hand."
          } >> "$GITHUB_STEP_SUMMARY"
          echo "::error title=Exhibit A::fork PRs are not analysed; a maintainer must review"
          exit 1
"""

MANUAL_STEPS = """\
Next steps (manual):
  1. Create the 'exhibit-a' environment, then its secret:
       gh secret set EXHIBIT_A_API_KEY --env exhibit-a
  2. Enable the workflow with repository variable EXHIBIT_A_ENABLED=true:
       gh variable set EXHIBIT_A_ENABLED --body true
  3. Require status checks 'exhibit-a / verify' and 'exhibit-a / fork-guard'
     on the default branch (Settings > Rules / branch protection).
Merges are blocked only with branch protection; a repository admin can bypass.
"""


def workflow_text() -> str:
    """Return the workflow YAML with current SHA pins substituted."""
    return (
        WORKFLOW_TEMPLATE
        .replace("__CHECKOUT_ACTION__", CHECKOUT_ACTION)
        .replace("__CHECKOUT_SHA__", CHECKOUT_SHA)
        .replace("__EXHIBIT_A_ACTION__", EXHIBIT_A_ACTION)
        .replace("__EXHIBIT_A_SHA__", EXHIBIT_A_ACTION_SHA)
    )


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(getattr(args, "path", None) or DEFAULT_PATH)
    if target.exists() and not getattr(args, "force", False):
        print(f"init: {target} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(workflow_text(), encoding="utf-8", newline="\n")
    print_banner(args)
    print(f"init: wrote {target}")
    print(MANUAL_STEPS, end="" if MANUAL_STEPS.endswith("\n") else "\n")
    return 0


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``init`` subcommand to the CLI."""
    parser = sub.add_parser(
        "init",
        help="Write a GitHub Actions workflow that runs Exhibit A on pull requests.",
    )
    parser.add_argument(
        "--path",
        default=None,
        metavar="FILE",
        help="Where to write the workflow (default: .github/workflows/exhibit-a.yml).",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite an existing workflow file.")
    parser.set_defaults(func=cmd_init)
