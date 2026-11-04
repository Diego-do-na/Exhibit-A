"""Implementation of the ``init`` CLI subcommand (extension module).

Writes a GitHub Actions workflow that runs the Exhibit A Action on pull
requests. No secret values are written: the workflow only references a
protected-environment secret by name.
"""

from __future__ import annotations

import argparse
import difflib
import getpass
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from ..style import OK, SKIP, WARN, kv, next_steps, section, status

# Full commit SHAs (tags are mutable). Update these constants when bumping
# actions/checkout or the Exhibit A Action, then re-run ``exhibit-a init --force``.
CHECKOUT_ACTION = "actions/checkout"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"  # actions/checkout v7.0.1
EXHIBIT_A_ACTION = "diego-do-na/Exhibit-A"
EXHIBIT_A_ACTION_SHA = "9d881359c6181f5b8d5b44a4c2b554a351e0cf19"  # origin/main (stdin JS graph, init secrets)

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
  analyze:
    name: exhibit-a / analyze
    if: >-
      vars.EXHIBIT_A_ENABLED == 'true' &&
      github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    timeout-minutes: 45
    environment: exhibit-a
    permissions:
      contents: read
      pull-requests: write
    outputs:
      proven: ${{ steps.exhibit.outputs.proven }}
    steps:
      - name: Check out the PR head
        uses: __CHECKOUT_ACTION__@__CHECKOUT_SHA__
        with:
          persist-credentials: false
          fetch-depth: 0

      - name: Exhibit A
        id: exhibit
        uses: __EXHIBIT_A_ACTION__@__EXHIBIT_A_SHA__
        with:
          api-key: ${{ secrets.EXHIBIT_A_API_KEY }}
          profile: compact
          fail-on: never
          comment: "true"
          suggest-fixes: "true"__WITH_EXTRA__

  verify:
    name: exhibit-a / verify
    needs: analyze
    if: >-
      always() &&
      vars.EXHIBIT_A_ENABLED == 'true' &&
      github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions: {}
    steps:
      - name: Fail when a finding is proven
        env:
          ANALYZE: ${{ needs.analyze.result }}
          PROVEN: ${{ needs.analyze.outputs.proven }}
        run: |
          set -euo pipefail
          if [[ "$ANALYZE" != success ]]; then
            echo "::error title=Exhibit A::analyze did not succeed ($ANALYZE)"
            exit 1
          fi
          [[ "$PROVEN" =~ ^[0-9]+$ ]] || {
            echo "::error title=Exhibit A::proven count missing"
            exit 1
          }
          if [[ "$PROVEN" != 0 ]]; then
            echo "::error title=Exhibit A::$PROVEN proven finding(s)"
            exit 1
          fi

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

INIT_NEXT_STEPS = (
    "gh secret set EXHIBIT_A_API_KEY --env exhibit-a",
    "gh variable set EXHIBIT_A_ENABLED --body true",
    "exhibit-a dashboard",
)
INIT_NEXT_NOTE = (
    "Enable the workflow with repository variable EXHIBIT_A_ENABLED=true.\n"
    "Require status checks 'exhibit-a / verify' and 'exhibit-a / fork-guard' "
    "on the default branch (Settings > Rules / branch protection).\n"
    "Merges are blocked only with branch protection; a repository admin can bypass."
)
DIFF_LIMIT = 40
EXHIBIT_DIR = ".exhibit-a"


def _check_meta_base_url(value: str | None) -> str | None:
    """Validate ``--meta-base-url``; the key travels with the endpoint, so http is refused."""
    if value is None:
        return None
    url = value.strip().rstrip("/")
    if (
        len(url) <= len("https://x")
        or len(url) > 208
        or not url.startswith("https://")
        or any(char.isspace() for char in url)
    ):
        raise ValueError("init: --meta-base-url must be an https:// URL without spaces")
    return url


def _check_model(value: str | None) -> str | None:
    """Validate ``--model``: a single registry model id, never a sentence."""
    if value is None:
        return None
    model = value.strip()
    if (
        not model
        or len(model) > 64
        or any(char.isspace() for char in model)
        or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in model)
    ):
        raise ValueError("init: --model must be a single model id without spaces")
    return model


def workflow_text(meta_base_url: str | None = None, model: str | None = None) -> str:
    """Return the workflow YAML with current SHA pins substituted."""
    extra = ""
    if model is not None:
        extra += f"\n          model: {model}"
    if meta_base_url is not None:
        extra += f"\n        env:\n          META_BASE_URL: {meta_base_url}"
    return (
        WORKFLOW_TEMPLATE
        .replace("__CHECKOUT_ACTION__", CHECKOUT_ACTION)
        .replace("__CHECKOUT_SHA__", CHECKOUT_SHA)
        .replace("__EXHIBIT_A_ACTION__", EXHIBIT_A_ACTION)
        .replace("__EXHIBIT_A_SHA__", EXHIBIT_A_ACTION_SHA)
        .replace("__WITH_EXTRA__", extra)
    )


def repo_root_for(target: Path) -> Path:
    """Repository root that should hold ``.exhibit-a/`` for this workflow path."""
    resolved = target.expanduser()
    if not resolved.is_absolute():
        resolved = (Path.cwd() / resolved).resolve()
    else:
        resolved = resolved.resolve()
    parts = list(resolved.parts)
    if ".github" in parts:
        idx = parts.index(".github")
        return Path(*parts[:idx]) if idx else resolved.parent
    return resolved.parent


def short_diff(current: str, wanted: str, path: str) -> str:
    """A short unified diff so a human can see why init would rewrite the workflow."""
    lines = list(
        difflib.unified_diff(
            current.splitlines(),
            wanted.splitlines(),
            fromfile=path,
            tofile="exhibit-a init template",
            lineterm="",
            n=2,
        )
    )
    if len(lines) > DIFF_LIMIT:
        lines = lines[:DIFF_LIMIT] + ["..."]
    return "\n".join(lines)


def compact_graph_summary(raw: dict) -> dict:
    """Map ``scan --graph`` output onto the compact artifact-schema.md object."""
    stats = raw.get("stats") if isinstance(raw.get("stats"), dict) else {}
    names: list[str] = []
    for item in raw.get("entries") or []:
        if isinstance(item, str) and item:
            names.append(item[:200])
        elif isinstance(item, dict):
            name = str(item.get("name") or item.get("oracle_name") or "")
            if name:
                names.append(name[:200])
        if len(names) >= 32:
            break
    compact_stats = {
        key: stats[key]
        for key in ("files", "nodes", "edges", "resolved", "external", "unresolved")
        if key in stats and isinstance(stats[key], (int, float)) and not isinstance(stats[key], bool)
    }
    return {
        "schema_version": "1",
        "available": True,
        "status": "built",
        "effect": "",
        "reason": "",
        "stats": compact_stats,
        "build_seconds": raw.get("build_seconds"),
        "entries": names,
        "changed": [],
        "paths": [],
        "paths_to_other_sinks": 0,
        "source_file": "",
    }


def write_scan_files(repo: Path) -> tuple[Path, Path | None]:
    """Run ``exhibit-a scan --graph`` on ``repo`` and write ``.exhibit-a/`` files."""
    from exhibit_a.cli.scan import _graph_builder, graph_summary
    from exhibit_a.scan import detect

    exhibit = repo / EXHIBIT_DIR
    exhibit.mkdir(parents=True, exist_ok=True)
    result = detect(str(repo))
    profile_path = exhibit / "profile.json"
    profile_path.write_text(result.profile.model_dump_json(indent=2) + "\n", encoding="utf-8")
    language = result.profile.language
    if language not in ("python", "javascript", "typescript"):
        language = "python"
    try:
        build, _, _, _ = _graph_builder(language)
        started = time.perf_counter()
        graph = build(repo)
        raw = graph_summary(graph, time.perf_counter() - started, language=language)
        summary_path = exhibit / "graph-summary.json"
        summary_path.write_text(
            json.dumps(compact_graph_summary(raw), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, TypeError):
        return profile_path, None
    return profile_path, summary_path


def _write_workflow(target: Path, text: str, *, backup: bool) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if backup and target.exists():
        shutil.copy2(target, target.with_name(target.name + ".bak"))
    target.write_text(text, encoding="utf-8", newline="\n")


def _github_slug(repo: Path) -> str | None:
    """Return ``owner/name`` from the origin remote, or None without a GitHub remote."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    match = re.search(r"github\.com[:/]([^/\s]+/[^/\s]+?)(?:\.git)?\s*$", proc.stdout.strip())
    return match.group(1) if match else None


def _gh_setup(slug: str, key: str) -> tuple[bool, bool]:
    """Store the API key secret and the enable flag. Never raises, never prints the key."""
    try:
        secret = subprocess.run(
            ["gh", "secret", "set", "EXHIBIT_A_API_KEY", "--env", "exhibit-a", "--repo", slug],
            input=key + "\n", capture_output=True, text=True, timeout=60,
        )
        variable = subprocess.run(
            ["gh", "variable", "set", "EXHIBIT_A_ENABLED", "--body", "true", "--repo", slug],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return False, False
    return secret.returncode == 0, variable.returncode == 0


def _maybe_store_secrets(repo: Path) -> None:
    """Offer one-time secret setup when running interactively with ``gh``.

    The key is piped to ``gh secret set`` via stdin, so it never lands in an
    argument list or a file. Anything missing degrades to the printed commands.
    """
    if not sys.stdin.isatty() or shutil.which("gh") is None:
        return
    slug = _github_slug(repo)
    if slug is None:
        status(SKIP, "no GitHub origin remote; create the secret by hand")
        return
    try:
        key = getpass.getpass(f"EXHIBIT_A_API_KEY for {slug} (empty to skip): ")
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        status(SKIP, "no key entered; create the secret by hand")
        return
    if not key.strip():
        status(SKIP, "no key entered; create the secret by hand")
        return
    stored, enabled = _gh_setup(slug, key.strip())
    if stored:
        status(OK, "stored EXHIBIT_A_API_KEY")
    else:
        status(WARN, "gh secret set failed; create it by hand")
    if enabled:
        status(OK, "set EXHIBIT_A_ENABLED=true")
    else:
        status(WARN, "gh variable set failed; set it by hand")


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(getattr(args, "path", None) or DEFAULT_PATH)
    try:
        meta_url = _check_meta_base_url(getattr(args, "meta_base_url", None))
        model = _check_model(getattr(args, "model", None))
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    wanted = workflow_text(meta_url, model)
    force = bool(getattr(args, "force", False))
    update = bool(getattr(args, "update", False))
    if target.exists():
        current = target.read_text(encoding="utf-8")
        if current != wanted and not force and not update:
            print(f"init: {target} differs from the current template (use --update or --force)",
                  file=sys.stderr)
            diff = short_diff(current, wanted, str(target))
            if diff:
                print(diff, file=sys.stderr)
            return 2
        if current != wanted:
            _write_workflow(target, wanted, backup=update and not force)
    else:
        _write_workflow(target, wanted, backup=False)

    repo = repo_root_for(target)
    profile_path, summary_path = write_scan_files(repo)

    def shown(path: Path) -> str:
        try:
            return str(path.resolve().relative_to(repo.resolve()))
        except ValueError:
            return str(path)

    section("init")
    kv("wrote", shown(target))
    kv("profile", shown(profile_path))
    if summary_path is not None:
        kv("graph-summary", shown(summary_path))
        status(OK, "scan wrote profile and graph-summary")
    else:
        status(WARN, "scan wrote profile; graph-summary was not produced")
    next_steps(INIT_NEXT_STEPS, note=INIT_NEXT_NOTE)
    _maybe_store_secrets(repo)
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
    parser.add_argument(
        "--update",
        action="store_true",
        help="Replace a differing workflow after copying it to FILE.bak.",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite an existing workflow file.")
    parser.add_argument(
        "--meta-base-url",
        default=None,
        metavar="URL",
        help="Model base URL written into the workflow (META_BASE_URL). Must be https://.",
    )
    parser.add_argument(
        "--model",
        default=None,
        metavar="ID",
        help="Model id written into the workflow (must match the provider registry).",
    )
    parser.set_defaults(func=cmd_init)
