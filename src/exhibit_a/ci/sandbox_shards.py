"""Partition docker-marked tests into disjoint CI shards and pre-build images.

The GitHub Actions ``sandbox`` job used to run ``pytest -m docker`` serially
with a 60-minute timeout. Collection is hundreds of tests, each starting an
isolated and resource-limited container, so one runner cancelled at the job
limit. This module:

- collects every test marked ``docker``
- packs their files into ``SPLITS`` shards (greedy by test count)
- pre-builds the Python and Node sandbox images the suite actually uses
  (the old workflow called ``build_image([])``, which is not the pytest image)

Every docker-marked test belongs to exactly one shard. Images are tagged by
content hash and reused; each test still gets its own container.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

SPLITS = 4
REPO_ROOT = Path(__file__).resolve().parents[3]


def _pytest_cmd() -> list[str]:
    return [sys.executable, "-m", "pytest"]


def collect_docker_counts(root: Path | None = None) -> list[tuple[str, int]]:
    """Return ``(relative_path, docker_test_count)`` for every file with a docker test."""
    repo = root or REPO_ROOT
    env = dict(os.environ)
    env.setdefault("PYTHONPATH", str(repo / "src") + os.pathsep + str(repo))
    done = subprocess.run(
        [*_pytest_cmd(), "-m", "docker", "--collect-only", "-q"],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    if done.returncode not in (0, 1):
        raise RuntimeError(
            "pytest --collect-only -m docker failed:\n"
            + (done.stderr or done.stdout)[-4000:]
        )
    counts: dict[str, int] = {}
    for line in done.stdout.splitlines():
        text = line.strip()
        if not text.startswith("tests/") or "::" not in text:
            continue
        path = text.split("::", 1)[0]
        counts[path] = counts.get(path, 0) + 1
    if not counts:
        raise RuntimeError("pytest collected no docker-marked tests")
    return sorted(counts.items(), key=lambda item: item[0])


def partition_files(
    counts: Sequence[tuple[str, int]],
    splits: int = SPLITS,
) -> list[list[str]]:
    """Greedy bin-pack files into ``splits`` shards. Deterministic for a given collection."""
    if splits < 1:
        raise ValueError("splits must be >= 1")
    bins: list[list[str]] = [[] for _ in range(splits)]
    sizes = [0] * splits
    ordered = sorted(counts, key=lambda item: (-item[1], item[0]))
    for path, n in ordered:
        idx = min(range(splits), key=lambda i: (sizes[i], i))
        bins[idx].append(path)
        sizes[idx] += n
    for group in bins:
        group.sort()
    return bins


def shard_files(group: int, splits: int = SPLITS, root: Path | None = None) -> list[str]:
    """Return the test file paths for a 1-indexed shard."""
    if group < 1 or group > splits:
        raise ValueError(f"group must be in 1..{splits}, got {group}")
    return partition_files(collect_docker_counts(root), splits)[group - 1]


def _walk_requirement_lists(node: object, into: list[list[str]]) -> None:
    if isinstance(node, dict):
        raw = node.get("requirements")
        if isinstance(raw, list) and raw and all(isinstance(item, str) for item in raw):
            into.append([str(item) for item in raw])
        for value in node.values():
            _walk_requirement_lists(value, into)
    elif isinstance(node, list):
        for item in node:
            _walk_requirement_lists(item, into)


def _is_npm_spec(req: str) -> bool:
    return "@" in req and "==" not in req and ">=" not in req and "<" not in req


def corpus_requirement_sets(root: Path | None = None) -> tuple[list[tuple[str, ...]], list[tuple[str, ...]]]:
    """Pip and npm requirement tuples declared by corpus ``case.json`` files."""
    repo = root or REPO_ROOT
    pip_sets: set[tuple[str, ...]] = set()
    npm_sets: set[tuple[str, ...]] = set()
    for path in sorted((repo / "bench" / "corpus").glob("*/case.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        found: list[list[str]] = []
        _walk_requirement_lists(payload, found)
        for reqs in found:
            cleaned = tuple(sorted({item.strip() for item in reqs if item.strip()}))
            if not cleaned:
                continue
            if all(_is_npm_spec(item) for item in cleaned):
                npm_sets.add(cleaned)
            elif not any(_is_npm_spec(item) for item in cleaned):
                pip_sets.add(cleaned)
    return sorted(pip_sets), sorted(npm_sets)


def python_requirement_sets(root: Path | None = None) -> list[list[str]]:
    """Images the Python sandbox actually builds: pytest, then pytest + corpus deps."""
    from exhibit_a.sandbox.runner import PYTEST_VERSION

    sets: list[list[str]] = [[PYTEST_VERSION]]
    pip_sets, _ = corpus_requirement_sets(root)
    for extra in pip_sets:
        sets.append([PYTEST_VERSION, *extra])
    return sets


def node_package_sets(root: Path | None = None) -> list[list[str]]:
    _, npm_sets = corpus_requirement_sets(root)
    return [[], *[list(item) for item in npm_sets]]


def prebuild_images(root: Path | None = None) -> list[str]:
    """Build (or reuse) every common sandbox image. Safe to call more than once."""
    from exhibit_a.sandbox.image import build_image
    from exhibit_a.sandbox.image_node import build_node_image

    tags: list[str] = []
    seen: set[str] = set()
    for reqs in python_requirement_sets(root):
        tag = build_image(reqs)
        if tag not in seen:
            tags.append(tag)
            seen.add(tag)
    for pkgs in node_package_sets(root):
        tag = build_node_image(pkgs)
        if tag not in seen:
            tags.append(tag)
            seen.add(tag)
    return tags


def run_shard(group: int, splits: int = SPLITS, pytest_args: Sequence[str] | None = None) -> int:
    files = shard_files(group, splits)
    cmd = [*_pytest_cmd(), "-m", "docker", *files, *(pytest_args or ())]
    return subprocess.call(cmd, cwd=REPO_ROOT)


def _print_shards(splits: int) -> None:
    counts = collect_docker_counts()
    total = sum(n for _, n in counts)
    bins = partition_files(counts, splits)
    by_file = dict(counts)
    print(f"docker tests: {total} in {len(counts)} files, {splits} shards")
    for i, group in enumerate(bins, start=1):
        n = sum(by_file[path] for path in group)
        print(f"shard {i}/{splits}: {n} tests, {len(group)} files")
        for path in group:
            print(f"  {by_file[path]:4d}  {path}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--splits", type=int, default=SPLITS)
    parser.add_argument("--group", type=int, default=0, help="1-indexed shard to print or run")
    parser.add_argument("--run", action="store_true", help="exec pytest -m docker on that shard")
    parser.add_argument("--prebuild", action="store_true", help="build common sandbox images once")
    parser.add_argument("--list", action="store_true", help="print every shard and its files")
    parser.add_argument(
        "pytest_args",
        nargs=argparse.REMAINDER,
        help="extra pytest flags; pass after -- (example: --run -- -q --durations=40)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    extra = list(args.pytest_args)
    if extra and extra[0] == "--":
        extra = extra[1:]
    args.pytest_args = extra
    if args.splits < 1:
        print("splits must be >= 1", file=sys.stderr)
        return 2
    if args.prebuild:
        tags = prebuild_images()
        for tag in tags:
            print(tag)
        if not args.run and not args.list and not args.group:
            return 0
    if args.list and not args.group:
        _print_shards(args.splits)
        return 0
    if args.group:
        files = shard_files(args.group, args.splits)
        if args.run:
            return run_shard(args.group, args.splits, args.pytest_args)
        print("\n".join(files))
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
