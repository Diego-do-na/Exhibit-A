"""Docker-marked tests are partitioned into disjoint CI shards that cover the suite.

These tests collect with ``pytest -m docker --collect-only``. They never skip,
deselect, or weaken a sandbox assertion, and they do not start a container.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

from exhibit_a.ci.sandbox_shards import (
    SPLITS,
    collect_docker_counts,
    partition_files,
    python_requirement_sets,
    shard_files,
)
from exhibit_a.sandbox.runner import PYTEST_VERSION

ROOT = Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _collect_nodeids(files: list[str] | None = None) -> set[str]:
    cmd = [sys.executable, "-m", "pytest", "-m", "docker", "--collect-only", "-q"]
    if files:
        cmd.extend(files)
    env = dict(os.environ)
    env.setdefault("PYTHONPATH", str(ROOT / "src") + os.pathsep + str(ROOT))
    done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env, timeout=120)
    assert done.returncode in (0, 1), done.stderr[-2000:]
    ids = set()
    for line in done.stdout.splitlines():
        text = line.strip()
        if text.startswith("tests/") and "::" in text:
            ids.add(text)
    return ids


def test_partition_is_disjoint_and_covers_every_file():
    counts = collect_docker_counts()
    files = {path for path, _ in counts}
    bins = partition_files(counts, SPLITS)
    assert len(bins) == SPLITS
    seen: list[str] = []
    for group in bins:
        assert group, "a shard with no docker tests would look skipped"
        overlap = set(seen) & set(group)
        assert not overlap, overlap
        seen.extend(group)
    assert set(seen) == files


def test_union_of_shard_nodeids_equals_all_docker_tests():
    all_ids = _collect_nodeids()
    assert all_ids, "pytest collected no docker-marked tests"
    union: set[str] = set()
    for group in range(1, SPLITS + 1):
        shard_ids = _collect_nodeids(shard_files(group))
        overlap = union & shard_ids
        assert not overlap, f"shard {group} re-runs {sorted(overlap)[:5]}"
        union |= shard_ids
    assert union == all_ids
    assert sum(n for _, n in collect_docker_counts()) == len(all_ids)


def test_prebuild_sets_include_the_pytest_image_the_runner_uses():
    sets = python_requirement_sets()
    assert [PYTEST_VERSION] in sets
    assert any("starlette==0.26.1" in reqs for reqs in sets)
    assert all(reqs[0] == PYTEST_VERSION for reqs in sets)


def test_ci_workflow_splits_sandbox_into_four_shards_and_a_gate():
    workflow = yaml.safe_load(CI_YML.read_text(encoding="utf-8"))
    test_job = workflow["jobs"]["test"]
    assert "strategy" not in test_job
    assert any(
        "not docker and not ollama and not integration" in str(step.get("run", ""))
        for step in test_job["steps"]
    )

    sandbox = workflow["jobs"]["sandbox"]
    assert sandbox["timeout-minutes"] == 30
    assert sandbox["strategy"]["fail-fast"] is False
    assert sandbox["strategy"]["matrix"]["shard"] == [1, 2, 3, 4]
    runs = "\n".join(str(step.get("run", "")) for step in sandbox["steps"])
    assert "exhibit_a.ci.sandbox_shards --prebuild" in runs
    assert "--group ${{ matrix.shard }} --run" in runs
    assert "build_image([])" not in runs
    assert "pytest -m docker" not in runs

    for step in sandbox["steps"]:
        uses = step.get("uses", "")
        if "@" in uses:
            ref = uses.split("@", 1)[1]
            assert SHA40.match(ref), uses

    gate = workflow["jobs"]["sandbox-complete"]
    assert gate["needs"] == "sandbox"
    assert gate["if"] == "always()"
    script = "\n".join(str(step.get("run", "")) for step in gate["steps"])
    assert "needs.sandbox.result" in script
    assert "exit 1" in script
    assert "cancelled" in script.lower() or "failed or were cancelled" in script
