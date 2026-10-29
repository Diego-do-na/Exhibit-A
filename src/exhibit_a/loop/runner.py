"""How the loop executes tests: the ``TestRunner`` seam and its sandbox-backed default.

The loop needs two kinds of execution:

* ``run_baseline`` runs the project's own tests and returns the sandbox result dict
  (``outcome``, ``exit_code``, ``stdout``, ``stderr``, ``oracle_events``);
* ``run_exploit`` runs an exploit test with the oracle and returns its ``Judgement``.

``SandboxRunner`` runs both inside the isolated, resource-limited Docker sandbox, on an
image that has the case's requirements baked in. For an exploit it stages a copy of the app
with the test in a private oracle directory, mounts the canary as a real read-only file in
the same allowed/outside layout the host oracle uses, and judges the oracle events written
inside the container with the oracle's own provenance rules, applied to the paths the
container saw. Unit tests inject a fake runner so they need no Docker.

The exploit path applies the same oracle defences as the host path (docs/oracle-a1.md,
docs/oracle-provenance.md): the static tripwire runs before staging (a hit is an ``error``
judgement, i.e. ``invalid_test``); the staged app is hashed and the manifest goes to the
plugin with the key; forged event lines and any change to the app tree reach the judgement
(``forged_events``, ``app_tree_changes``), and frames count as application code only if the
plugin admitted them and they match the staged copy kept on the host.
"""

from __future__ import annotations

import secrets
import shutil
import tempfile
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, runtime_checkable

from pydantic import ValidationError

from exhibit_a.oracle import Judgement, OracleEvent
from exhibit_a.oracle.guard import channel_problem
from exhibit_a.oracle.oracle import (
    ENV_ALLOWED_DIR,
    ENV_CANARY_TOKEN,
    REASON_CHANNEL_TRIPWIRE,
    TestOutcome,
    _judge,
)
from exhibit_a.oracle.provenance import AppTree, ManifestError, app_manifest

# Where the sandbox mounts the clone; frames recorded inside the container use these paths.
_WORKSPACE = PurePosixPath("/workspace")
_SCRATCH = "/tmp/exhibit_a_oracle"

# The canary is a real file (not a symlink), so apps that canonicalise paths resolve to it.
_CANARY_MOUNT = f"{_SCRATCH}/outside/canary.txt"

# Written next to the exploit. It runs inside the container before the test: it makes the app
# importable and fills the allowed directory beside the mounted canary.
_CONFTEST = f'''\
import os
import sys

sys.path.insert(0, {str(_WORKSPACE)!r})
_allowed = os.path.join({_SCRATCH!r}, "allowed")
os.makedirs(_allowed, exist_ok=True)
with open(os.path.join(_allowed, "public.txt"), "w", encoding="utf-8") as fh:
    fh.write("public file\\n")
'''


@runtime_checkable
class TestRunner(Protocol):
    def run_baseline(self, clone_path: str, test_path: str, timeout: float) -> dict[str, Any]:
        """Run the project's own tests on ``clone_path``; ``test_path`` is relative to it."""
        ...

    def run_exploit(
        self,
        app_root: Path,
        test_path: Path,
        entry_points: Collection[str],
        *,
        timeout: float,
    ) -> Judgement:
        """Run one exploit test against ``app_root`` and judge why it failed or passed."""
        ...


@dataclass(frozen=True)
class SandboxRunner:
    """Baseline and exploit runs in the Docker sandbox with the case's requirements.

    ``requirements`` are pip requirements baked into the pinned sandbox image (pytest is
    always included). ``image`` names an already built image and makes them unused.
    """

    requirements: Sequence[str] = ()
    image: str | None = None

    def run_baseline(self, clone_path: str, test_path: str, timeout: float) -> dict[str, Any]:
        from exhibit_a.sandbox import run

        return run(clone_path, test_path, timeout, requirements=list(self.requirements), image=self.image)

    def run_exploit(
        self,
        app_root: Path,
        test_path: Path,
        entry_points: Collection[str],
        *,
        timeout: float,
    ) -> Judgement:
        """Run the exploit in the sandbox and judge it; raises ``OSError`` if it could not run."""
        from exhibit_a.sandbox import run

        problem = channel_problem(Path(test_path))
        if problem is not None:
            # Not run at all, as on the host path: the loop classifies "error" as invalid_test.
            return Judgement(
                observed_effect=False, provenance_ok=False, reason=problem, test_outcome="error",
                reason_code=REASON_CHANNEL_TRIPWIRE,
            )
        oracle_dir = f"_exhibit_a_oracle_{secrets.token_hex(4)}"
        container_test = _WORKSPACE / oracle_dir / "test_exploit.py"
        token = "CANARY-" + secrets.token_hex(16)
        with tempfile.TemporaryDirectory(prefix="exhibit_a_exploit_") as tmp:
            stage = Path(tmp) / "app"
            shutil.copytree(app_root, stage)
            (stage / oracle_dir).mkdir()
            shutil.copyfile(test_path, stage / oracle_dir / "test_exploit.py")
            (stage / oracle_dir / "conftest.py").write_text(_CONFTEST, encoding="utf-8")
            canary = Path(tmp) / "canary.txt"
            canary.write_text(token + "\n", encoding="utf-8")
            # The stage is never mounted (the sandbox copies it), so it stays the host's
            # untouched copy of what the plugin's manifest describes.
            try:
                manifest = app_manifest(stage, {oracle_dir})
            except ManifestError as exc:
                raise OSError(f"cannot hash the staged app: {exc}") from exc
            result = run(
                str(stage),
                f"{oracle_dir}/test_exploit.py",
                timeout,
                requirements=list(self.requirements),
                image=self.image,
                canary_path=str(canary),
                canary_mount=_CANARY_MOUNT,
                events_path=str(Path(tmp) / "events.jsonl"),
                env={ENV_CANARY_TOKEN: token, ENV_ALLOWED_DIR: f"{_SCRATCH}/allowed"},
                manifest=manifest,
            )
            if result["outcome"] == "env_failure":
                raise OSError(f"sandbox could not run the exploit: {result['stderr']}")
            return _judge(
                _outcome(result),
                _events(result["oracle_events"]),
                Path(_WORKSPACE),
                Path(container_test),
                set(entry_points),
                forged_events=result.get("oracle_forged_events", 0),
                forged_reason=result.get("oracle_forged_reason", ""),
                app_tree=AppTree(str(_WORKSPACE), stage, manifest),
                app_tree_changes=result.get("app_tree_changes", []),
                allowed_dir=f"{_SCRATCH}/allowed",
            )


def _outcome(result: dict[str, Any]) -> TestOutcome:
    """Pytest's exit status, as the host oracle reads it: only exit code 1 is a test failure."""
    if result["outcome"] == "timeout":
        return "timeout"
    return {0: "passed", 1: "failed"}.get(result["exit_code"], "error")


def _events(raw: list[Any]) -> list[OracleEvent]:
    """Events come out of the container as untrusted JSON; malformed ones are dropped."""
    events = []
    for item in raw:
        try:
            events.append(OracleEvent.model_validate(item))
        except ValidationError:
            continue
    return events
