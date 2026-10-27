"""How the loop executes tests: the ``TestRunner`` seam and its sandbox-backed default.

The loop needs two kinds of execution:

* ``run_baseline`` runs the project's own tests and returns the sandbox result dict
  (``outcome``, ``exit_code``, ``stdout``, ``stderr``, ``oracle_events``);
* ``run_exploit`` runs an exploit test with the oracle and returns its ``Judgement``.

``SandboxRunner`` runs the baseline inside the isolated, resource-limited Docker sandbox,
on an image that has the case's requirements baked in. Its exploit step still delegates to
``run_oracle``, which runs as a host child process until the oracle moves into the sandbox.
Unit tests inject a fake runner so they need no Docker.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from exhibit_a.oracle import Judgement, run_oracle


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
    """Baseline in the Docker sandbox with the case's requirements; exploit via the oracle.

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
        return run_oracle(app_root, test_path, entry_points, timeout=timeout)
