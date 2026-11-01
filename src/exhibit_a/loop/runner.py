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

The exploit path applies the same oracle defences as the host path (docs/oracle/oracle-a1.md,
docs/oracle/oracle-provenance.md): the static tripwire runs before staging (a hit is an ``error``
judgement, i.e. ``invalid_test``); the staged app is hashed and the manifest goes to the
plugin with the key; forged event lines and any change to the app tree reach the judgement
(``forged_events``, ``app_tree_changes``), and frames count as application code only if the
plugin admitted them and they match the staged copy kept on the host.
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, runtime_checkable

from pydantic import ValidationError

from exhibit_a.oracle import Judgement, OracleEvent, run_oracle
from exhibit_a.oracle.guard import channel_problem, connect_problem, dos_problem, exec_problem, sql_problem
from exhibit_a.oracle.oracle import (
    ENV_ALLOWED_DIR,
    ENV_CANARY_TOKEN,
    ENV_CONNECT_URL,
    EXEC_CANARY_NAME,
    EXEC_MARKER_NAME,
    REASON_CHANNEL_TRIPWIRE,
    TestOutcome,
    _judge,
    canary_connect_url,
    exec_canary_script,
    pick_connect_port,
    sql_db_problem,
)
from exhibit_a.oracle.plugin import ENV_DOS
from exhibit_a.oracle.provenance import AppTree, ManifestError, app_manifest

# Where the sandbox mounts the clone; frames recorded inside the container use these paths.
_WORKSPACE = PurePosixPath("/workspace")
_SCRATCH = "/tmp/exhibit_a_oracle"

# The canary is a real file (not a symlink), so apps that canonicalise paths resolve to it.
_CANARY_MOUNT = f"{_SCRATCH}/outside/canary.txt"
_EXEC_CANARY_MOUNT = f"{_SCRATCH}/outside/{EXEC_CANARY_NAME}"
_EXEC_MARKER = f"{_SCRATCH}/outside/{EXEC_MARKER_NAME}"

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
        effect: str = "canary_read",
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
    # canary_sql only: the application's SQLite database, as a path relative to the app tree
    # (case.json run.sql_db). The container sees a copy of it with the canary table added.
    sql_db: str | None = None

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
        effect: str = "canary_read",
    ) -> Judgement:
        """Run the exploit in the sandbox and judge it; raises ``OSError`` if it could not run."""
        from exhibit_a.sandbox import run

        problem = channel_problem(Path(test_path))
        if problem is None and effect == "canary_exec":
            problem = exec_problem(Path(test_path))
        if problem is None and effect == "canary_sql":
            problem = sql_problem(Path(test_path))
        if problem is None and effect == "canary_connect":
            problem = connect_problem(Path(test_path))
        if problem is None and effect == "canary_dos":
            problem = dos_problem(Path(test_path))
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
            # For a read effect the canary must exist before the run; for a write
            # effect it must be absent so the app creates it during the run.
            if effect == "canary_read":
                canary.write_text(token + "\n", encoding="utf-8")
            elif effect == "canary_exec":
                canary.write_text(exec_canary_script(_EXEC_MARKER, token), encoding="utf-8")
            if effect == "canary_sql":
                # The database must be where the case says; the sandbox seeds a copy of it.
                problem = sql_db_problem(stage, self.sql_db)
                if problem is not None:
                    raise OSError(f"sandbox could not run the exploit: {problem}")
            canary_url = None
            if effect == "canary_connect":
                # The listener runs inside the container on loopback; the test learns only
                # its URL and must make the application request it.
                canary_url = canary_connect_url(pick_connect_port(), secrets.token_hex(16))
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
                canary_path=str(canary) if effect in ("canary_read", "canary_exec") else None,
                canary_mount=_EXEC_CANARY_MOUNT if effect == "canary_exec" else _CANARY_MOUNT,
                events_path=str(Path(tmp) / "events.jsonl"),
                env={
                    ENV_CANARY_TOKEN: token,
                    ENV_ALLOWED_DIR: f"{_SCRATCH}/allowed",
                    **({ENV_CONNECT_URL: canary_url} if canary_url is not None else {}),
                    **({ENV_DOS: "1"} if effect == "canary_dos" else {}),
                },
                manifest=manifest,
                effect=effect,
                sql_db=self.sql_db if effect == "canary_sql" else None,
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
                effect=effect,
                # Read: nothing to check after the run. Write: the sandbox's post-run dump of the
                # outside/ tmpfs must confirm a regular file with the token; absent means False.
                canary_written=bool(result.get("canary_written", False)) if effect == "canary_write" else None,
                # Exec: the host's own read of the marker; a missing answer stays unverified.
                canary_ran=result.get("canary_ran") is True if effect == "canary_exec" else None,
                # Connect: the URL handed out and what the in-container listener recorded
                # (untrusted: the judge needs signed plugin events for the same request).
                canary_url=canary_url if effect == "canary_connect" else None,
                connect_log=list(result.get("connect_log", [])) if effect == "canary_connect" else None,
            )


@dataclass(frozen=True)
class HostRunner:
    """Test-only host runner for unit tests and research tooling.

    Runs the baseline via host ``pytest`` in a scrubbed child process and the exploit via
    ``run_oracle`` on the host. Untrusted test code must never execute on the host in
    normal operation, so ``allow_host_execution=True`` is required as an explicit switch
    that the CLI never sets.
    """

    allow_host_execution: bool = False
    requirements: Sequence[str] = ()
    sql_db: str | None = None

    def __post_init__(self) -> None:
        if not self.allow_host_execution:
            raise PermissionError(
                "HostRunner executes untrusted test code on the host and requires "
                "allow_host_execution=True (test-only switch; never set by the CLI)"
            )

    def run_baseline(self, clone_path: str, test_path: str, timeout: float) -> dict[str, Any]:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(clone_path),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_path]
        try:
            proc = subprocess.run(cmd, cwd=clone_path, env=env, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {
                "outcome": "timeout",
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "oracle_events": [],
            }
        return {
            "outcome": "passed" if proc.returncode == 0 else "failed",
            "exit_code": proc.returncode,
            "stdout": proc.stdout.decode(errors="replace"),
            "stderr": proc.stderr.decode(errors="replace"),
            "oracle_events": [],
        }

    def run_exploit(
        self,
        app_root: Path,
        test_path: Path,
        entry_points: Collection[str],
        *,
        timeout: float,
        effect: str = "canary_read",
    ) -> Judgement:
        return run_oracle(
            app_root,
            test_path,
            entry_points,
            timeout=timeout,
            effect=effect,
            sql_db=self.sql_db,
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
