"""
Hardened sandbox runner.

Provides `run(clone_path, test_path, timeout, requirements=None, image=None)` which executes pytest inside an
ephemeral Docker container with strict isolation:
 - unprivileged user
 - all capabilities dropped
 - no network during test run
 - read-only root filesystem except a writable copy of the clone mounted at /workspace
 - CPU / memory / pids limits
 - prebuilt pinned image (see image.py); deps are installed at build time, never at run time
 - container removed afterwards

Returns:
    dict: {
        "outcome": "passed" | "failed" | "timeout" | "env_failure",
        "exit_code": int | None,
        "stdout": str,
        "stderr": str,
        "oracle_events": list,
        "oracle_forged_events": int
    }

Oracle events are signed by the plugin with a key generated here per run and written to the
container's stdin (``docker run -i``), never to its environment, command line or a mount.
Only lines that verify are returned in ``oracle_events`` (as their event bodies); the rest
are dropped and counted in ``oracle_forged_events`` (finding A-1, docs/oracle-a1.md).

This module shells out to the `docker` CLI. It does not mount the docker socket
or any host directory other than a temporary copy of `clone_path`.
"""
from __future__ import annotations

import secrets
import shutil
import subprocess
import tempfile
import uuid
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Dict, Any, Mapping

from .image import build_image
from exhibit_a.oracle.plugin import KEY_BYTES, key_message, verify_lines

PYTEST_VERSION = "pytest==7.3.2"

# The oracle plugin is mounted read-only as a single module; only the events file is writable.
_PLUGIN_SOURCE = Path(__file__).resolve().parent.parent / "oracle" / "plugin.py"
_PLUGIN_MODULE = "exhibit_a_oracle_plugin"
_PLUGIN_DIR = "/opt/exhibit_a_plugin"
_CANARY_MOUNT = "/oracle/canary"
_EVENTS_MOUNT = "/oracle/events.jsonl"
_ENV_PREFIX = "EXHIBIT_A_"


def _read_events(path: str, key: bytes) -> tuple[list, int]:
    """Bodies of the signed lines that verify under ``key``, and how many lines were dropped.

    The file is writable from inside the container, so every line is untrusted: malformed,
    unsigned, badly signed and replayed (seq not increasing) lines are all dropped.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return [], 0
    bodies, rejected = verify_lines(lines, key)
    return bodies, len(rejected)


def _check_docker_available() -> bool:
    from shutil import which

    docker = which("docker")
    if not docker:
        return False
    try:
        # quick sanity check
        subprocess.run(["docker", "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def run(
    clone_path: str,
    test_path: str,
    timeout: float,
    requirements: list[str] | None = None,
    image: str | None = None,
    canary_path: str | None = None,
    events_path: str | None = None,
    env: Mapping[str, str] | None = None,
    canary_mount: str = _CANARY_MOUNT,
) -> Dict[str, Any]:
    """
    Execute pytest inside an ephemeral, hardened docker container.

    Args:
        clone_path: path to a local clone directory (will be copied).
        test_path: path to the test file to execute (absolute or relative to clone_path).
        timeout: wall-time limit in seconds for the test run.
        requirements: extra pip requirements baked into the prebuilt image (pytest is always included).
        image: tag of an already built image; when given, `requirements` is ignored.
        canary_path: optional host file exposed read-only inside the container as the canary.
        events_path: optional host file that receives the oracle events written in the container; setting
            it (or `canary_path`) loads the oracle plugin. It is the only extra writable mount.
        env: extra `EXHIBIT_A_*` variables passed to the container; the canary/events paths are set by run().
        canary_mount: where the canary appears inside the container, as a real read-only file so code that
            canonicalises paths sees the file itself. Besides the default it must have the shape
            /tmp/<work>/<dir>/<file>; <work> then gets its own small writable tmpfs, so tests can lay out
            directories around the canary.

    Returns:
        dict with outcome, exit_code, stdout, stderr, oracle_events.
    """
    if not _check_docker_available():
        return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": "docker not available", "oracle_events": [], "oracle_forged_events": 0}

    # Create a temporary copy of the clone. Place it under a directory inside the
    # user's HOME so Colima (which shares $HOME) can bind-mount it reliably.
    home_cache_root = os.path.join(Path.home(), ".cache", "exhibit-a", "sandbox")
    os.makedirs(home_cache_root, exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix="exhibit_a_sandbox_", dir=home_cache_root)
    try:
        # copy the repo into tmpdir/workspace
        workspace = os.path.join(tmpdir, "workspace")
        shutil.copytree(clone_path, workspace, dirs_exist_ok=True)

        # compute test path relative to workspace
        if os.path.isabs(test_path):
            rel_test = os.path.relpath(test_path, clone_path)
        else:
            rel_test = test_path

        run_name = f"exhibit_a_run_{uuid.uuid4().hex[:8]}"

        extra_env = dict(env or {})
        bad = [k for k in extra_env if not k.startswith(_ENV_PREFIX)]
        if bad:
            return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": f"env keys must start with {_ENV_PREFIX}: {bad}", "oracle_events": [], "oracle_forged_events": 0}

        mount = PurePosixPath(canary_mount)
        canary_work = mount.parent.parent
        custom_mount = mount != PurePosixPath(_CANARY_MOUNT)
        if custom_mount and (
            ".." in mount.parts
            or "." in canary_mount.split("/")
            or not canary_work.is_relative_to("/tmp")
            or canary_work == PurePosixPath("/tmp")
        ):
            return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": f"invalid canary_mount: {canary_mount!r}", "oracle_events": [], "oracle_forged_events": 0}

        observe = canary_path is not None or events_path is not None
        oracle_key = secrets.token_bytes(KEY_BYTES)
        events_file = os.path.join(tmpdir, "events.jsonl")
        extra_args: list[str] = []
        plugin_flag = ""
        if observe:
            # Private copies under tmpdir keep every mount bind-able and the host originals untouched.
            Path(events_file).write_text("")
            plugin_copy = os.path.join(tmpdir, f"{_PLUGIN_MODULE}.py")
            shutil.copyfile(_PLUGIN_SOURCE, plugin_copy)
            extra_args += ["-v", f"{plugin_copy}:{_PLUGIN_DIR}/{_PLUGIN_MODULE}.py:ro"]
            # Still a known path inside the container (a bind mount cannot be hidden from the
            # test); the plugin signs every line, and unverified lines are dropped in collect().
            extra_args += ["-v", f"{events_file}:{_EVENTS_MOUNT}:rw"]
            extra_args += ["-e", f"PYTHONPATH={_PLUGIN_DIR}", "-e", f"EXHIBIT_A_EVENTS={_EVENTS_MOUNT}"]
            if canary_path is not None:
                canary_copy = os.path.join(tmpdir, "canary")
                shutil.copyfile(canary_path, canary_copy)
                if custom_mount:
                    # Stays writable: the exploit's conftest fills the allowed directory here, and an
                    # app's static files live in the writable /workspace. A test can therefore plant
                    # symlinks next to them; the oracle plugin flags reads through links created
                    # during the run (via_symlink) instead of relying on a read-only mount.
                    extra_args += ["--tmpfs", f"{canary_work}:rw,size=16m,mode=1777"]
                extra_args += ["-v", f"{canary_copy}:{mount}:ro", "-e", f"EXHIBIT_A_CANARY={mount}"]
            plugin_flag = f"-p {_PLUGIN_MODULE} "
        for env_name, value in extra_env.items():
            if env_name in ("EXHIBIT_A_EVENTS", "EXHIBIT_A_CANARY") and observe:
                continue
            extra_args += ["-e", f"{env_name}={value}"]

        def collect() -> dict:
            if not observe:
                return {"oracle_events": [], "oracle_forged_events": 0}
            events, forged = _read_events(events_file, oracle_key)
            if events_path is not None:
                try:
                    shutil.copyfile(events_file, events_path)
                except OSError:
                    pass
            return {"oracle_events": events, "oracle_forged_events": forged}

        # 1) Resolve the prebuilt image (built once with network, reused across runs).
        if image is None:
            try:
                image = build_image([PYTEST_VERSION, *(requirements or [])])
            except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as e:
                return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": f"failed to prepare sandbox image: {e}", "oracle_events": [], "oracle_forged_events": 0}

        # 2) Run the image with strict isolation and no network.
        cmd = [
            "docker",
            "run",
            "-i",  # stdin carries the oracle key to the plugin, and nothing else
            "--name",
            run_name,
            "--rm",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=64m,mode=1777",
            "--network",
            "none",
            "-e",
            "HOME=/tmp",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "512m",
            "--cpus",
            "0.5",
            "-v",
            f"{workspace}:/workspace:rw",
            *extra_args,
            "--workdir",
            "/workspace",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            image,
            "bash",
            "-lc",
            f"pytest -q -p no:cacheprovider {plugin_flag}/workspace/{rel_test}",
        ]

        try:
            proc = subprocess.run(
                cmd,
                input=key_message(oracle_key) if observe else b"",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
            stdout = proc.stdout.decode(errors="replace")
            stderr = proc.stderr.decode(errors="replace")
            exit_code = proc.returncode
            outcome = "passed" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired as e:
            # ensure container is removed
            subprocess.run(["docker", "rm", "-f", run_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {"outcome": "timeout", "exit_code": None, "stdout": e.stdout.decode() if e.stdout else "", "stderr": e.stderr.decode() if e.stderr else "", **collect()}
        except OSError as e:
            return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": str(e), "oracle_events": [], "oracle_forged_events": 0}

        return {"outcome": outcome, "exit_code": exit_code, "stdout": stdout, "stderr": stderr, **collect()}
    finally:
        # best-effort cleanup of the temp dir
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

