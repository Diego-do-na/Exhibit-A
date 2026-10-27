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
        "oracle_events": list
    }

This module shells out to the `docker` CLI. It does not mount the docker socket
or any host directory other than a temporary copy of `clone_path`.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import uuid
import os
import sys
from pathlib import Path
from typing import Dict, Any

from .image import build_image

PYTEST_VERSION = "pytest==7.3.2"


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
) -> Dict[str, Any]:
    """
    Execute pytest inside an ephemeral, hardened docker container.

    Args:
        clone_path: path to a local clone directory (will be copied).
        test_path: path to the test file to execute (absolute or relative to clone_path).
        timeout: wall-time limit in seconds for the test run.
        requirements: extra pip requirements baked into the prebuilt image (pytest is always included).
        image: tag of an already built image; when given, `requirements` is ignored.

    Returns:
        dict with outcome, exit_code, stdout, stderr, oracle_events.
    """
    if not _check_docker_available():
        return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": "docker not available", "oracle_events": []}

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

        # 1) Resolve the prebuilt image (built once with network, reused across runs).
        if image is None:
            try:
                image = build_image([PYTEST_VERSION, *(requirements or [])])
            except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as e:
                return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": f"failed to prepare sandbox image: {e}", "oracle_events": []}

        # 2) Run the image with strict isolation and no network.
        cmd = [
            "docker",
            "run",
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
            "--workdir",
            "/workspace",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            image,
            "bash",
            "-lc",
            f"pytest -q -p no:cacheprovider /workspace/{rel_test}",
        ]

        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            stdout = proc.stdout.decode(errors="replace")
            stderr = proc.stderr.decode(errors="replace")
            exit_code = proc.returncode
            outcome = "passed" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired as e:
            # ensure container is removed
            subprocess.run(["docker", "rm", "-f", run_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {"outcome": "timeout", "exit_code": None, "stdout": e.stdout.decode() if e.stdout else "", "stderr": e.stderr.decode() if e.stderr else "", "oracle_events": []}
        except OSError as e:
            return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": str(e), "oracle_events": []}

        return {"outcome": outcome, "exit_code": exit_code, "stdout": stdout, "stderr": stderr, "oracle_events": []}
    finally:
        # best-effort cleanup of the temp dir
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

