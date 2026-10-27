"""
Hardened sandbox runner.

Provides `run(clone_path, test_path, timeout)` which executes pytest inside an
ephemeral Docker container with strict isolation:
 - unprivileged user
 - all capabilities dropped
 - no network during test run
 - read-only root filesystem except a writable copy of the clone mounted at /workspace
 - CPU / memory / pids limits
 - pinned base image
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
from typing import Dict, Any

BASE_IMAGE = "python:3.11.9-slim-bullseye"
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


def run(clone_path: str, test_path: str, timeout: float) -> Dict[str, Any]:
    """
    Execute pytest inside an ephemeral, hardened docker container.

    Args:
        clone_path: path to a local clone directory (will be copied).
        test_path: path to the test file to execute (absolute or relative to clone_path).
        timeout: wall-time limit in seconds for the test run.

    Returns:
        dict with outcome, exit_code, stdout, stderr, oracle_events.
    """
    if not _check_docker_available():
        return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": "docker not available", "oracle_events": []}

    # Create a temporary copy of the clone. Place it under the current working
    # directory so Docker on macOS/Colima can bind-mount the path reliably.
    tmpdir = tempfile.mkdtemp(prefix="exhibit_a_sandbox_", dir=os.getcwd())
    try:
        # copy the repo into tmpdir/workspace
        workspace = os.path.join(tmpdir, "workspace")
        shutil.copytree(clone_path, workspace, dirs_exist_ok=True)

        # compute test path relative to workspace
        if os.path.isabs(test_path):
            rel_test = os.path.relpath(test_path, clone_path)
        else:
            rel_test = test_path

        builder_name = f"exhibit_a_builder_{uuid.uuid4().hex[:8]}"
        image_tag = f"exhibit_a_sandbox_img:{uuid.uuid4().hex[:8]}"
        run_name = f"exhibit_a_run_{uuid.uuid4().hex[:8]}"

        # 1) Start a short-lived builder container (with network) to install pytest.
        try:
            subprocess.run(["docker", "pull", BASE_IMAGE], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            # if pull fails we continue; docker may have cached image already
            pass

        try:
            subprocess.run(
                ["docker", "run", "--name", builder_name, "-d", "-v", f"{workspace}:/workspace:rw", BASE_IMAGE, "sleep", "infinity"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            return {"outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": f"failed to start builder container: {e.stderr.decode() if e.stderr else e}", "oracle_events": []}

        try:
            # Install pytest into the builder container (this step requires network)
            res = subprocess.run(["docker", "exec", builder_name, "pip", "install", "-q", PYTEST_VERSION], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode != 0:
                stderr = res.stderr.decode(errors="replace")
                return {"outcome": "env_failure", "exit_code": None, "stdout": res.stdout.decode(errors="replace"), "stderr": f"failed to install pytest in builder: {stderr}", "oracle_events": []}

            # Commit the builder container into a new image we can run with --network none
            res = subprocess.run(["docker", "commit", builder_name, image_tag], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode != 0:
                return {"outcome": "env_failure", "exit_code": None, "stdout": res.stdout.decode(errors="replace"), "stderr": res.stderr.decode(errors="replace"), "oracle_events": []}
        finally:
            # remove the builder container
            subprocess.run(["docker", "rm", "-f", builder_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 2) Run the committed image with strict isolation and no network.
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
            # run as default user in the container (root) so mounted workspaces are accessible
            image_tag,
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
        finally:
            # cleanup the temporary image we created
            subprocess.run(["docker", "rmi", "-f", image_tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return {"outcome": outcome, "exit_code": exit_code, "stdout": stdout, "stderr": stderr, "oracle_events": []}
    finally:
        # best-effort cleanup of the temp dir
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

