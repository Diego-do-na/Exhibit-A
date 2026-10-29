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
        "oracle_forged_events": int,
        "oracle_forged_reason": str,
        "app_tree_changes": list
    }

Oracle events are signed by the plugin with a key generated here per run and written to the
container's stdin (``docker run -i``), never to its environment, command line or a mount.
Only lines that verify are returned in ``oracle_events`` (as their event bodies); the rest
are dropped and counted in ``oracle_forged_events`` (finding A-1, docs/oracle-a1.md).

When the oracle is loaded, the workspace copy is hashed before the container starts and that
manifest follows the key on stdin, so the plugin can admit only staged application code. The
test's own directory is left out (``staging_exclude``). After the container exits the copy is
hashed again; ``app_tree_changes`` lists every added, removed or modified entry, and any entry
rules out a proof (docs/oracle-provenance.md).

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
from exhibit_a.oracle.oracle import _MAX_CANARY_READ
from exhibit_a.oracle.provenance import ManifestError, app_manifest, staging_exclude, tree_changes

PYTEST_VERSION = "pytest==7.3.2"

# The oracle plugin is mounted read-only as a single module; only the events file is writable.
_PLUGIN_SOURCE = Path(__file__).resolve().parent.parent / "oracle" / "plugin.py"
_PLUGIN_MODULE = "exhibit_a_oracle_plugin"
_PLUGIN_DIR = "/opt/exhibit_a_plugin"
_CANARY_MOUNT = "/oracle/canary"
_EVENTS_MOUNT = "/oracle/events.jsonl"
_ENV_PREFIX = "EXHIBIT_A_"
_WORKSPACE = "/workspace"


def _env_failure(stderr: str) -> Dict[str, Any]:
    return {
        "outcome": "env_failure", "exit_code": None, "stdout": "", "stderr": stderr,
        "oracle_events": [], "oracle_forged_events": 0, "oracle_forged_reason": "", "app_tree_changes": [],
    }


def _read_events(path: str, key: bytes) -> tuple[list, int, str]:
    """Bodies of the signed lines that verify under ``key``, the dropped count and the first reason.

    The file is writable from inside the container, so every line is untrusted: malformed,
    unsigned, badly signed and replayed (seq not increasing) lines are all dropped.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return [], 0, ""
    bodies, rejected = verify_lines(lines, key)
    return bodies, len(rejected), (rejected[0] if rejected else "")


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
    manifest: Mapping[str, str] | None = None,
    effect: str = "canary_read",
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
        manifest: the caller's manifest of the staged app (provenance.app_manifest of `clone_path` with
            `staging_exclude(test_path)`). The workspace copy must hash to it, or the run is an env_failure.
            Without it the copy's own manifest is used. Only used when the oracle is loaded.

    Returns:
        dict with outcome, exit_code, stdout, stderr, oracle_events, oracle_forged_events,
        oracle_forged_reason and app_tree_changes.
    """
    if not _check_docker_available():
        return _env_failure("docker not available")

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
            return _env_failure(f"env keys must start with {_ENV_PREFIX}: {bad}")

        mount = PurePosixPath(canary_mount)
        canary_work = mount.parent.parent
        custom_mount = mount != PurePosixPath(_CANARY_MOUNT)
        if custom_mount and (
            ".." in mount.parts
            or "." in canary_mount.split("/")
            or not canary_work.is_relative_to("/tmp")
            or canary_work == PurePosixPath("/tmp")
        ):
            return _env_failure(f"invalid canary_mount: {canary_mount!r}")

        if effect not in ("canary_read", "canary_write"):
            return _env_failure(f"unknown oracle effect: {effect}")
        observe = canary_path is not None or events_path is not None or effect == "canary_write"
        oracle_key = secrets.token_bytes(KEY_BYTES)
        events_file = os.path.join(tmpdir, "events.jsonl")
        extra_args: list[str] = []
        plugin_flag = ""
        exclude = staging_exclude(PurePosixPath(rel_test).as_posix())
        staged: dict[str, str] = {}
        if observe:
            # Hashed before any test code runs; the plugin gets it on stdin with the key.
            try:
                staged = app_manifest(workspace, exclude)
            except ManifestError as e:
                return _env_failure(f"cannot hash the staged app: {e}")
            if manifest is not None and dict(manifest) != staged:
                return _env_failure("the staged workspace does not match the caller's manifest")
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
            elif effect == "canary_write":
                # For a write-effect run we provide an empty host-side directory mounted
                # at the sandbox's scratch root (canary_work). The test may create the
                # canary path under it; after the container exits we inspect that host
                # mount to decide whether the run left a file with the token.
                host_canary_root = os.path.join(tmpdir, "canary_root")
                os.makedirs(host_canary_root, exist_ok=True)
                extra_args += ["-v", f"{host_canary_root}:{canary_work}:rw", "-e", f"EXHIBIT_A_CANARY={mount}"]
            plugin_flag = f"-p {_PLUGIN_MODULE} "
        for env_name, value in extra_env.items():
            if env_name in ("EXHIBIT_A_EVENTS", "EXHIBIT_A_CANARY") and observe:
                continue
            extra_args += ["-e", f"{env_name}={value}"]

        def collect() -> dict:
            if not observe:
                return {"oracle_events": [], "oracle_forged_events": 0, "oracle_forged_reason": "", "app_tree_changes": []}
            events, forged, forged_reason = _read_events(events_file, oracle_key)
            if events_path is not None:
                try:
                    shutil.copyfile(events_file, events_path)
                except OSError:
                    pass
            payload = {
                "oracle_events": events,
                "oracle_forged_events": forged,
                "oracle_forged_reason": forged_reason,
                "app_tree_changes": tree_changes(workspace, staged, exclude),
            }
            # For write-effect runs inspect the host-side mount we bound to the
            # sandbox scratch root to see whether a canary file holding the token
            # was left there. The caller provides the token via EXHIBIT_A_CANARY_TOKEN
            # in `env`.
            if effect == "canary_write":
                token = extra_env.get("EXHIBIT_A_CANARY_TOKEN")
                try:
                    rel = PurePosixPath(canary_mount).relative_to(PurePosixPath(canary_work))
                except Exception:
                    rel = PurePosixPath("outside/canary.txt")
                host_canary_root = os.path.join(tmpdir, "canary_root")
                host_canary_path = os.path.join(host_canary_root, *rel.parts)
                canary_written = False
                if token is not None:
                    try:
                        with open(host_canary_path, "rb") as fh:
                            content = fh.read(_MAX_CANARY_READ)
                        canary_written = token.encode("utf-8") in content
                    except Exception:
                        canary_written = False
                payload["canary_written"] = canary_written
                # also expose the post-run listing for debugging / external checks
                try:
                    listing = []
                    for root, dirs, files in os.walk(host_canary_root):
                        for f in files:
                            listing.append(os.path.relpath(os.path.join(root, f), host_canary_root))
                    payload["outside_listing"] = listing
                except Exception:
                    payload["outside_listing"] = []
            return payload

        # 1) Resolve the prebuilt image (built once with network, reused across runs).
        if image is None:
            try:
                image = build_image([PYTEST_VERSION, *(requirements or [])])
            except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as e:
                return _env_failure(f"failed to prepare sandbox image: {e}")

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
            f"{workspace}:{_WORKSPACE}:rw",
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
                input=key_message(oracle_key, app_root=_WORKSPACE, manifest=staged) if observe else b"",
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
            return _env_failure(str(e))

        return {"outcome": outcome, "exit_code": exit_code, "stdout": stdout, "stderr": stderr, **collect()}
    finally:
        # best-effort cleanup of the temp dir
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass
