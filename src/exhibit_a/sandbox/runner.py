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
    plus, for effect="canary_write" only: "canary_written": bool and "outside_listing": list
    (what the run left in the writable outside/ tmpfs; see docs/sandbox-write-effect.md).

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

import json
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


# Write effect: the scratch directory is a tmpfs, so what the run left in it is read back by a
# short script that runs inside the container after pytest and writes a JSON result file.
_OUTSIDE_MOUNT = "/oracle/outside.json"
_MAX_OUTSIDE_BYTES = 1 << 20
_MAX_OUTSIDE_ENTRIES = 200
_OUTSIDE_DUMP = r'''
import json, os, stat, sys
work, canary, out = sys.argv[1:4]
token = os.environ.get("EXHIBIT_A_CANARY_TOKEN", "")
outside = os.path.dirname(canary)
listing = []
for here, dirs, files in os.walk(outside):
    for name in sorted(dirs + files):
        path = os.path.join(here, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        kind = ("link" if stat.S_ISLNK(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode)
                else "file" if stat.S_ISREG(st.st_mode) else "other")
        listing.append({"path": os.path.relpath(path, work), "kind": kind, "size": st.st_size})
written = False
try:
    if stat.S_ISREG(os.lstat(canary).st_mode):
        with open(canary, "rb") as fh:
            written = bool(token) and token.encode() in fh.read(1 << 20)
except OSError:
    pass
with open(out, "w") as fh:
    json.dump({"canary_written": written, "listing": listing[:200]}, fh)
'''


def _read_outside(path: str) -> tuple[bool, list[dict]]:
    """``(canary_written, listing)`` from the in-container dump; anything odd is "not written".

    The file is writable from inside the container, so it is untrusted: size-capped, strictly
    typed, and only a literal ``true`` counts. A missing or empty file (the dump never ran, as
    after a timeout) means the write was not confirmed.
    """
    try:
        if os.lstat(path).st_size > _MAX_OUTSIDE_BYTES:
            return False, []
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return False, []
    if not isinstance(data, dict):
        return False, []
    listing = [
        {"path": str(e["path"])[:300], "kind": str(e["kind"])[:10], "size": e["size"]}
        for e in data.get("listing", [])[:_MAX_OUTSIDE_ENTRIES]
        if isinstance(e, dict) and isinstance(e.get("path"), str) and isinstance(e.get("kind"), str)
        and isinstance(e.get("size"), int) and not isinstance(e.get("size"), bool)
    ] if isinstance(data.get("listing"), list) else []
    return data.get("canary_written") is True, listing


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
        if effect == "canary_write":
            if canary_path is not None:
                return _env_failure("a write effect mounts no canary file: canary_path must be None")
            if not custom_mount:
                return _env_failure("a write effect needs a canary_mount of the shape /tmp/<work>/<dir>/<file>")
        observe = canary_path is not None or events_path is not None or effect == "canary_write"
        oracle_key = secrets.token_bytes(KEY_BYTES)
        events_file = os.path.join(tmpdir, "events.jsonl")
        outside_file = os.path.join(tmpdir, "outside.json")
        extra_args: list[str] = []
        plugin_args: list[str] = []
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
                # Write effect: NO canary file is mounted. The scratch directory is a small
                # tmpfs (size-capped, gone with the container), so the app can create
                # <canary_work>/outside/canary.txt and nothing on the host is writable. What the
                # run left there comes back through a result file written by the dump below.
                extra_args += ["--tmpfs", f"{canary_work}:rw,size=16m,mode=1777",
                               "-e", f"EXHIBIT_A_CANARY={mount}"]
                Path(outside_file).write_text("")
                extra_args += ["-v", f"{outside_file}:{_OUTSIDE_MOUNT}:rw"]
            plugin_args = ["-p", _PLUGIN_MODULE]
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
            if effect == "canary_write":
                written, listing = _read_outside(outside_file)
                payload["canary_written"] = written
                payload["outside_listing"] = listing
            return payload

        # 1) Resolve the prebuilt image (built once with network, reused across runs).
        if image is None:
            try:
                image = build_image([PYTEST_VERSION, *(requirements or [])])
            except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as e:
                return _env_failure(f"failed to prepare sandbox image: {e}")

        # 2) Run the image with strict isolation and no network.
        pytest_args = ["-q", "-p", "no:cacheprovider", *plugin_args, f"/workspace/{rel_test}"]
        if effect == "canary_write":
            # pytest's own exit status is kept; the dump runs after it, in isolated mode. Every
            # value reaches the shell as a positional parameter, never spliced into its text.
            pytest_argv = [
                "bash", "-c",
                'pytest "${@:4}"; rc=$?; python -I -S -c "$1" "$2" "$3" ' + _OUTSIDE_MOUNT + '; exit $rc',
                "exhibit-a", _OUTSIDE_DUMP, str(canary_work), str(mount), *pytest_args,
            ]
        else:
            pytest_argv = ["pytest", *pytest_args]
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
            "--memory-swap",
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
            *pytest_argv,
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
