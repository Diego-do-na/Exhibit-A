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
    (what the run left in the writable outside/ tmpfs; see docs/reference/sandbox-write-effect.md),
    and for effect="canary_exec" only: "canary_ran": bool (the host's own check of the marker the
    canary executable left; see docs/reference/sandbox.md). For effect="canary_sql" the canary table is
    added to a copy of the application's database by a first, equally isolated container, and the copy
    is mounted read-only over the declared path in the test's container (docs/reference/sandbox.md).

Oracle events are signed by the plugin with a key generated here per run and written to the
container's stdin (``docker run -i``), never to its environment, command line or a mount.
Only lines that verify are returned in ``oracle_events`` (as their event bodies); the rest
are dropped and counted in ``oracle_forged_events`` (finding A-1, docs/oracle/oracle-a1.md).

When the oracle is loaded, the workspace copy is hashed before the container starts and that
manifest follows the key on stdin, so the plugin can admit only staged application code. The
test's own directory is left out (``staging_exclude``). After the container exits the copy is
hashed again; ``app_tree_changes`` lists every added, removed or modified entry, and any entry
rules out a proof (docs/oracle/oracle-provenance.md).

This module shells out to the `docker` CLI. It does not mount the docker socket
or any host directory other than a temporary copy of `clone_path`.
"""
from __future__ import annotations

import json
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import uuid
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Dict, Any, Mapping

from .image import build_image
from exhibit_a.oracle.oracle import SQL_CANARY_COLUMN, SQL_CANARY_TABLE, marker_holds_token, sql_db_problem
from exhibit_a.oracle.plugin import ENV_MARKER, ENV_SQL, KEY_BYTES, key_message, verify_lines
from exhibit_a.oracle.provenance import ManifestError, app_manifest, staging_exclude, tree_changes

PYTEST_VERSION = "pytest==7.3.2"
SECCOMP_PROFILE = Path(__file__).resolve().parent / "seccomp.json"
RUNTIME_ENV = "EXHIBIT_A_DOCKER_RUNTIME"
NON_ROOT_FALLBACK_UID = 65534
NON_ROOT_FALLBACK_GID = 65534
MEMORY_LIMIT = "512m"
MEMORY_LIMIT_BYTES = 512 * 1024 * 1024
PIDS_LIMIT = 64
CPUS_LIMIT = "0.5"
TMPFS_SPEC = "/tmp:rw,size=64m,mode=1777"
_RUNTIME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Complete audit list of every container mount the sandbox runner ever declares.
# Every bind-mount host source lives inside the per-run temporary directory under
# ~/.cache/exhibit-a/sandbox/exhibit_a_sandbox_<id>/ and is deleted after the run.
DECLARED_MOUNTS: tuple[dict[str, str], ...] = (
    {
        "target": "/workspace",
        "mode": "rw",
        "kind": "bind",
        "scope": "all",
        "source": "<tmpdir>/workspace (staged copy of clone_path)",
    },
    {
        "target": "/tmp",
        "mode": "rw,size=64m,mode=1777",
        "kind": "tmpfs",
        "scope": "all",
        "source": "tmpfs (in-memory, 64 MiB cap)",
    },
    {
        "target": "/opt/exhibit_a_plugin/exhibit_a_oracle_plugin.py",
        "mode": "ro",
        "kind": "bind",
        "scope": "oracle",
        "source": "<tmpdir>/exhibit_a_oracle_plugin.py (per-run copy of plugin.py)",
    },
    {
        "target": "/oracle/events.jsonl",
        "mode": "rw",
        "kind": "bind",
        "scope": "oracle",
        "source": "<tmpdir>/events.jsonl (HMAC-signed event sink)",
    },
    {
        "target": "/oracle/canary (or /tmp/<work>/<dir>/<file>)",
        "mode": "ro",
        "kind": "bind",
        "scope": "canary_read|canary_exec",
        "source": "<tmpdir>/canary (per-run copy of canary_path)",
    },
    {
        "target": "/tmp/<work>",
        "mode": "rw,size=16m,mode=1777",
        "kind": "tmpfs",
        "scope": "custom_mount",
        "source": "tmpfs (in-memory, 16 MiB cap)",
    },
    {
        "target": "/tmp/<work>/<dir>",
        "mode": "rw",
        "kind": "bind",
        "scope": "canary_exec",
        "source": "<tmpdir>/outside (per-run directory for canary_ran marker)",
    },
    {
        "target": "/oracle/outside.json",
        "mode": "rw",
        "kind": "bind",
        "scope": "canary_write",
        "source": "<tmpdir>/outside.json (post-run tmpfs listing)",
    },
    {
        "target": "/workspace/<sql_db>",
        "mode": "ro",
        "kind": "bind",
        "scope": "canary_sql",
        "source": "<tmpdir>/seed/seeded.db (seeded copy of application SQLite DB)",
    },
    {
        "target": "/seed/original.db",
        "mode": "ro",
        "kind": "bind",
        "scope": "canary_sql_seed",
        "source": "<tmpdir>/workspace/<sql_db> (staged application SQLite DB)",
    },
    {
        "target": "/seed/out",
        "mode": "rw",
        "kind": "bind",
        "scope": "canary_sql_seed",
        "source": "<tmpdir>/seed (per-run seed output directory)",
    },
)

# The oracle plugin is mounted read-only as a single module; only the events file is writable.
_PLUGIN_SOURCE = Path(__file__).resolve().parent.parent / "oracle" / "plugin.py"
_PLUGIN_MODULE = "exhibit_a_oracle_plugin"
_PLUGIN_DIR = "/opt/exhibit_a_plugin"
_CANARY_MOUNT = "/oracle/canary"
_EVENTS_MOUNT = "/oracle/events.jsonl"
_ENV_PREFIX = "EXHIBIT_A_"
_WORKSPACE = "/workspace"
_MARKER_NAME = "canary_ran"
_TOKEN_ENV = "EXHIBIT_A_CANARY_TOKEN"

# canary_sql: a first container adds the canary table to a copy of the application's database. It
# sees the original read-only and one scratch directory, with the same limits and no network as the
# test's container; the host never opens the database. The test's container then gets the copy
# mounted read-only over the declared path, so neither the test nor the app can change it.
_SEED_TIMEOUT = 120
_SEED_SCRIPT = f'''
import os, shutil, sqlite3, sys
source, target = sys.argv[1:3]
shutil.copyfile(source, target)
connection = sqlite3.connect(target)
connection.execute("PRAGMA trusted_schema=OFF")
connection.execute("PRAGMA journal_mode=DELETE").fetchall()
connection.execute("CREATE TABLE {SQL_CANARY_TABLE} ({SQL_CANARY_COLUMN} TEXT)")
connection.execute("INSERT INTO {SQL_CANARY_TABLE} ({SQL_CANARY_COLUMN}) VALUES (?)", (os.environ["EXHIBIT_A_CANARY_TOKEN"],))
connection.commit()
connection.close()
'''


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


def _container_user() -> str:
    """Return a non-root ``uid:gid`` string for ``docker run --user``.

    Maps to the invoking host user when non-root so bind-mounted files in the temporary directory
    are accessible; falls back to ``65534:65534`` (nobody:nogroup) when invoked as root.
    """
    uid = os.getuid() if hasattr(os, "getuid") else NON_ROOT_FALLBACK_UID
    gid = os.getgid() if hasattr(os, "getgid") else NON_ROOT_FALLBACK_GID
    if uid <= 0:
        uid = NON_ROOT_FALLBACK_UID
    if gid <= 0:
        gid = NON_ROOT_FALLBACK_GID
    return f"{uid}:{gid}"


def _seccomp_args() -> tuple[list[str], str | None]:
    """Return ``(["--security-opt", "seccomp=<path>"], None)`` or an error string if missing."""
    if not SECCOMP_PROFILE.is_file():
        return [], f"sandbox seccomp profile not found: {SECCOMP_PROFILE}"
    return ["--security-opt", f"seccomp={SECCOMP_PROFILE}"], None


def _resolve_runtime(runtime: str | None = None) -> tuple[list[str], str | None]:
    """Resolve the optional Docker runtime (``EXHIBIT_A_DOCKER_RUNTIME``).

    When set (e.g. ``runsc`` for gVisor), verifies that the runtime is installed in Docker and
    returns ``(["--runtime", rt], None)``. If the runtime is invalid or not installed, fails
    closed with an error string and never silently falls back to the default runtime.
    """
    rt = (runtime if runtime is not None else os.environ.get(RUNTIME_ENV, "")).strip()
    if not rt:
        return [], None
    if not _RUNTIME_RE.match(rt):
        return [], f"invalid docker runtime in {RUNTIME_ENV}: {rt!r}"
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{json .Runtimes}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return [], f"cannot verify docker runtime {rt!r}: {e}"
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace").strip() or "docker info failed"
        return [], f"cannot verify docker runtime {rt!r}: {err}"
    raw = proc.stdout.decode(errors="replace").strip()
    if raw:
        try:
            runtimes = json.loads(raw)
        except ValueError:
            return [], f"cannot parse docker runtimes for {rt!r}: {raw[:200]}"
        if not isinstance(runtimes, dict) or rt not in runtimes:
            avail = ", ".join(sorted(runtimes)) if isinstance(runtimes, dict) and runtimes else "none"
            return [], (
                f"requested docker runtime {rt!r} ({RUNTIME_ENV}) is not installed in Docker "
                f"(available: {avail})"
            )
    return ["--runtime", rt], None


def _verify_declared_mounts(cmd: list[str], tmpdir: str) -> str | None:
    """Audit every ``-v`` and ``--tmpfs`` flag in ``cmd`` against the declared mount policy.

    Every bind mount's host source must reside strictly inside ``tmpdir`` (never the Docker
    socket or arbitrary host paths), use an explicit ``ro`` or ``rw`` mode, and target one of
    the declared container mount points. Every ``--tmpfs`` mount must be under ``/tmp`` with an
    explicit size limit.
    """
    tmp_root = Path(tmpdir).resolve()
    static_targets = {
        _WORKSPACE,
        f"{_PLUGIN_DIR}/{_PLUGIN_MODULE}.py",
        _EVENTS_MOUNT,
        _CANARY_MOUNT,
        _OUTSIDE_MOUNT,
        "/seed/original.db",
        "/seed/out",
    }
    i = 0
    while i < len(cmd):
        arg = cmd[i]
        if arg in ("-v", "--volume"):
            if i + 1 >= len(cmd):
                return "missing volume specification after -v"
            spec = cmd[i + 1]
            parts = spec.split(":")
            if len(parts) != 3:
                return f"undeclared or unformatted volume specification: {spec!r}"
            host_src, container_dst, mode = parts
            if mode not in ("ro", "rw"):
                return f"invalid mount mode {mode!r} in {spec!r}"
            if "docker.sock" in host_src or "docker.sock" in container_dst:
                return f"forbidden docker socket mount: {spec!r}"
            try:
                resolved_src = Path(host_src).resolve()
            except OSError as e:
                return f"cannot resolve mount source {host_src!r}: {e}"
            if not resolved_src.is_relative_to(tmp_root):
                return f"host mount source {host_src!r} is outside per-run tmpdir {tmpdir!r}"
            allowed_target = (
                container_dst in static_targets
                or (container_dst.startswith("/tmp/") and ".." not in PurePosixPath(container_dst).parts)
                or (container_dst.startswith(f"{_WORKSPACE}/") and ".." not in PurePosixPath(container_dst).parts)
            )
            if not allowed_target:
                return f"undeclared container mount target: {container_dst!r}"
            i += 2
            continue
        if arg == "--tmpfs":
            if i + 1 >= len(cmd):
                return "missing tmpfs specification after --tmpfs"
            spec = cmd[i + 1]
            target, _, opts = spec.partition(":")
            if not (target == "/tmp" or target.startswith("/tmp/")) or "size=" not in opts:
                return f"undeclared or uncapped tmpfs mount: {spec!r}"
            i += 2
            continue
        if arg.startswith("--mount"):
            return f"undeclared --mount flag is not allowed: {arg!r}"
        i += 1
    return None


def _seed_database(
    image: str,
    source: str,
    seed_dir: str,
    token: str,
    runtime_args: list[str] | None = None,
    seccomp_args: list[str] | None = None,
    tmpdir: str | None = None,
) -> str | None:
    """Add the canary table to a copy of ``source`` in a throwaway container; None, or why it failed.

    Same isolation as the test's container: read-only root, no network, no capabilities, seccomp
    profile, non-root user, and the same limits. The original is mounted read-only; the copy lands
    in ``seed_dir``, the only writable mount.
    """
    if seccomp_args is None:
        seccomp_args, seccomp_err = _seccomp_args()
        if seccomp_err is not None:
            return seccomp_err
    if runtime_args is None:
        runtime_args, rt_err = _resolve_runtime()
        if rt_err is not None:
            return rt_err
    name = f"exhibit_a_seed_{uuid.uuid4().hex[:8]}"
    cmd = [
        "docker", "run", "--name", name, "--rm",
        *runtime_args,
        "--read-only", "--tmpfs", TMPFS_SPEC,
        "--network", "none", "-e", "HOME=/tmp", "-e", f"{_TOKEN_ENV}={token}", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        *seccomp_args,
        "--pids-limit", str(PIDS_LIMIT), "--memory", MEMORY_LIMIT,
        "--memory-swap", MEMORY_LIMIT, "--cpus", CPUS_LIMIT,
        "-v", f"{source}:/seed/original.db:ro", "-v", f"{seed_dir}:/seed/out:rw",
        "--user", _container_user(), image,
        "python", "-I", "-S", "-c", _SEED_SCRIPT, "/seed/original.db", "/seed/out/seeded.db",
    ]
    if tmpdir is not None:
        mount_err = _verify_declared_mounts(cmd, tmpdir)
        if mount_err is not None:
            return mount_err
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=_SEED_TIMEOUT)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "seeding the canary table timed out"
    except OSError as e:
        return f"cannot seed the canary table: {e}"
    if proc.returncode != 0:
        return "cannot add the canary table to the application's database: " + proc.stderr.decode(errors="replace")[-500:]
    return None


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
    sql_db: str | None = None,
    runtime: str | None = None,
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
        sql_db: for effect="canary_sql", the application's database as a path relative to the clone. It
            must exist there as a regular file; the test's container sees a copy of it with the canary
            table added, mounted read-only at that path.
        runtime: optional Docker runtime name (defaults to `EXHIBIT_A_DOCKER_RUNTIME`, e.g. `runsc` for gVisor).
            Fails closed with `env_failure` if set and not installed.

    Returns:
        dict with outcome, exit_code, stdout, stderr, oracle_events, oracle_forged_events,
        oracle_forged_reason and app_tree_changes.
    """
    if not _check_docker_available():
        return _env_failure("docker not available")

    seccomp_args, seccomp_err = _seccomp_args()
    if seccomp_err is not None:
        return _env_failure(seccomp_err)

    runtime_args, runtime_err = _resolve_runtime(runtime)
    if runtime_err is not None:
        return _env_failure(runtime_err)

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

        if effect not in ("canary_read", "canary_write", "canary_exec", "canary_sql"):
            return _env_failure(f"unknown oracle effect: {effect}")
        if effect == "canary_write":
            if canary_path is not None:
                return _env_failure("a write effect mounts no canary file: canary_path must be None")
            if not custom_mount:
                return _env_failure("a write effect needs a canary_mount of the shape /tmp/<work>/<dir>/<file>")
        if effect == "canary_exec" and (canary_path is None or not custom_mount or _TOKEN_ENV not in extra_env):
            return _env_failure("an exec effect needs the canary, a canary_mount of the shape "
                                f"/tmp/<work>/<dir>/<file> and {_TOKEN_ENV}")
        if effect == "canary_sql":
            problem = sql_db_problem(Path(workspace), sql_db)
            if problem is not None:
                return _env_failure(problem)
            if canary_path is not None or events_path is None or _TOKEN_ENV not in extra_env:
                return _env_failure("a sql effect mounts no canary file and needs events_path and "
                                    f"{_TOKEN_ENV}")
        observe = canary_path is not None or events_path is not None or effect == "canary_write"
        oracle_key = secrets.token_bytes(KEY_BYTES)
        events_file = os.path.join(tmpdir, "events.jsonl")
        outside_file = os.path.join(tmpdir, "outside.json")
        outside_dir = os.path.join(tmpdir, "outside")
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
                if effect == "canary_exec":
                    # The canary stays a read-only file, now executable. The directory around it is
                    # a bind mount, because a tmpfs is noexec and the mount point of a file inside it
                    # would leave outside/ owned by root: the marker lands here and the host reads
                    # it itself after the run, trusting nothing the container says about it.
                    os.chmod(canary_copy, 0o555)
                    os.mkdir(outside_dir)
                    os.chmod(outside_dir, 0o777)
                    Path(outside_dir, mount.name).touch(mode=0o444)
                    marker = mount.parent / _MARKER_NAME
                    extra_args += ["-v", f"{outside_dir}:{mount.parent}:rw", "-e", f"{ENV_MARKER}={marker}"]
                extra_args += ["-v", f"{canary_copy}:{mount}:ro", "-e", f"EXHIBIT_A_CANARY={mount}"]
            elif effect == "canary_sql":
                # The canary is the database file, at its declared path; the mount comes once the
                # seeded copy exists (below). The plugin gets the path and the table, never the test.
                extra_args += ["-e", f"EXHIBIT_A_CANARY={_WORKSPACE}/{sql_db}", "-e", f"{ENV_SQL}={SQL_CANARY_TABLE}"]
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
            if effect == "canary_exec":
                payload["canary_ran"] = marker_holds_token(
                    Path(outside_dir, _MARKER_NAME), extra_env[_TOKEN_ENV])
            return payload

        # 1) Resolve the prebuilt image (built once with network, reused across runs).
        if image is None:
            try:
                image = build_image([PYTEST_VERSION, *(requirements or [])])
            except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as e:
                return _env_failure(f"failed to prepare sandbox image: {e}")

        if effect == "canary_sql":
            seed_dir = os.path.join(tmpdir, "seed")
            os.mkdir(seed_dir)
            os.chmod(seed_dir, 0o777)
            seeded = os.path.join(seed_dir, "seeded.db")
            failure = _seed_database(
                image,
                os.path.join(workspace, str(sql_db)),
                seed_dir,
                extra_env[_TOKEN_ENV],
                runtime_args=runtime_args,
                seccomp_args=seccomp_args,
                tmpdir=tmpdir,
            )
            if failure is not None:
                return _env_failure(failure)
            try:
                if not stat.S_ISREG(os.lstat(seeded).st_mode):
                    return _env_failure("the seeded database is not a regular file")
                os.chmod(seeded, 0o444)
            except OSError as e:
                return _env_failure(f"the seeded database is missing: {e}")
            extra_args += ["-v", f"{seeded}:{_WORKSPACE}/{sql_db}:ro"]

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
            *runtime_args,
            "--read-only",
            "--tmpfs",
            TMPFS_SPEC,
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
            *seccomp_args,
            "--pids-limit",
            str(PIDS_LIMIT),
            "--memory",
            MEMORY_LIMIT,
            "--memory-swap",
            MEMORY_LIMIT,
            "--cpus",
            CPUS_LIMIT,
            "-v",
            f"{workspace}:{_WORKSPACE}:rw",
            *extra_args,
            "--workdir",
            "/workspace",
            "--user",
            _container_user(),
            image,
            *pytest_argv,
        ]

        mount_err = _verify_declared_mounts(cmd, tmpdir)
        if mount_err is not None:
            return _env_failure(mount_err)

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
            if exit_code in (125, 126, 127) and (
                runtime_args
                or "docker:" in stderr
                or "OCI runtime" in stderr
                or "unknown or invalid runtime" in stderr
            ):
                return _env_failure(f"docker failed to start container: {stderr.strip()}")
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


_PROBE_SCRIPT = r"""
import ctypes, errno, json, os, socket

def _read_first(paths):
    for p in paths:
        if os.path.exists(p):
            try:
                return open(p, encoding="utf-8", errors="replace").read().strip()
            except OSError:
                pass
    return ""

status = {}
try:
    for line in open("/proc/self/status", encoding="utf-8", errors="replace"):
        if ":" in line:
            k, v = line.split(":", 1)
            status[k.strip()] = v.strip()
except OSError:
    pass

interfaces = []
try:
    for line in open("/proc/net/dev", encoding="utf-8", errors="replace").read().splitlines()[2:]:
        if ":" in line:
            interfaces.append(line.split(":", 1)[0].strip())
except OSError:
    pass

net_connect_blocked = False
try:
    s = socket.create_connection(("1.1.1.1", 80), timeout=1)
    s.close()
except OSError:
    net_connect_blocked = True

rootfs_readonly = False
try:
    with open("/_exhibit_a_probe", "w") as fh:
        fh.write("x")
except OSError as exc:
    rootfs_readonly = exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM)

tmp_writable = False
try:
    p = "/tmp/_exhibit_a_probe"
    with open(p, "w") as fh:
        fh.write("ok")
    os.unlink(p)
    tmp_writable = True
except OSError:
    tmp_writable = False

mounts = []
try:
    for line in open("/proc/self/mountinfo", encoding="utf-8", errors="replace"):
        parts = line.split()
        if len(parts) >= 5 and "-" in parts:
            dash = parts.index("-")
            fstype = parts[dash + 1] if dash + 1 < len(parts) else ""
            mounts.append({"mount_point": parts[4], "fstype": fstype, "opts": parts[5]})
except OSError:
    pass

libc = ctypes.CDLL(None, use_errno=True)

def _errno_name(code):
    return errno.errorcode.get(code, str(code))

ctypes.set_errno(0)
r_ptrace = libc.ptrace(-1, 0, 0, 0)
ptrace_errno = _errno_name(ctypes.get_errno()) if r_ptrace == -1 else "OK"

ctypes.set_errno(0)
r_unshare = libc.unshare(0)
unshare_errno = _errno_name(ctypes.get_errno()) if r_unshare == -1 else "OK"

ctypes.set_errno(0)
r_mount = libc.mount(0, 0, 0, 0, 0)
mount_errno = _errno_name(ctypes.get_errno()) if r_mount == -1 else "OK"

try:
    os.chroot("/tmp")
    chroot_errno = "OK"
except OSError as exc:
    chroot_errno = _errno_name(exc.errno)

try:
    os.setuid(0)
    setuid_errno = "OK"
except OSError as exc:
    setuid_errno = _errno_name(exc.errno)

try:
    os.chown("/tmp", 0, 0)
    chown_errno = "OK"
except OSError as exc:
    chown_errno = _errno_name(exc.errno)

mem_max = _read_first(["/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"])
mem_swap_max = _read_first(["/sys/fs/cgroup/memory.swap.max", "/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes"])
pids_max = _read_first(["/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max"])
cpu_max = _read_first(["/sys/fs/cgroup/cpu.max"])
if not cpu_max:
    q = _read_first(["/sys/fs/cgroup/cpu/cpu.cfs_quota_us"])
    p = _read_first(["/sys/fs/cgroup/cpu/cpu.cfs_period_us"])
    if q and p:
        cpu_max = f"{q} {p}"

payload = {
    "uid": os.getuid(),
    "euid": os.geteuid(),
    "gid": os.getgid(),
    "egid": os.getegid(),
    "no_new_privs": status.get("NoNewPrivs", ""),
    "seccomp_mode": status.get("Seccomp", ""),
    "capabilities": {
        "CapInh": status.get("CapInh", ""),
        "CapPrm": status.get("CapPrm", ""),
        "CapEff": status.get("CapEff", ""),
        "CapBnd": status.get("CapBnd", ""),
        "CapAmb": status.get("CapAmb", ""),
    },
    "seccomp_probes": {
        "ptrace": ptrace_errno,
        "unshare": unshare_errno,
        "mount": mount_errno,
        "chroot": chroot_errno,
        "setuid": setuid_errno,
        "chown": chown_errno,
    },
    "network": {
        "interfaces": interfaces,
        "external_connect_blocked": net_connect_blocked,
    },
    "filesystem": {
        "rootfs_readonly": rootfs_readonly,
        "tmp_writable": tmp_writable,
        "docker_socket_present": os.path.exists("/var/run/docker.sock"),
        "mounts": mounts,
    },
    "limits": {
        "memory_max": mem_max,
        "memory_swap_max": mem_swap_max,
        "pids_max": pids_max,
        "cpu_max": cpu_max,
    },
}
print(json.dumps(payload))
"""


def probe_isolation(
    runtime: str | None = None,
    image: str | None = None,
    timeout: float = 60.0,
) -> Dict[str, Any]:
    """Run a probe container with the sandbox's isolation flags and return observed effective settings."""
    if not _check_docker_available():
        return {"ok": False, "error": "docker not available", "probe": None}

    seccomp_args, seccomp_err = _seccomp_args()
    if seccomp_err is not None:
        return {"ok": False, "error": seccomp_err, "probe": None}

    configured_rt = (runtime if runtime is not None else os.environ.get(RUNTIME_ENV, "")).strip()
    runtime_args, runtime_err = _resolve_runtime(runtime)
    if runtime_err is not None:
        return {"ok": False, "error": runtime_err, "probe": None, "configured_runtime": configured_rt}

    default_rt = "runc"
    available_runtimes: list[str] = []
    try:
        info_proc = subprocess.run(
            ["docker", "info", "--format", "{{.DefaultRuntime}}\n{{json .Runtimes}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        if info_proc.returncode == 0:
            lines = info_proc.stdout.decode(errors="replace").splitlines()
            if lines and lines[0].strip():
                default_rt = lines[0].strip()
            if len(lines) >= 2 and lines[1].strip():
                rts = json.loads(lines[1].strip())
                if isinstance(rts, dict):
                    available_runtimes = sorted(rts)
    except Exception:
        pass

    if image is None:
        try:
            image = build_image([PYTEST_VERSION])
        except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as e:
            return {"ok": False, "error": f"failed to prepare sandbox image: {e}", "probe": None}

    probe_name = f"exhibit_a_probe_{uuid.uuid4().hex[:8]}"
    cmd = [
        "docker",
        "run",
        "--name",
        probe_name,
        "--rm",
        *runtime_args,
        "--read-only",
        "--tmpfs",
        TMPFS_SPEC,
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
        *seccomp_args,
        "--pids-limit",
        str(PIDS_LIMIT),
        "--memory",
        MEMORY_LIMIT,
        "--memory-swap",
        MEMORY_LIMIT,
        "--cpus",
        CPUS_LIMIT,
        "--user",
        _container_user(),
        image,
        "python",
        "-I",
        "-S",
        "-c",
        _PROBE_SCRIPT,
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", probe_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"ok": False, "error": "probe container timed out", "probe": None}
    except OSError as e:
        return {"ok": False, "error": str(e), "probe": None}

    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace").strip()
        return {"ok": False, "error": f"probe container failed (exit {proc.returncode}): {err}", "probe": None}

    try:
        probe_data = json.loads(proc.stdout.decode(errors="replace").strip())
    except ValueError as e:
        return {"ok": False, "error": f"invalid probe output: {e}", "probe": None}

    return {
        "ok": True,
        "error": "",
        "configured_runtime": configured_rt or None,
        "effective_runtime": configured_rt or default_rt,
        "available_runtimes": available_runtimes,
        "seccomp_profile_path": str(SECCOMP_PROFILE),
        "probe": probe_data,
    }

