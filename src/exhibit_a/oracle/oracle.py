"""Run an exploit test against a target app and judge whether its failure is real.

The oracle plants a canary file outside the app's allowed directory, runs the exploit test
in a subprocess with the observer plugin loaded, and checks two things:

* effect: the canary was opened while the test ran;
* provenance: the open came from application code reached through a declared entry point,
  called from the test, and not from the test touching the sink or the file itself.

The subprocess is a plain child process. The sandbox (a separate component) is what makes
untrusted tests safe to run; the oracle only decides what the run means.

Events are trusted only if they carry a valid signature under a key generated here for this
run and handed to the plugin on stdin (finding A-1, see docs/oracle/oracle-a1.md). Lines that do not
verify are dropped and counted; any such line rules out a proof. Before running, the test
source is checked by a static tripwire (``guard.py``) for references to the oracle channel
and for writes into, or forging from, the application tree.

Provenance is authenticated against the app as staged (docs/oracle/oracle-provenance.md): the app
tree is hashed before the run and the manifest goes to the plugin on stdin with the key; only
frames the plugin admitted against it, and that pass the host-side re-check, are application
code. The tree is hashed again after the run; any change rules out a proof.

The test is never told where the canary is (finding A-11 F2): it gets the allowed directory and
the token, and a real exploit reaches the canary from there. Each event carries the path the
code requested; one that neither starts inside the allowed directory nor names the canary
exactly is refused (``canary_not_via_allowed_dir``). Access comes from the open flags, not the
mode string (F4), and a write effect also needs the canary to exist with the token after the
run (F5). See docs/oracle/oracle-provenance.md, section 3.7.

The ``canary_exec`` effect (command execution, unsafe deserialization) plants an executable
instead; ``_judge_exec`` and section 3.9 of that document say what proves it. The ``canary_sql``
effect (SQL injection) adds a table with the token to a copy of the application's own SQLite
database; ``_judge_sql`` and section 3.10 say what proves it. The ``canary_connect`` effect (SSRF)
starts a loopback HTTP listener that serves the token at one unguessable path; ``_judge_connect``
and section 3.11 say what proves it. The ``canary_dos`` effect (algorithmic complexity: ReDoS,
quadratic parsing) has the runner time the entry point on a malicious input against a benign
input of the same length; ``_judge_dos`` and section 3.12 say what proves it.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Collection
from pathlib import Path, PurePath, PurePosixPath
from typing import Literal
from urllib.parse import urlsplit

from exhibit_a.oracle.guard import channel_problem, connect_problem, dos_problem, exec_problem, sql_problem
from exhibit_a.oracle.plugin import (
    DOS_FLOOR,
    DOS_MIN_APP_FRACTION,
    DOS_RATIO,
    ENV_CANARY,
    ENV_CONNECT,
    ENV_DOS,
    ENV_EVENTS,
    ENV_MARKER,
    ENV_SQL,
    KEY_BYTES,
    key_message,
    verify_lines,
)
from exhibit_a.oracle.provenance import AppTree, ManifestError, app_manifest, tree_changes
from exhibit_a.schemas.base import StrictModel

ENV_ALLOWED_DIR = "EXHIBIT_A_ALLOWED_DIR"
ENV_CANARY_TOKEN = "EXHIBIT_A_CANARY_TOKEN"
#: The test contract for canary_connect: the full URL of the per-run loopback listener.
ENV_CONNECT_URL = ENV_CONNECT

TestOutcome = Literal["passed", "failed", "error", "timeout"]

# Which effect on the canary counts as proof for this run. "canary_read" is the original
# path-traversal style effect (the app leaks a file outside the allowed directory);
# "canary_write" is the archive-extraction / zip-slip style effect (the app creates a file
# outside the allowed directory). Both are observed through the same signed events; only the
# access the event carries differs. See docs/oracle/second-class.md. "canary_exec" is command
# execution: the app runs an executable outside the allowed directory, which leaves the token in
# a marker file beside it; it has its own judge (_judge_exec). "canary_sql" is SQL injection: the
# app reads a row of a table it never queries, in its own SQLite database (_judge_sql).
Effect = Literal["canary_read", "canary_write", "canary_exec", "canary_sql", "canary_connect", "canary_dos"]
# Which accesses count for each effect: "r+" or O_RDWR is both a read and a write.
_ACCEPTED_ACCESS = {"canary_read": {"read", "read_write"}, "canary_write": {"write", "read_write"}}
# A write effect reads at most this much of the canary after the run to find the token.
_MAX_CANARY_READ = 1 << 20
# canary_exec: the executable and the marker it leaves, side by side under outside/.
EXEC_CANARY_NAME = "canary"
EXEC_MARKER_NAME = "canary_ran"
# canary_sql: the table (and its one column) added to a copy of the application's database. The
# test is told the table's name and that the application never queries it, never the database path.
SQL_CANARY_TABLE = "exhibit_canary"
SQL_CANARY_COLUMN = "token"
_MAX_SQL_DB_BYTES = 256 << 20
_SQL_DB_PATH = re.compile(r"[A-Za-z0-9_./-]{1,200}")
_PLUGIN_MODULE = "exhibit_a_oracle_plugin"
_PLUGIN_SOURCE = Path(__file__).resolve().parent / "plugin.py"


def _access(event: OracleEvent) -> str:
    """``read``, ``write``, ``read_write`` or ``unknown``: what the observed operation could do.

    The plugin classifies an open from its flags on the platform it runs on. An open event
    without ``flags`` (older plugins recorded only the mode string, which is ``None`` for
    ``os.open``) is ``unknown`` and proves neither effect; so is any event without ``access``.
    """
    if event.access is None or (event.op == "open" and event.flags is None):
        return "unknown"
    return event.access

# Machine-readable reasons a judgement is not a proof (Judgement.reason_code).
REASON_CHANNEL_TRIPWIRE = "channel_tripwire"
REASON_FORGED_EVENTS = "forged_events"
REASON_APP_TREE_CHANGED = "app_tree_changed"
REASON_FRAME_NOT_ADMITTED = "frame_not_admitted"
REASON_NO_EFFECT = "no_effect"
REASON_PROVENANCE = "provenance"
REASON_MANIFEST_FAILED = "manifest_failed"
REASON_NOT_VIA_ALLOWED_DIR = "canary_not_via_allowed_dir"
REASON_CANARY_TAMPERED = "canary_tampered"
REASON_FROM_TEST = "process_from_test"
REASON_PROCESS_API_CHANGED = "process_api_changed"
REASON_CONNECT_FROM_TEST = "connect_from_test"
REASON_SQL_FROM_TEST = "sql_from_test"
REASON_SQL_API_CHANGED = "sql_api_changed"
REASON_SQL_UNPLACED = "sql_unplaced"
REASON_FLAKY = "flaky"
REASON_DOS_FROM_TEST = "dos_from_test"
REASON_DOS_API_CHANGED = "dos_api_changed"


class Frame(StrictModel):
    file: str
    function: str
    qualname: str
    # The code object's first line (co_firstlineno), and, for frames under the app root of a
    # run that had a manifest, whether the plugin admitted the frame as staged app code and,
    # if not, why. Missing in events from older plugins, which admits nothing.
    line: int | None = None
    admitted: bool | None = None
    admission: str | None = None


class OracleEvent(StrictModel):
    """One observed open of (or rename or link onto) the canary file."""

    type: Literal["canary_read"] = "canary_read"
    path: str
    # The audit event's mode string for an open; the event name for a rename or link.
    mode: str
    stack: list[Frame]
    # How the canary was reached and what the operation could do (see plugin.access_of).
    # Missing in events from older plugins, which classify as "unknown": never a proof.
    op: Literal[
        "open", "rename", "link", "process", "native", "env", "chdir", "codegen",
        "sql_connect", "sql_read", "sql_text", "connect", "request", "dos",
    ] = "open"
    flags: int | None = None
    access: Literal["read", "write", "read_write", "unknown", "exec", "sql", "cpu"] | None = None
    # The path as the code asked for it, absolute but not resolved; None if unknown.
    requested: str | None = None
    # Set when the opened path went through a symlink created during the run; such a read
    # has no provenance. Missing in events from older plugins, which means False.
    via_symlink: bool = False
    symlink: str | None = None
    symlink_target: str | None = None
    # canary_exec only: which file an open reached, the command a process event started, whether
    # it names the canary, whether the innermost app frame names a sink, and what changed since
    # install (a watched API or sensitive variable) when the process started.
    target: Literal["canary", "marker", "db"] = "canary"
    command: str | None = None
    names_canary: bool = False
    sink_named: bool = False
    patched: str | None = None
    # canary_sql only. ``sql_connect``: ``connection`` (the plugin's index of it), whether it was
    # opened on the application's own database file, whether the plugin could instrument it, and in
    # ``command`` the database name as passed; ``patched`` names ``sqlite3.connect`` if it was no
    # longer the plugin's wrapper. ``sql_read``: a read of the canary ``table`` and ``column`` in
    # ``database`` (sqlite's name for it: main, temp or an alias) on that ``connection``.
    # ``sql_text``: the statement that read it, from the trace callback.
    # canary_connect only. ``connect``: the ``host`` and ``port`` of an outbound connection
    # attempt (``socket.connect``, ``socket.getaddrinfo``, ``http.client.connect``); ``request``:
    # the ``url`` of an HTTP request (``urllib.Request``) or its request target
    # (``http.client.send``). ``path`` is the run's canary URL.
    host: str | None = None
    port: int | None = None
    url: str | None = None
    # canary_dos only. Median malicious/benign application CPU, the fraction of malicious
    # CPU spent in admitted app frames, how many pairs were sampled, and whether the
    # malicious samples were too spread to trust (``noisy``: never a proof).
    ratio: float | None = None
    malicious_cpu: float | None = None
    benign_cpu: float | None = None
    app_fraction: float | None = None
    samples: int | None = None
    noisy: bool = False
    connection: int | None = None
    declared_db: bool = False
    instrumented: bool = False
    table: str | None = None
    column: str | None = None
    database: str | None = None


class Judgement(StrictModel):
    observed_effect: bool
    provenance_ok: bool
    reason: str
    test_outcome: TestOutcome
    events: list[OracleEvent] = []
    # Event lines dropped because they did not verify (bad signature, unsigned, replayed or
    # reordered seq, malformed). Any of them rules out a proof.
    forged_events: int = 0
    # Entries of the application tree added, removed or modified during the run ("added: p",
    # "removed: p", "modified: p", or "unverifiable: ..."). Any of them rules out a proof.
    app_tree_changes: list[str] = []
    # One of the REASON_* codes when the judgement is not a proof; "" for a proof.
    reason_code: str = ""


def run_oracle(
    app_root: Path,
    test_path: Path,
    entry_points: Collection[str],
    *,
    timeout: float = 60.0,
    effect: Effect = "canary_read",
    sql_db: str | None = None,
) -> Judgement:
    """Run ``test_path`` against the app in ``app_root`` and judge the result.

    ``entry_points`` are the function names (plain or qualified) through which a real
    request enters the application, e.g. ``{"App.handle_request"}``. The test finds the
    allowed directory and the canary through the ``EXHIBIT_A_*`` environment variables.

    ``effect`` selects what counts as proof: ``"canary_read"`` (the app reads a file outside
    the allowed directory) or ``"canary_write"`` (the app creates a file outside it, as in an
    archive-extraction / zip-slip escape). For a write effect the canary file is not planted:
    the proof is that the app itself opens the canary path for writing, so it must not exist
    beforehand. ``"canary_exec"`` plants an executable at ``outside/canary``: the app must run it
    (see ``_judge_exec``). ``"canary_sql"`` runs the test against a staged copy of the app whose
    database, ``sql_db`` (a path relative to ``app_root``, a SQLite file the app uses), has the canary
    table added; the app must read it through an entry point (see ``_judge_sql``). Raises
    ``ValueError`` if ``sql_db`` is missing or unusable. ``"canary_connect"`` starts a loopback
    HTTP listener serving the token at one unguessable path; the app must request that URL
    through an entry point (see ``_judge_connect``). ``"canary_dos"`` times the entry point
    on a malicious input against a same-length benign input (see ``_judge_dos``).
    """
    if effect not in (
        "canary_read", "canary_write", "canary_exec", "canary_sql", "canary_connect", "canary_dos",
    ):
        raise ValueError(f"unknown effect {effect!r}")
    if sql_db is not None and effect != "canary_sql":
        raise ValueError("sql_db is only for the canary_sql effect")
    app_root = Path(app_root).resolve()
    test_path = Path(test_path).resolve()

    problem = channel_problem(test_path)
    if problem is None and effect == "canary_exec":
        problem = exec_problem(test_path)
    if problem is None and effect == "canary_sql":
        problem = sql_problem(test_path)
    if problem is None and effect == "canary_connect":
        problem = connect_problem(test_path)
    if problem is None and effect == "canary_dos":
        problem = dos_problem(test_path)
    if problem is not None:
        # Not run at all: an "error" outcome, which the loop classifies as invalid_test.
        return Judgement(
            observed_effect=False, provenance_ok=False, reason=problem, test_outcome="error",
            reason_code=REASON_CHANNEL_TRIPWIRE,
        )
    if effect == "canary_sql":
        return _run_sql(app_root, test_path, set(entry_points), timeout, sql_db)
    if effect == "canary_connect":
        return _run_connect(app_root, test_path, set(entry_points), timeout)
    if effect == "canary_dos":
        return _run_dos(app_root, test_path, set(entry_points), timeout)

    # The test's own directory is test code even when it sits inside the app root.
    exclude = []
    if test_path.parent.is_relative_to(app_root) and test_path.parent != app_root:
        exclude.append(test_path.parent.relative_to(app_root).as_posix())
    elif test_path.parent == app_root:
        exclude += [test_path.name, "conftest.py"]
    try:
        manifest = app_manifest(app_root, exclude)
    except ManifestError as exc:
        return Judgement(
            observed_effect=False, provenance_ok=False, test_outcome="error",
            reason=f"the application tree could not be hashed before the run: {exc}",
            reason_code=REASON_MANIFEST_FAILED,
        )

    key = secrets.token_bytes(KEY_BYTES)
    with tempfile.TemporaryDirectory(prefix="exhibit_a_oracle_") as tmp:
        work = Path(tmp).resolve()
        allowed = work / "allowed"
        outside = work / "outside"
        allowed.mkdir()
        outside.mkdir()
        (allowed / "public.txt").write_text("public file\n", encoding="utf-8")
        token = "CANARY-" + secrets.token_hex(16)
        canary = outside / (EXEC_CANARY_NAME if effect == "canary_exec" else "canary.txt")
        marker = outside / EXEC_MARKER_NAME
        script = exec_canary_script(marker, token)
        if effect == "canary_read":
            # Read effect: the canary must exist for the app to leak it.
            canary.write_text(token + "\n", encoding="utf-8")
        elif effect == "canary_exec":
            canary.write_text(script, encoding="utf-8")
            canary.chmod(0o555)
        # Write effect: leave the canary absent; the app proves the escape by creating it.
        events_path = work / "events.jsonl"
        ini = work / "pytest.ini"
        ini.write_text("[pytest]\n", encoding="utf-8")

        outcome = _run_test(
            app_root, test_path, work, ini, allowed, canary, token, events_path, timeout, key=key,
            manifest=manifest, marker=marker if effect == "canary_exec" else None,
        )
        events, forged, forged_reason = _read_events(events_path, key)
        written = canary_written(canary, token) if effect == "canary_write" else None
        ran = None
        if effect == "canary_exec":
            ran = marker_holds_token(marker, token) and _file_is(canary, script)
    changes = tree_changes(app_root, manifest, exclude)

    # On this path the app root is also the source of truth for the host-side re-check; any
    # change to it is reported above and rules out a proof, so its content is the staged one.
    return _judge(
        outcome, events, app_root, test_path, set(entry_points),
        effect=effect, forged_events=forged, forged_reason=forged_reason,
        app_tree=AppTree(str(app_root), app_root, manifest), app_tree_changes=changes,
        allowed_dir=str(allowed), canary_written=written, canary_ran=ran,
    )


def sql_db_shape_problem(rel: object) -> str | None:
    """Why ``rel`` cannot name the application's database (``run.sql_db``), or None.

    It must be a plain relative path inside the app: letters, digits and ``_./-`` only (it ends up
    in a container mount specification), no ``..`` or ``.`` component, no empty one, no leading ``/``.
    """
    if not isinstance(rel, str) or not rel:
        return "sql_db must be a non-empty path relative to the application tree"
    if not _SQL_DB_PATH.fullmatch(rel):
        return "sql_db may only hold letters, digits and '_', '.', '-', '/' (at most 200 characters)"
    path = PurePosixPath(rel)
    if path.is_absolute() or path.as_posix() != rel or any(part in (".", "..") for part in path.parts):
        return "sql_db must be a normalised relative path without '.' or '..' components"
    return None


def sql_db_problem(root: Path, rel: object) -> str | None:
    """Why ``root / rel`` cannot be the application's database, or None.

    The database must be a regular file (not a link, nor behind one) inside ``root``, of a size
    that is cheap to copy for every run. It may be empty: an empty file is a valid empty SQLite
    database. A missing file is a problem: the app has to find its own database where it expects it.
    """
    problem = sql_db_shape_problem(rel)
    if problem is not None:
        return problem
    current = Path(root)
    for part in PurePosixPath(str(rel)).parts:
        current = current / part
        try:
            st = os.lstat(current)
        except OSError:
            return f"sql_db {rel!r} does not exist in the application tree"
        if stat.S_ISLNK(st.st_mode):
            return f"sql_db {rel!r} is, or is behind, a symbolic link"
    if not stat.S_ISREG(st.st_mode):
        return f"sql_db {rel!r} is not a regular file"
    if st.st_size > _MAX_SQL_DB_BYTES:
        return f"sql_db {rel!r} is larger than {_MAX_SQL_DB_BYTES >> 20} MiB"
    return None


def seed_sql_canary(db: Path, token: str) -> None:
    """Add the canary table, holding ``token``, to ``db``, a private copy of the app's database.

    Host path only (a research and test tool, not isolated): the sandbox seeds inside a container
    (sandbox/runner.py). The copy is switched to the rollback journal, so reading it never needs a
    write-ahead log beside it, and made read-only, so the tree check sees any change to it. A
    database that already has a table of that name is refused rather than trusted.
    """
    import sqlite3

    try:
        connection = sqlite3.connect(db)
        try:
            connection.execute("PRAGMA journal_mode=DELETE").fetchall()
            connection.execute(f"CREATE TABLE {SQL_CANARY_TABLE} ({SQL_CANARY_COLUMN} TEXT)")
            connection.execute(f"INSERT INTO {SQL_CANARY_TABLE} ({SQL_CANARY_COLUMN}) VALUES (?)", (token,))
            connection.commit()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise ValueError(f"cannot add the canary table to the application's database: {exc}") from exc
    os.chmod(db, 0o444)


def _run_sql(app_root: Path, test_path: Path, entry_points: set[str], timeout: float, sql_db: str | None) -> Judgement:
    """The host path of ``canary_sql``: run in a staged copy of the app, with the canary table seeded.

    The application's own database file is never touched: the app is copied into the work
    directory, the canary table is added to the copy and the test runs there. The copy is hashed
    with the rest of the app (database included, read-only), so a change to it by the app or the
    test shows in the tree check.
    """
    problem = sql_db_problem(app_root, sql_db)
    if problem is not None:
        raise ValueError(problem)
    key = secrets.token_bytes(KEY_BYTES)
    token = "CANARY-" + secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix="exhibit_a_oracle_") as tmp:
        work = Path(tmp).resolve()
        allowed = work / "allowed"
        allowed.mkdir()
        (allowed / "public.txt").write_text("public file\n", encoding="utf-8")
        stage = work / "app"
        try:
            shutil.copytree(app_root, stage, symlinks=True)
        except (OSError, shutil.Error) as exc:
            return Judgement(
                observed_effect=False, provenance_ok=False, test_outcome="error",
                reason=f"the application tree could not be staged: {exc}", reason_code=REASON_MANIFEST_FAILED,
            )
        run_test = stage / test_path.relative_to(app_root) if test_path.is_relative_to(app_root) else test_path
        db = stage / str(sql_db)
        seed_sql_canary(db, token)
        exclude = []
        if run_test.parent.is_relative_to(stage) and run_test.parent != stage:
            exclude.append(run_test.parent.relative_to(stage).as_posix())
        elif run_test.parent == stage:
            exclude += [run_test.name, "conftest.py"]
        try:
            manifest = app_manifest(stage, exclude)
        except ManifestError as exc:
            return Judgement(
                observed_effect=False, provenance_ok=False, test_outcome="error",
                reason=f"the application tree could not be hashed before the run: {exc}",
                reason_code=REASON_MANIFEST_FAILED,
            )
        events_path = work / "events.jsonl"
        ini = work / "pytest.ini"
        ini.write_text("[pytest]\n", encoding="utf-8")
        outcome = _run_test(
            stage, run_test, work, ini, allowed, db.resolve(), token, events_path, timeout, key=key,
            manifest=manifest, sql_table=SQL_CANARY_TABLE,
        )
        events, forged, forged_reason = _read_events(events_path, key)
        changes = tree_changes(stage, manifest, exclude)
        return _judge(
            outcome, events, stage, run_test, entry_points,
            effect="canary_sql", forged_events=forged, forged_reason=forged_reason,
            app_tree=AppTree(str(stage), stage, manifest), app_tree_changes=changes,
        )


#: Hosts that count as this machine's loopback for a canary connection.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"})
_SERVER_SOURCE = Path(__file__).resolve().parent / "canary_server.py"
_MAX_CONNECT_LOG_BYTES = 1 << 20
_MAX_CONNECT_LOG_LINES = 10000


def canary_connect_url(port: int, secret: str) -> str:
    """The canary URL for a run: the loopback listener with its unguessable path."""
    return f"http://127.0.0.1:{port}/{secret}"


def parse_canary_url(url: object) -> tuple[str, int, str] | None:
    """``(host, port, secret path)`` of a canary URL, or None if it is not one.

    A canary URL is an ``http`` URL on a loopback host with an explicit port and a
    non-empty path. Anything else (another scheme or host, a missing port or path) is
    not a URL the oracle ever hands out and never matches.
    """
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "http" or not parts.hostname or not parts.path or parts.path == "/":
        return None
    if parts.port is None:
        return None
    host = parts.hostname.lower()
    if host not in _LOOPBACK_HOSTS:
        return None
    return host, parts.port, parts.path


def pick_connect_port() -> int:
    """A random loopback port for the canary listener (20000-59999)."""
    return 20000 + secrets.randbelow(40000)


def read_connect_log(path: Path) -> list[dict]:
    """Listener records from ``path``; malformed lines are dropped, never trusted.

    The log file is writable from inside the run, so every line is untrusted: only a
    dict with a string ``target`` counts as a request record. The oracle never proves
    from this file alone (see ``_judge_connect``).
    """
    try:
        if os.lstat(path).st_size > _MAX_CONNECT_LOG_BYTES:
            return []
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []
    records = []
    for line in lines[:_MAX_CONNECT_LOG_LINES]:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        # Request records carry the request target; connection records carry none.
        if isinstance(item.get("target"), str) or item.get("kind") == "connection":
            records.append(item)
    return records


def _run_connect(app_root: Path, test_path: Path, entry_points: set[str], timeout: float) -> Judgement:
    """The host path of ``canary_connect``: a loopback listener serves the token.

    The listener runs as a separate child process bound to 127.0.0.1 on a random port; it
    never loads the oracle plugin, so its own sockets produce no events. The test gets the
    listener's URL and the token, and must make the application request the URL through a
    declared entry point. The listener's log is untrusted (see ``read_connect_log``): the
    proof needs a signed plugin event for the same request (see ``_judge_connect``).
    """
    key = secrets.token_bytes(KEY_BYTES)
    token = "CANARY-" + secrets.token_hex(16)
    secret = secrets.token_hex(16)
    port = pick_connect_port()
    url = canary_connect_url(port, secret)
    with tempfile.TemporaryDirectory(prefix="exhibit_a_oracle_") as tmp:
        work = Path(tmp).resolve()
        allowed = work / "allowed"
        allowed.mkdir()
        (allowed / "public.txt").write_text("public file\n", encoding="utf-8")
        exclude = []
        if test_path.parent.is_relative_to(app_root) and test_path.parent != app_root:
            exclude.append(test_path.parent.relative_to(app_root).as_posix())
        elif test_path.parent == app_root:
            exclude += [test_path.name, "conftest.py"]
        try:
            manifest = app_manifest(app_root, exclude)
        except ManifestError as exc:
            return Judgement(
                observed_effect=False, provenance_ok=False, test_outcome="error",
                reason=f"the application tree could not be hashed before the run: {exc}",
                reason_code=REASON_MANIFEST_FAILED,
            )
        events_path = work / "events.jsonl"
        log_path = work / "connect.jsonl"
        log_path.write_text("")
        ini = work / "pytest.ini"
        ini.write_text("[pytest]\n", encoding="utf-8")
        server = subprocess.Popen(
            [sys.executable, "-I", "-S", str(_SERVER_SOURCE),
             str(port), "/" + secret, token, str(log_path)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            cwd=work,
        )
        try:
            if not _wait_for_port(port, timeout=10.0):
                _stop(server)
                return Judgement(
                    observed_effect=False, provenance_ok=False, test_outcome="error",
                    reason="the canary listener did not start: the run cannot prove anything",
                    reason_code=REASON_MANIFEST_FAILED,
                )
            outcome = _run_test(
                app_root, test_path, work, ini, allowed, url, token, events_path, timeout,
                key=key, manifest=manifest, connect_url=url,
            )
            events, forged, forged_reason = _read_events(events_path, key)
            log = read_connect_log(log_path)
        finally:
            _stop(server)
    changes = tree_changes(app_root, manifest, exclude)
    return _judge(
        outcome, events, app_root, test_path, entry_points,
        effect="canary_connect", forged_events=forged, forged_reason=forged_reason,
        app_tree=AppTree(str(app_root), app_root, manifest), app_tree_changes=changes,
        allowed_dir=str(allowed), canary_url=url, connect_log=log,
    )


def _run_dos(app_root: Path, test_path: Path, entry_points: set[str], timeout: float) -> Judgement:
    """The host path of ``canary_dos``: no canary file, the plugin times the entry point.

    The test supplies two same-length inputs through the ``dos_probe`` fixture; the plugin
    calls the entry point with each, several times, and signs the CPU ratio. Nothing is
    planted on disk. Sandbox CPU and time limits are unchanged on the other path.
    """
    key = secrets.token_bytes(KEY_BYTES)
    token = "CANARY-" + secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix="exhibit_a_oracle_") as tmp:
        work = Path(tmp).resolve()
        allowed = work / "allowed"
        allowed.mkdir()
        (allowed / "public.txt").write_text("public file\n", encoding="utf-8")
        exclude = []
        if test_path.parent.is_relative_to(app_root) and test_path.parent != app_root:
            exclude.append(test_path.parent.relative_to(app_root).as_posix())
        elif test_path.parent == app_root:
            exclude += [test_path.name, "conftest.py"]
        try:
            manifest = app_manifest(app_root, exclude)
        except ManifestError as exc:
            return Judgement(
                observed_effect=False, provenance_ok=False, test_outcome="error",
                reason=f"the application tree could not be hashed before the run: {exc}",
                reason_code=REASON_MANIFEST_FAILED,
            )
        events_path = work / "events.jsonl"
        ini = work / "pytest.ini"
        ini.write_text("[pytest]\n", encoding="utf-8")
        outcome = _run_test(
            app_root, test_path, work, ini, allowed, "dos", token, events_path, timeout,
            key=key, manifest=manifest, dos=True,
        )
        events, forged, forged_reason = _read_events(events_path, key)
    changes = tree_changes(app_root, manifest, exclude)
    return _judge(
        outcome, events, app_root, test_path, entry_points,
        effect="canary_dos", forged_events=forged, forged_reason=forged_reason,
        app_tree=AppTree(str(app_root), app_root, manifest), app_tree_changes=changes,
        allowed_dir=str(allowed),
    )


def _wait_for_port(port: int, timeout: float) -> bool:
    """Whether 127.0.0.1:``port`` accepts a connection within ``timeout`` seconds."""
    import socket

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _stop(server: "subprocess.Popen[bytes]") -> None:
    try:
        server.terminate()
        server.wait(timeout=10.0)
    except (OSError, subprocess.TimeoutExpired):
        try:
            server.kill()
        except OSError:
            pass


def canary_written(canary: Path, token: str) -> bool:
    """Whether the run left a regular file at ``canary`` (absent before) holding ``token``.

    The write effect is planted nowhere, so the file can only come from the run. A symlink,
    a directory, an empty or token-less file, or one that cannot be read is not a write.
    """
    try:
        st = os.lstat(canary)
        if not stat.S_ISREG(st.st_mode):
            return False
        with open(canary, "rb") as handle:
            content = handle.read(_MAX_CANARY_READ)
    except OSError:
        return False
    return token.encode("utf-8") in content


def exec_canary_script(marker: PurePath | str, token: str) -> str:
    """The canary executable: it appends the run's token to the marker, with shell builtins only."""
    return f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(token)} >> {shlex.quote(str(marker))}\n"


def marker_holds_token(marker: Path, token: str) -> bool:
    """Whether the run left a regular, single-link marker holding only the token, line by line.

    Each run of the canary appends one line. The container can write this file, so it is untrusted:
    a link, a FIFO, an oversized file or any other content is not a proof, and neither is an error.
    """
    try:
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > _MAX_CANARY_READ:
            return False
        content = os.read(fd, _MAX_CANARY_READ)
    except OSError:
        return False
    finally:
        os.close(fd)
    lines = content.decode("utf-8", "replace").splitlines()
    return bool(lines) and all(line == token for line in lines)


def _file_is(path: Path, content: str) -> bool:
    """Whether ``path`` is a regular file with exactly this content (the canary was not replaced)."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode) and path.read_text(encoding="utf-8") == content
    except (OSError, UnicodeDecodeError):
        return False


def _run_test(
    app_root: Path,
    test_path: Path,
    work: Path,
    ini: Path,
    allowed: Path,
    canary: Path | str,
    token: str,
    events_path: Path,
    timeout: float,
    *,
    key: bytes | None,
    manifest: dict[str, str] | None = None,
    marker: Path | None = None,
    sql_table: str | None = None,
    connect_url: str | None = None,
    dos: bool = False,
) -> TestOutcome:
    """Run the test with the plugin; ``key`` goes to the plugin on stdin, never elsewhere.

    ``manifest`` (the staged app tree, see provenance.py) follows the key on stdin. With
    ``key=None`` stdin is ``/dev/null`` and the plugin runs unsigned (only useful to test that
    the judge refuses such events).
    """
    # A private per-run copy of the plugin (stdlib only), read-only, as the sandbox does: the test
    # cannot reach, or modify through the import path, the package source in the repository.
    plugin_dir = Path(work) / "plugin"
    plugin_dir.mkdir()
    plugin_copy = plugin_dir / f"{_PLUGIN_MODULE}.py"
    shutil.copyfile(_PLUGIN_SOURCE, plugin_copy)
    plugin_copy.chmod(0o400)
    plugin_dir.chmod(0o500)
    # Scrubbed environment: no inherited secrets, only what the run needs.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.pathsep.join([str(app_root), str(plugin_dir)]),
        "PYTHONDONTWRITEBYTECODE": "1",
        ENV_ALLOWED_DIR: str(allowed),
        ENV_CANARY: str(canary),
        ENV_CANARY_TOKEN: token,
        ENV_EVENTS: str(events_path),
    }
    if marker is not None:
        env[ENV_MARKER] = str(marker)
    if sql_table is not None:
        env[ENV_SQL] = sql_table  # ENV_CANARY above is the application's database file
    if connect_url is not None:
        env[ENV_CONNECT_URL] = connect_url  # the test contract; ENV_CANARY carries it too
    if dos:
        env[ENV_DOS] = "1"
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        _PLUGIN_MODULE,
        "-p",
        "no:cacheprovider",
        "-c",
        str(ini),
        f"--rootdir={work}",
        "-q",
        str(test_path),
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=app_root,
            env=env,
            input=(
                key_message(key, app_root=str(app_root), manifest=manifest)
                if key is not None and manifest is not None
                else key_message(key) if key is not None else None
            ),
            stdin=subprocess.DEVNULL if key is None else None,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "timeout"
    if proc.returncode == 0:
        return "passed"
    if proc.returncode == 1:
        return "failed"
    return "error"  # collection error, usage error, no tests collected, interrupted


def verify_events(lines, key: bytes) -> tuple[list[OracleEvent], int, str]:
    """Events from signed lines that verify under ``key``, the dropped count and why.

    A body that verifies but does not fit ``OracleEvent`` is dropped and counted too: only
    the plugin can sign, so it means the plugin and judge disagree, and it proves nothing.
    """
    bodies, rejected = verify_lines(lines, key)
    events = []
    for body in bodies:
        try:
            events.append(OracleEvent.model_validate(body))
        except ValueError:
            rejected.append("signed event of an unknown shape")
    return events, len(rejected), (rejected[0] if rejected else "")


def _read_events(path: Path, key: bytes) -> tuple[list[OracleEvent], int, str]:
    if not path.exists():
        return [], 0, ""
    return verify_events(path.read_text(encoding="utf-8", errors="replace").splitlines(), key)


def _under(file: str, root: Path) -> bool:
    try:
        Path(file).relative_to(root)
    except ValueError:
        return False
    return True


def _judge(
    outcome: TestOutcome,
    events: list[OracleEvent],
    app_root: Path,
    test_path: Path,
    entry_points: set[str],
    *,
    effect: Effect = "canary_read",
    forged_events: int = 0,
    forged_reason: str = "",
    app_tree: AppTree | None = None,
    app_tree_changes: list[str] | None = None,
    allowed_dir: str | None = None,
    canary_written: bool | None = None,
    canary_ran: bool | None = None,
    canary_url: str | None = None,
    connect_log: list[dict] | None = None,
) -> Judgement:
    """Decide what a run means.

    ``app_tree`` turns on authenticated provenance: a frame counts as application code only
    if the plugin admitted it against the staged manifest and ``app_tree.check`` agrees. Both
    product paths (``run_oracle`` and the sandbox runner) pass it; without it the check is the
    older lexical one, kept for direct callers of this function. ``app_tree_changes`` lists
    what changed in the app tree during the run; any change rules out a proof.

    ``allowed_dir`` (the allowed directory as the run saw it) turns on the route check: an
    event counts only if its ``requested`` path starts inside the allowed directory or is the
    canary's own path (see ``_route_problem``). ``canary_written`` is the post-run check of a
    write effect (``canary_written()``): False rules a write out. None means the caller did not
    check; the sandbox path cannot yet (the canary_write side of the sandbox is T076, which must
    pass it here), and a direct caller may judge events alone. ``canary_ran`` is the post-run
    check of an exec effect (``marker_holds_token``); there None is not a proof (``_judge_exec``).
    """
    changes = list(app_tree_changes or [])
    tampered = bool(forged_events or changes)
    # A run whose channel or app tree was tampered with did not run to a result the oracle can
    # trust. A *pass* then becomes "error" (invalid_test) so it can neither count as "the
    # suspicion did not materialise" nor satisfy the fixed-code re-run of the differential.
    judged_outcome: TestOutcome = "error" if tampered and outcome == "passed" else outcome
    if forged_events:
        # Someone other than the plugin wrote to the events file (or the plugin ran without
        # a key): the run is an attempt to cheat or cannot be verified, never a proof.
        kind = "unsigned (the plugin got no key)" if forged_reason == "unsigned event" else forged_reason
        return Judgement(
            observed_effect=bool(events),
            provenance_ok=False,
            reason=(
                f"{forged_events} forged or unverifiable oracle event line(s) dropped "
                f"(first: {kind}); the oracle channel was tampered with"
            ),
            test_outcome=judged_outcome,
            events=events,
            forged_events=forged_events,
            app_tree_changes=changes,
            reason_code=REASON_FORGED_EVENTS,
        )
    if changes:
        return Judgement(
            observed_effect=bool(events),
            provenance_ok=False,
            reason=(
                f"{REASON_APP_TREE_CHANGED}: {len(changes)} entr{'y' if len(changes) == 1 else 'ies'} "
                f"of the application tree changed during the run (first: {changes[0]}); "
                "the run cannot prove anything"
            ),
            test_outcome=judged_outcome,
            events=events,
            app_tree_changes=changes,
            reason_code=REASON_APP_TREE_CHANGED,
        )
    if effect == "canary_exec":
        return _judge_exec(outcome, events, app_root, test_path.parent, entry_points, app_tree, canary_ran)
    if effect == "canary_sql":
        return _judge_sql(outcome, events, app_root, test_path.parent, entry_points, app_tree)
    if effect == "canary_connect":
        return _judge_connect(
            outcome, events, app_root, test_path.parent, entry_points, app_tree,
            canary_url, connect_log,
        )
    if effect == "canary_dos":
        return _judge_dos(outcome, events, app_root, test_path.parent, entry_points, app_tree)
    # Only opens of the kind this effect looks for count. A write-effect run ignores a read of
    # the canary path, and a read-effect run ignores a write: the wrong access never proves the
    # intended vulnerability. The full event list is still returned for the record.
    verb = "written" if effect == "canary_write" else "read"
    accepted = _ACCEPTED_ACCESS[effect]
    relevant = [event for event in events if _access(event) in accepted]
    if relevant and canary_written is False:
        # Opened for writing, but nothing with the token is there after the run: a failed or
        # empty open (e.g. "r+" on the absent canary) is not the escape this effect proves.
        return Judgement(
            observed_effect=False, provenance_ok=False, test_outcome=outcome, events=events,
            reason=(
                "the canary was opened for writing but no file holding the run's token was "
                f"left there; test {outcome}: nothing was proven"
            ),
            reason_code=REASON_NO_EFFECT,
        )
    if not relevant:
        reasons = {
            "failed": f"test failed but the canary was never {verb}: it failed for the wrong reason",
            "passed": f"test passed and the canary was never {verb}: nothing was proven",
            "error": f"test did not run to a result and the canary was never {verb}",
            "timeout": f"test timed out and the canary was never {verb}",
        }
        return Judgement(
            observed_effect=False, provenance_ok=False, reason=reasons[outcome],
            test_outcome=outcome, events=events, reason_code=REASON_NO_EFFECT,
        )

    test_dir = test_path.parent
    problems = []
    for event in relevant:
        problem = _route_problem(event, allowed_dir) or _provenance_problem(
            event, app_root, test_dir, entry_points, app_tree
        )
        if problem is None:
            if outcome == "failed":
                reason = f"canary {verb} by application code reached through an entry point; test failed"
            else:
                reason = f"canary {verb} through an entry point, but the test did not fail ({outcome})"
            return Judgement(
                observed_effect=True, provenance_ok=True, reason=reason, test_outcome=outcome, events=events,
                reason_code="" if outcome == "failed" else REASON_NO_EFFECT,
            )
        problems.append(problem)
    code, message = problems[0]
    return Judgement(
        observed_effect=True,
        provenance_ok=False,
        reason=f"canary {verb} without valid provenance: " + message,
        test_outcome=outcome,
        events=events,
        reason_code=code,
    )


def _started_from(event: OracleEvent, app_root: Path, test_dir: Path) -> Literal["test", "app"] | None:
    """Whose code is innermost on the stack; library frames in between do not count."""
    for frame in reversed(event.stack):
        if _under(frame.file, test_dir):
            return "test"
        if _under(frame.file, app_root):
            return "app"
    return None


def _judge_exec(
    outcome: TestOutcome,
    events: list[OracleEvent],
    app_root: Path,
    test_dir: Path,
    entry_points: set[str],
    app_tree: AppTree | None,
    canary_ran: bool | None,
) -> Judgement:
    """Decide a canary_exec run (docs/oracle/oracle-provenance.md, section 3.9).

    Proven only if all hold: nothing in the process wrote the canary or the marker; the test
    started no process and did not prepare the ground for one (environment, working directory,
    code built at run time, native calls); every process has valid provenance; the watched APIs
    were intact when each started; one of them, from an admitted app frame that names a sink,
    names the canary; and the host found the token in the marker after the run. Anything
    that cannot be verified, including an unchecked marker, is not a proof.
    """
    ran = canary_ran is True

    def refuse(code: str, why: str) -> Judgement:
        return Judgement(
            observed_effect=ran, provenance_ok=False, reason=f"canary_exec not proven: {why}; test {outcome}",
            test_outcome=outcome, events=events, reason_code=code,
        )

    if app_tree is None:
        return refuse(REASON_PROVENANCE, "provenance cannot be authenticated without the staged app")
    processes = []
    for event in events:
        if event.op in ("open", "rename", "link"):
            if _access(event) != "read":
                return refuse(REASON_CANARY_TAMPERED, f"in-process {event.op} of the {event.target} ({_access(event)})")
            continue
        if _started_from(event, app_root, test_dir) == "test":
            return refuse(REASON_FROM_TEST, f"the test itself did {event.mode} ({(event.command or '')[:200]!r})")
        if event.op == "process":
            processes.append(event)
    for event in processes:
        problem = _provenance_problem(event, app_root, test_dir, entry_points, app_tree)
        if problem is not None:
            return refuse(problem[0], f"{event.mode} ({(event.command or '')[:200]!r}): {problem[1]}")
        if event.patched is not None:
            return refuse(REASON_PROCESS_API_CHANGED, f"{event.patched} changed before {event.mode}")
        if any(frame.file.endswith("/weakref.py") for frame in event.stack):
            # A finalizer runs on whatever stack drops the object, whoever registered it.
            return refuse(REASON_PROVENANCE, f"{event.mode} ran from a finalizer, not from the code on the stack")
    if not ran:
        if canary_ran is None:
            why = "the marker was not checked after the run"
        else:
            why = "the canary never left the token in the marker"
        return Judgement(
            observed_effect=False, provenance_ok=False, reason=f"canary_exec not proven: {why}; test {outcome}",
            test_outcome=outcome, events=events, reason_code=REASON_NO_EFFECT,
        )
    if not any(event.names_canary and event.sink_named for event in processes):
        return refuse(REASON_PROVENANCE, "no process from an application sink names the canary")
    if outcome == "failed":
        reason = "canary executed by a process application code started through an entry point; test failed"
    else:
        reason = f"canary executed through an entry point, but the test did not fail ({outcome})"
    return Judgement(
        observed_effect=True, provenance_ok=True, reason=reason, test_outcome=outcome, events=events,
        reason_code="" if outcome == "failed" else REASON_NO_EFFECT,
    )


def _judge_sql(
    outcome: TestOutcome,
    events: list[OracleEvent],
    app_root: Path,
    test_dir: Path,
    entry_points: set[str],
    app_tree: AppTree | None,
) -> Judgement:
    """Decide a canary_sql run (docs/oracle/oracle-provenance.md, section 3.10).

    Proven only if all hold: every connection of the run was opened by admitted application code;
    nothing but application code touched the database file; the canary table's token column was
    read at least once, and every read of that table ran on a connection to the application's own
    database (its main schema), came from admitted application code, reached through a declared
    entry point called from the test; and the test failed. A read from a test frame, a connection
    the test opened, a statement the test ran on the app's connection, a copy of the database read
    by the test: none proves, and neither does anything the oracle could not place. The oracle
    checks the read; that the token reached the test is what the failing assertion checks.
    """

    def refuse(code: str, why: str, observed: bool = False) -> Judgement:
        return Judgement(
            observed_effect=observed, provenance_ok=False, reason=f"canary_sql not proven: {why}; test {outcome}",
            test_outcome=outcome, events=events, reason_code=code,
        )

    if app_tree is None:
        return refuse(REASON_PROVENANCE, "provenance cannot be authenticated without the staged app")
    connections: dict[int, OracleEvent] = {}
    reads = []
    for event in events:
        if event.op == "sql_connect":
            who = _started_from(event, app_root, test_dir)
            if who != "app":
                return refuse(REASON_SQL_FROM_TEST, "a database connection was opened by "
                              + ("the test itself" if who == "test" else "code nobody vouches for"))
            if event.patched is not None:
                return refuse(REASON_SQL_API_CHANGED, f"{event.patched} was replaced before a connection opened")
            if event.connection is None or event.connection in connections:
                return refuse(REASON_PROVENANCE, "a connection could not be told apart from another")
            connections[event.connection] = event
        elif event.op in ("open", "rename", "link"):
            who = _started_from(event, app_root, test_dir)
            if who != "app":
                return refuse(REASON_SQL_FROM_TEST, f"the database file was touched by "
                              f"{'the test itself' if who == 'test' else 'code nobody vouches for'} ({event.mode})")
            if _access(event) != "read":
                return refuse(REASON_CANARY_TAMPERED, f"in-process {event.op} of the database file ({_access(event)})")
        elif event.op == "sql_read":
            reads.append(event)
    relevant = []
    for event in reads:
        who = _started_from(event, app_root, test_dir)
        if who != "app":
            return refuse(REASON_SQL_FROM_TEST, "the canary table was read by "
                          + ("a statement the test ran itself" if who == "test" else "code nobody vouches for"))
        opened = connections.get(event.connection) if event.connection is not None else None
        if opened is None or not opened.declared_db or not event.declared_db or event.database != "main":
            return refuse(REASON_SQL_UNPLACED, "the canary table was read on a connection, or in a database, "
                          "that is not the application's own database as opened by the application")
        problem = _provenance_problem(event, app_root, test_dir, entry_points, app_tree)
        if problem is not None:
            return refuse(problem[0], f"canary table read without valid provenance: {problem[1]}", observed=True)
        if event.column == SQL_CANARY_COLUMN:
            relevant.append(event)
    if not relevant:
        why = {
            "failed": "test failed but the canary row was never read: it failed for the wrong reason",
            "passed": "test passed and the canary row was never read: nothing was proven",
            "error": "test did not run to a result and the canary row was never read",
            "timeout": "test timed out and the canary row was never read",
        }[outcome]
        return Judgement(
            observed_effect=False, provenance_ok=False, reason=why, test_outcome=outcome, events=events,
            reason_code=REASON_NO_EFFECT,
        )
    if outcome == "failed":
        reason = "canary row read by application code through an entry point; test failed"
    else:
        reason = f"canary row read through an entry point, but the test did not fail ({outcome})"
    return Judgement(
        observed_effect=True, provenance_ok=True, reason=reason, test_outcome=outcome, events=events,
        reason_code="" if outcome == "failed" else REASON_NO_EFFECT,
    )


def _secret_hit(target: str, secret: str) -> bool:
    """Whether a requested ``target`` names this run's secret path.

    The exact secret path, or anything under it (an app that appends to the URL still
    proves it knew the secret). Anything else, including a longer string that merely
    starts the same way, does not match.
    """
    return target == secret or target.startswith(secret + "/")


def _connect_matches_canary(event: OracleEvent, port: int) -> bool:
    """Whether a ``connect`` event names this run's listener: a loopback host and its port."""
    if event.op != "connect" or event.port != port or not event.host:
        return False
    return event.host.lower() in _LOOPBACK_HOSTS


def _request_matches_canary(event: OracleEvent, port: int, secret: str) -> bool:
    """Whether a ``request`` event names this run's secret path on the listener.

    ``urllib.Request`` carries the full URL (host, port and path must all match);
    ``http.client.send`` carries only the request target (the path must match, and the
    matching connection is checked separately). Anything else names nothing.
    """
    if event.op != "request" or not event.url:
        return False
    if event.url.startswith("/"):
        return _secret_hit(event.url, secret)
    try:
        parts = urlsplit(event.url)
    except ValueError:
        return False
    return (
        parts.scheme == "http"
        and (parts.hostname or "").lower() in _LOOPBACK_HOSTS
        and parts.port == port
        and _secret_hit(parts.path, secret)
    )


def _judge_connect(
    outcome: TestOutcome,
    events: list[OracleEvent],
    app_root: Path,
    test_dir: Path,
    entry_points: set[str],
    app_tree: AppTree | None,
    canary_url: str | None,
    connect_log: list[dict] | None,
) -> Judgement:
    """Decide a canary_connect run (docs/oracle/oracle-provenance.md, section 3.11).

    Proven only if all hold: nothing connected or requested from test frames (one such
    event refuses the whole run, even beside a genuine one); the listener's log shows a
    request for this run's secret path; a signed plugin event shows the application
    itself requested that path (``urllib``/``http.client``) with valid provenance; a
    signed plugin event shows the application itself connected to the listener with valid
    provenance; and the test failed. The log is untrusted: without the signed plugin
    events, forged or truthful, it proves nothing.
    """

    def refuse(code: str, why: str, observed: bool = False) -> Judgement:
        return Judgement(
            observed_effect=observed, provenance_ok=False, reason=f"canary_connect not proven: {why}; test {outcome}",
            test_outcome=outcome, events=events, reason_code=code,
        )

    if app_tree is None:
        return refuse(REASON_PROVENANCE, "provenance cannot be authenticated without the staged app")
    parsed = parse_canary_url(canary_url)
    if parsed is None:
        return refuse(REASON_NO_EFFECT, "the run's canary URL was not recorded, so nothing matches it")
    _, port, secret = parsed
    for event in events:
        if event.op not in ("connect", "request"):
            continue
        who = _started_from(event, app_root, test_dir)
        if who != "app":
            return refuse(REASON_CONNECT_FROM_TEST, "an outbound connection was opened or requested by "
                          + ("the test itself" if who == "test" else "code nobody vouches for"))
    log = connect_log or []
    log_hit = any(
        isinstance(record, dict) and isinstance(record.get("target"), str)
        and _secret_hit(record["target"], secret)
        for record in log
    )
    url_hit = connect_hit = False
    for event in events:
        if event.op == "request" and _request_matches_canary(event, port, secret):
            problem = _provenance_problem(event, app_root, test_dir, entry_points, app_tree)
            if problem is not None:
                return refuse(problem[0], f"canary URL requested without valid provenance: {problem[1]}",
                               observed=True)
            url_hit = True
        elif event.op == "connect" and _connect_matches_canary(event, port):
            problem = _provenance_problem(event, app_root, test_dir, entry_points, app_tree)
            if problem is not None:
                return refuse(problem[0], f"canary connection without valid provenance: {problem[1]}",
                               observed=True)
            connect_hit = True
    if not log_hit:
        why = {
            "failed": "test failed but the canary listener recorded no request for its secret path",
            "passed": "test passed and the canary listener recorded no request: nothing was proven",
            "error": "test did not run to a result and the canary listener recorded no request",
            "timeout": "test timed out and the canary listener recorded no request",
        }[outcome]
        return Judgement(
            observed_effect=False, provenance_ok=False, reason=why, test_outcome=outcome, events=events,
            reason_code=REASON_NO_EFFECT,
        )
    if not (url_hit and connect_hit):
        missing = "the request" if connect_hit else "the connection" if url_hit else "a request and a connection"
        why = {
            "failed": f"test failed but {missing} to the canary from application code was not observed",
            "passed": f"test passed and {missing} to the canary from application code was not observed",
            "error": f"test did not run to a result and {missing} to the canary from application code was not observed",
            "timeout": f"test timed out and {missing} to the canary from application code was not observed",
        }[outcome]
        # The listener saw the request, so the effect was observed; the matching signed
        # plugin event from application code is what is missing.
        return Judgement(
            observed_effect=True, provenance_ok=False, reason=why + " with valid provenance",
            test_outcome=outcome, events=events, reason_code=REASON_PROVENANCE,
        )
    if outcome == "failed":
        reason = "canary URL requested by application code reached through an entry point; test failed"
    else:
        reason = f"canary URL requested through an entry point, but the test did not fail ({outcome})"
    return Judgement(
        observed_effect=True, provenance_ok=True, reason=reason, test_outcome=outcome, events=events,
        reason_code="" if outcome == "failed" else REASON_NO_EFFECT,
    )


def _finite(value: float | None) -> bool:
    """Whether ``value`` is a usable finite measurement (NaN/inf never prove)."""
    return isinstance(value, (int, float)) and value == value and abs(value) != float("inf")


def _judge_dos(
    outcome: TestOutcome,
    events: list[OracleEvent],
    app_root: Path,
    test_dir: Path,
    entry_points: set[str],
    app_tree: AppTree | None,
) -> Judgement:
    """Decide a canary_dos run (docs/oracle/oracle-provenance.md, section 3.12).

    Proven only if all hold: authenticated provenance is on; nothing timed from test
    frames (the probe itself is the plugin); ``sys.setprofile`` was intact; one signed
    ``dos`` event shows a median malicious/benign application-CPU ratio above the
    documented threshold, malicious application CPU above the absolute floor, and that
    CPU spent in admitted app frames reached through a declared entry point called from
    the test; the samples were not noisy; and the test failed. A noisy machine is
    ``flaky``, never a proof.
    """

    def refuse(code: str, why: str, observed: bool = False) -> Judgement:
        return Judgement(
            observed_effect=observed, provenance_ok=False, reason=f"canary_dos not proven: {why}; test {outcome}",
            test_outcome=outcome, events=events, reason_code=code,
        )

    if app_tree is None:
        return refuse(REASON_PROVENANCE, "provenance cannot be authenticated without the staged app")
    probes = [event for event in events if event.op == "dos"]
    if not probes:
        why = {
            "failed": "test failed but the runner never timed the entry point: it failed for the wrong reason",
            "passed": "test passed and the runner never timed the entry point: nothing was proven",
            "error": "test did not run to a result and the runner never timed the entry point",
            "timeout": "test timed out and the runner never timed the entry point",
        }[outcome]
        return Judgement(
            observed_effect=False, provenance_ok=False, reason=why, test_outcome=outcome, events=events,
            reason_code=REASON_NO_EFFECT,
        )
    for event in probes:
        who = _started_from(event, app_root, test_dir)
        if who == "test":
            return refuse(REASON_DOS_FROM_TEST, "CPU was sampled from a test frame, not the application")
        if event.patched is not None:
            return refuse(REASON_DOS_API_CHANGED, f"{event.patched} changed while the entry point was timed")
        problem = _provenance_problem(event, app_root, test_dir, entry_points, app_tree)
        if problem is not None:
            return refuse(problem[0], f"entry point timed without valid provenance: {problem[1]}", observed=True)
        if event.noisy or not all(
            _finite(v) for v in (event.ratio, event.malicious_cpu, event.benign_cpu, event.app_fraction)
        ):
            return refuse(
                REASON_FLAKY,
                "the CPU samples were too noisy or not finite to prove algorithmic complexity",
            )
        ratio = float(event.ratio)
        malicious_cpu = float(event.malicious_cpu)
        fraction = float(event.app_fraction)
        if fraction < DOS_MIN_APP_FRACTION:
            return refuse(
                REASON_DOS_FROM_TEST,
                f"only {fraction:.0%} of malicious CPU was in application frames (busy loop, sleep, hashing)",
            )
        if ratio <= DOS_RATIO or malicious_cpu < DOS_FLOOR:
            return Judgement(
                observed_effect=False, provenance_ok=False,
                reason=(
                    f"canary_dos not proven: median ratio {ratio:.1f}x "
                    f"(need >{DOS_RATIO:.0f}x) and malicious app CPU {malicious_cpu:.4f}s "
                    f"(need >={DOS_FLOOR:.3f}s); test {outcome}"
                ),
                test_outcome=outcome, events=events, reason_code=REASON_NO_EFFECT,
            )
    if outcome == "failed":
        reason = (
            f"application CPU on the malicious input was {probes[0].ratio:.1f}x the benign "
            "input of the same length, spent in application frames through an entry point; test failed"
        )
    else:
        reason = f"algorithmic complexity observed through an entry point, but the test did not fail ({outcome})"
    return Judgement(
        observed_effect=True, provenance_ok=True, reason=reason, test_outcome=outcome, events=events,
        reason_code="" if outcome == "failed" else REASON_NO_EFFECT,
    )


def _route_problem(event: OracleEvent, allowed_dir: str | None) -> tuple[str, str] | None:
    """``(reason code, why)`` the canary was not reached from the allowed directory, or None.

    A traversal starts inside the allowed directory and escapes, so its requested path starts
    with it, lexically (``<allowed>/../outside/canary.txt``). An app that canonicalises before
    it opens (Starlette's ``realpath``), or an absolute archive member, requests the canary's
    own path; that is accepted too. Anything else, such as a test that roots the app in the
    canary's directory under another spelling, or an unrecorded path, fails closed. An app
    rooted *exactly* at the canary's directory also requests the canary's own path: only the
    static guard sees that, and an obfuscated one is residual limit R6.
    """
    if allowed_dir is None:
        return None
    requested = event.requested
    if requested is None:
        return REASON_NOT_VIA_ALLOWED_DIR, (
            "the requested path was not recorded (older plugin, or a dir_fd of unknown origin)"
        )
    allowed = allowed_dir.rstrip("/") or "/"
    if requested.startswith(allowed + "/") or requested == event.path:
        return None
    return REASON_NOT_VIA_ALLOWED_DIR, (
        f"the canary was requested as {requested[:200]!r}, which neither starts in the allowed "
        "directory nor names the canary itself: the test chose where the app is rooted"
    )


def _provenance_problem(
    event: OracleEvent,
    app_root: Path,
    test_dir: Path,
    entry_points: set[str],
    app_tree: AppTree | None = None,
) -> tuple[str, str] | None:
    """``(reason code, why)`` this read is not an exploit through the app, or None if it is."""
    if event.via_symlink:
        # The test can plant a link inside the app's directory; a lexically safe app that
        # follows it shows nothing about the app. Links older than the run are not flagged.
        return REASON_PROVENANCE, f"canary reached through a symlink created during the run ({event.symlink})"
    # Test code wins over app code: the tests directory may live inside the app root.
    test_idx = [i for i, f in enumerate(event.stack) if _under(f.file, test_dir)]
    lexical = [
        i
        for i, f in enumerate(event.stack)
        if _under(f.file, app_root) and not _under(f.file, test_dir)
    ]
    rejected: list[tuple[int, str]] = []
    if app_tree is None:
        app_idx = lexical
    else:
        # Authenticated provenance: a frame under the app root that fails admission is never
        # application code, whatever its file name says.
        app_idx = []
        for i in lexical:
            why = app_tree.check(event.stack[i])
            if why is None:
                app_idx.append(i)
            else:
                rejected.append((i, why))
    if not app_idx:
        if rejected:
            i, why = rejected[0]
            frame = event.stack[i]
            return REASON_FRAME_NOT_ADMITTED, (
                f"no admitted application code on the stack: '{frame.qualname}' in {frame.file} "
                f"was rejected ({why})"
            )
        return REASON_PROVENANCE, "no application code on the stack (the test read the file itself)"
    outermost = app_idx[0]
    entry = event.stack[outermost]
    if entry.qualname not in entry_points and entry.function not in entry_points:
        return REASON_PROVENANCE, (
            f"the test reached application code at '{entry.qualname}', which is not a declared "
            "entry point (it called the sink directly)"
        )
    if not any(i < outermost for i in test_idx):
        return REASON_PROVENANCE, "the entry point was not called from the test"
    return None
