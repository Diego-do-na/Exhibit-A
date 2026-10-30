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
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Collection
from pathlib import Path
from typing import Literal

from exhibit_a.oracle.guard import channel_problem
from exhibit_a.oracle.plugin import ENV_CANARY, ENV_EVENTS, KEY_BYTES, key_message, verify_lines
from exhibit_a.oracle.provenance import AppTree, ManifestError, app_manifest, tree_changes
from exhibit_a.schemas.base import StrictModel

ENV_ALLOWED_DIR = "EXHIBIT_A_ALLOWED_DIR"
ENV_CANARY_TOKEN = "EXHIBIT_A_CANARY_TOKEN"

TestOutcome = Literal["passed", "failed", "error", "timeout"]

# Which effect on the canary counts as proof for this run. "canary_read" is the original
# path-traversal style effect (the app leaks a file outside the allowed directory);
# "canary_write" is the archive-extraction / zip-slip style effect (the app creates a file
# outside the allowed directory). Both are observed through the same signed events; only the
# access the event carries differs. See docs/oracle/second-class.md.
Effect = Literal["canary_read", "canary_write"]
# Which accesses count for each effect: "r+" or O_RDWR is both a read and a write.
_ACCEPTED_ACCESS = {"canary_read": {"read", "read_write"}, "canary_write": {"write", "read_write"}}
# A write effect reads at most this much of the canary after the run to find the token.
_MAX_CANARY_READ = 1 << 20
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
    op: Literal["open", "rename", "link"] = "open"
    flags: int | None = None
    access: Literal["read", "write", "read_write", "unknown"] | None = None
    # The path as the code asked for it, absolute but not resolved; None if unknown.
    requested: str | None = None
    # Set when the opened path went through a symlink created during the run; such a read
    # has no provenance. Missing in events from older plugins, which means False.
    via_symlink: bool = False
    symlink: str | None = None
    symlink_target: str | None = None


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
) -> Judgement:
    """Run ``test_path`` against the app in ``app_root`` and judge the result.

    ``entry_points`` are the function names (plain or qualified) through which a real
    request enters the application, e.g. ``{"App.handle_request"}``. The test finds the
    allowed directory and the canary through the ``EXHIBIT_A_*`` environment variables.

    ``effect`` selects what counts as proof: ``"canary_read"`` (the app reads a file outside
    the allowed directory) or ``"canary_write"`` (the app creates a file outside it, as in an
    archive-extraction / zip-slip escape). For a write effect the canary file is not planted:
    the proof is that the app itself opens the canary path for writing, so it must not exist
    beforehand.
    """
    if effect not in ("canary_read", "canary_write"):
        raise ValueError(f"unknown effect {effect!r}")
    app_root = Path(app_root).resolve()
    test_path = Path(test_path).resolve()

    problem = channel_problem(test_path)
    if problem is not None:
        # Not run at all: an "error" outcome, which the loop classifies as invalid_test.
        return Judgement(
            observed_effect=False, provenance_ok=False, reason=problem, test_outcome="error",
            reason_code=REASON_CHANNEL_TRIPWIRE,
        )

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
        canary = outside / "canary.txt"
        if effect == "canary_read":
            # Read effect: the canary must exist for the app to leak it.
            canary.write_text(token + "\n", encoding="utf-8")
        # Write effect: leave the canary absent; the app proves the escape by creating it.
        events_path = work / "events.jsonl"
        ini = work / "pytest.ini"
        ini.write_text("[pytest]\n", encoding="utf-8")

        outcome = _run_test(
            app_root, test_path, work, ini, allowed, canary, token, events_path, timeout, key=key,
            manifest=manifest,
        )
        events, forged, forged_reason = _read_events(events_path, key)
        written = canary_written(canary, token) if effect == "canary_write" else None
    changes = tree_changes(app_root, manifest, exclude)

    # On this path the app root is also the source of truth for the host-side re-check; any
    # change to it is reported above and rules out a proof, so its content is the staged one.
    return _judge(
        outcome, events, app_root, test_path, set(entry_points),
        effect=effect, forged_events=forged, forged_reason=forged_reason,
        app_tree=AppTree(str(app_root), app_root, manifest), app_tree_changes=changes,
        allowed_dir=str(allowed), canary_written=written,
    )


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


def _run_test(
    app_root: Path,
    test_path: Path,
    work: Path,
    ini: Path,
    allowed: Path,
    canary: Path,
    token: str,
    events_path: Path,
    timeout: float,
    *,
    key: bytes | None,
    manifest: dict[str, str] | None = None,
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
    pass it here), and a direct caller may judge events alone.
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
