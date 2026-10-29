"""Run an exploit test against a target app and judge whether its failure is real.

The oracle plants a canary file outside the app's allowed directory, runs the exploit test
in a subprocess with the observer plugin loaded, and checks two things:

* effect: the canary was opened while the test ran;
* provenance: the open came from application code reached through a declared entry point,
  called from the test, and not from the test touching the sink or the file itself.

The subprocess is a plain child process. The sandbox (a separate component) is what makes
untrusted tests safe to run; the oracle only decides what the run means.

Events are trusted only if they carry a valid signature under a key generated here for this
run and handed to the plugin on stdin (finding A-1, see docs/oracle-a1.md). Lines that do not
verify are dropped and counted; any such line rules out a proof. Before running, the test
source is checked by a static tripwire (``guard.py``) for references to the oracle channel
and for writes into, or forging from, the application tree.

Provenance is authenticated against the app as staged (docs/oracle-provenance.md): the app
tree is hashed before the run and the manifest goes to the plugin on stdin with the key; only
frames the plugin admitted against it, and that pass the host-side re-check, are application
code. The tree is hashed again after the run; any change rules out a proof.
"""

from __future__ import annotations

import os
import secrets
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

# Machine-readable reasons a judgement is not a proof (Judgement.reason_code).
REASON_CHANNEL_TRIPWIRE = "channel_tripwire"
REASON_FORGED_EVENTS = "forged_events"
REASON_APP_TREE_CHANGED = "app_tree_changed"
REASON_FRAME_NOT_ADMITTED = "frame_not_admitted"
REASON_NO_EFFECT = "no_effect"
REASON_PROVENANCE = "provenance"
REASON_MANIFEST_FAILED = "manifest_failed"


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
    """One observed open of the canary file."""

    type: Literal["canary_read"] = "canary_read"
    path: str
    mode: str
    stack: list[Frame]
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
) -> Judgement:
    """Run ``test_path`` against the app in ``app_root`` and judge the result.

    ``entry_points`` are the function names (plain or qualified) through which a real
    request enters the application, e.g. ``{"App.handle_request"}``. The test finds the
    allowed directory and the canary through the ``EXHIBIT_A_*`` environment variables.
    """
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
        canary.write_text(token + "\n", encoding="utf-8")
        events_path = work / "events.jsonl"
        ini = work / "pytest.ini"
        ini.write_text("[pytest]\n", encoding="utf-8")

        outcome = _run_test(
            app_root, test_path, work, ini, allowed, canary, token, events_path, timeout, key=key,
            manifest=manifest,
        )
        events, forged, forged_reason = _read_events(events_path, key)
    changes = tree_changes(app_root, manifest, exclude)

    # On this path the app root is also the source of truth for the host-side re-check; any
    # change to it is reported above and rules out a proof, so its content is the staged one.
    return _judge(
        outcome, events, app_root, test_path, set(entry_points),
        forged_events=forged, forged_reason=forged_reason,
        app_tree=AppTree(str(app_root), app_root, manifest), app_tree_changes=changes,
    )


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
    package_src = str(Path(__file__).resolve().parents[2])
    # Scrubbed environment: no inherited secrets, only what the run needs.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.pathsep.join([str(app_root), package_src]),
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
        "exhibit_a.oracle.plugin",
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
    forged_events: int = 0,
    forged_reason: str = "",
    app_tree: AppTree | None = None,
    app_tree_changes: list[str] | None = None,
) -> Judgement:
    """Decide what a run means.

    ``app_tree`` turns on authenticated provenance: a frame counts as application code only
    if the plugin admitted it against the staged manifest and ``app_tree.check`` agrees. Both
    product paths (``run_oracle`` and the sandbox runner) pass it; without it the check is the
    older lexical one, kept for direct callers of this function. ``app_tree_changes`` lists
    what changed in the app tree during the run; any change rules out a proof.
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
    if not events:
        reasons = {
            "failed": "test failed but the canary was never read: it failed for the wrong reason",
            "passed": "test passed and the canary was never read: nothing was proven",
            "error": "test did not run to a result and the canary was never read",
            "timeout": "test timed out and the canary was never read",
        }
        return Judgement(
            observed_effect=False, provenance_ok=False, reason=reasons[outcome], test_outcome=outcome,
            reason_code=REASON_NO_EFFECT,
        )

    test_dir = test_path.parent
    problems = []
    for event in events:
        problem = _provenance_problem(event, app_root, test_dir, entry_points, app_tree)
        if problem is None:
            if outcome == "failed":
                reason = "canary read by application code reached through an entry point; test failed"
            else:
                reason = f"canary read through an entry point, but the test did not fail ({outcome})"
            return Judgement(
                observed_effect=True, provenance_ok=True, reason=reason, test_outcome=outcome, events=events,
                reason_code="" if outcome == "failed" else REASON_NO_EFFECT,
            )
        problems.append(problem)
    code, message = problems[0]
    return Judgement(
        observed_effect=True,
        provenance_ok=False,
        reason="canary read without valid provenance: " + message,
        test_outcome=outcome,
        events=events,
        reason_code=code,
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
