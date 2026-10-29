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
source is checked by a static tripwire (``guard.py``) for references to the oracle channel.
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
from exhibit_a.schemas.base import StrictModel

ENV_ALLOWED_DIR = "EXHIBIT_A_ALLOWED_DIR"
ENV_CANARY_TOKEN = "EXHIBIT_A_CANARY_TOKEN"

TestOutcome = Literal["passed", "failed", "error", "timeout"]


class Frame(StrictModel):
    file: str
    function: str
    qualname: str


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
        return Judgement(observed_effect=False, provenance_ok=False, reason=problem, test_outcome="error")

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
            app_root, test_path, work, ini, allowed, canary, token, events_path, timeout, key=key
        )
        events, forged, forged_reason = _read_events(events_path, key)

    return _judge(
        outcome, events, app_root, test_path, set(entry_points),
        forged_events=forged, forged_reason=forged_reason,
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
) -> TestOutcome:
    """Run the test with the plugin; ``key`` goes to the plugin on stdin, never elsewhere.

    With ``key=None`` stdin is ``/dev/null`` and the plugin runs unsigned (only useful to
    test that the judge refuses such events).
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
            input=key_message(key) if key is not None else None,
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
) -> Judgement:
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
            test_outcome=outcome,
            events=events,
            forged_events=forged_events,
        )
    if not events:
        reasons = {
            "failed": "test failed but the canary was never read: it failed for the wrong reason",
            "passed": "test passed and the canary was never read: nothing was proven",
            "error": "test did not run to a result and the canary was never read",
            "timeout": "test timed out and the canary was never read",
        }
        return Judgement(
            observed_effect=False, provenance_ok=False, reason=reasons[outcome], test_outcome=outcome
        )

    test_dir = test_path.parent
    problems = []
    for event in events:
        problem = _provenance_problem(event, app_root, test_dir, entry_points)
        if problem is None:
            if outcome == "failed":
                reason = "canary read by application code reached through an entry point; test failed"
            else:
                reason = f"canary read through an entry point, but the test did not fail ({outcome})"
            return Judgement(
                observed_effect=True, provenance_ok=True, reason=reason, test_outcome=outcome, events=events
            )
        problems.append(problem)
    return Judgement(
        observed_effect=True,
        provenance_ok=False,
        reason="canary read without valid provenance: " + problems[0],
        test_outcome=outcome,
        events=events,
    )


def _provenance_problem(
    event: OracleEvent, app_root: Path, test_dir: Path, entry_points: set[str]
) -> str | None:
    """Why this read does not count as an exploit through the app, or None if it does."""
    if event.via_symlink:
        # The test can plant a link inside the app's directory; a lexically safe app that
        # follows it shows nothing about the app. Links older than the run are not flagged.
        return f"canary reached through a symlink created during the run ({event.symlink})"
    # Test code wins over app code: the tests directory may live inside the app root.
    test_idx = [i for i, f in enumerate(event.stack) if _under(f.file, test_dir)]
    app_idx = [
        i
        for i, f in enumerate(event.stack)
        if _under(f.file, app_root) and not _under(f.file, test_dir)
    ]
    if not app_idx:
        return "no application code on the stack (the test read the file itself)"
    outermost = app_idx[0]
    entry = event.stack[outermost]
    if entry.qualname not in entry_points and entry.function not in entry_points:
        return (
            f"the test reached application code at '{entry.qualname}', which is not a declared "
            "entry point (it called the sink directly)"
        )
    if not any(i < outermost for i in test_idx):
        return "the entry point was not called from the test"
    return None
