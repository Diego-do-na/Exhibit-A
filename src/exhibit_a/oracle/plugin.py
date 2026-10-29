"""Pytest plugin that observes reads of the canary file.

It runs inside the process that executes the exploit test. An audit hook watches every
``open``; when the canary is opened, the call stack is written to an events file so the
oracle can later check where the read came from. Configuration comes from environment
variables set by the oracle runner.

The recorded stack is the *logical* stack: when the canary is opened in a worker thread,
the frames of whoever handed the work to that thread are stitched in above the worker's
own frames, separated by a boundary pseudo-frame. Work is handed off in three ways, and
each is captured when it happens:

* ``threading.Thread.start``: the creating thread's stack, for the thread's whole life;
* ``ThreadPoolExecutor.submit``: the submitter's stack, for that one task (pool workers are
  reused, so the stack at thread creation would be stale);
* ``contextvars.copy_context``: the copier's stack, carried in the copied context. Libraries
  that run a task in a worker under a copied context (anyio, ``asyncio.to_thread``) are
  covered per task this way. A stack captured on the same thread is ignored, so code that
  runs where it was scheduled is judged by its real stack alone.

The same holds for asyncio tasks on one thread. A coroutine awaited directly is on the real
stack below its awaiter, but a coroutine run as a task of its own (``create_task``,
``gather``, ``wait_for``, ``TaskGroup``) is driven by the event loop, so its real stack starts
at the loop. ``BaseEventLoop.create_task`` is patched to capture the creator's stack; when a
task's own frames run, the loop frames below them are replaced by that stack, separated by a
task boundary pseudo-frame. The loop frames are dropped, not kept: whoever happens to drive
the loop did not ask for the task, so they must not vouch for it.

An open that reaches the canary through a symlink created during the run is flagged
``via_symlink``: a test can plant such a link inside the app's own directory and make a
lexically safe app follow it, which proves nothing about the app (see ``_fresh_symlink``).

Events are signed (finding A-1). The orchestrator generates a per-run key and writes it to
this process's stdin; the plugin reads it once, at import, before pytest collects anything
or redirects stdin. Each event is written as ``{"body": ..., "seq": n, "sig": hex}`` where
``sig`` is HMAC-SHA256 over ``seq`` and the canonical JSON of ``body`` (see ``_signed_bytes``)
and ``seq`` counts up from 0. A test that appends to the events file cannot produce a valid
signature without the key; one that replays a genuine line repeats its ``seq``. If no key
arrives the plugin runs *unsigned* (``sig`` is empty) and the judge trusts none of its events.
After install the events path is removed from ``os.environ`` and the file is written through
a descriptor opened at install time. None of this is a boundary against a test that inspects
this process's memory: the key lives in this process. See docs/oracle-a1.md.

The module stays self-contained (stdlib only): the sandbox mounts it as a single file.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import json
import os
import stat
import sys
import threading
import time
import weakref
from concurrent.futures import ThreadPoolExecutor

ENV_CANARY = "EXHIBIT_A_CANARY"
ENV_EVENTS = "EXHIBIT_A_EVENTS"

# What the orchestrator writes to stdin: the magic, the key in hex, a newline. Nothing else.
KEY_MAGIC = b"EXHIBIT-A-KEY "
KEY_BYTES = 32
_MAX_STDIN = 4096

_MAX_FRAMES = 200
_BOUNDARY = {"file": "<thread>", "function": "<thread boundary>", "qualname": "<thread boundary>"}
_TASK_BOUNDARY = {"file": "<task>", "function": "<task boundary>", "qualname": "<task boundary>"}
_TASK_EDGE = "task"
# A symlink counts as created during the run if its ctime or mtime is no older than the
# install time minus this many seconds. The margin covers coarse filesystem timestamps and
# small clock skew (e.g. a bind mount timestamped by the host clock); it errs towards
# flagging, which can only turn a proof into a non-proof, never the other way round.
_SYMLINK_SLACK = 2.0
_MAX_SYMLINK_HOPS = 40
_MAX_FIELD = 512

# A captured stack is a tuple of code objects, outermost first; None marks a thread boundary
# and _TASK_EDGE a task boundary.
# Code objects are cheap to collect and are only turned into paths when the canary is read.
_ORIGIN: contextvars.ContextVar[tuple[int, tuple] | None] = contextvars.ContextVar(
    "exhibit_a_origin", default=None
)
_local = threading.local()
_THREAD_ORIGIN = "_exhibit_a_origin"
# Creator stacks keyed by the task's coroutine, registered before the task can run (eager
# tasks run their first step inside create_task).
_TASK_ORIGINS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_installed = False


def _origin() -> tuple:
    """The logical stack that handed work to the current thread, or ``()`` if none."""
    held = _ORIGIN.get()
    if held is not None and held[0] != threading.get_ident():
        return held[1]
    task = getattr(_local, "origin", None)
    if task is not None:
        return task
    return getattr(threading.current_thread(), _THREAD_ORIGIN, ())


def _task_origin() -> tuple[object, tuple] | None:
    """The running task's coroutine frame and creator stack, if one was captured."""
    try:
        task = asyncio.current_task()
    except RuntimeError:
        return None  # no event loop running on this thread
    if task is None:
        return None
    coro = task.get_coro()
    try:
        origin = _TASK_ORIGINS.get(coro)
    except TypeError:
        return None  # not weak-referenceable, so never registered
    frame = getattr(coro, "cr_frame", None)
    if origin is None or frame is None:
        return None
    return frame, origin


def _capture(frame) -> tuple:
    """The logical stack at ``frame``: inherited origin, boundary, then real frames."""
    task = _task_origin()
    codes = []
    while frame is not None and len(codes) < _MAX_FRAMES:
        codes.append(frame.f_code)
        if task is not None and frame is task[0]:
            break  # the task's outermost frame: below it is only the loop
        frame = frame.f_back
    codes.reverse()
    if task is not None and frame is task[0]:
        stack = (*task[1], _TASK_EDGE, *codes)
    else:
        origin = _origin()
        stack = (*origin, None, *codes) if origin else tuple(codes)
    return stack[-_MAX_FRAMES:]


def _frame_dict(code) -> dict[str, str]:
    if code is None:
        return dict(_BOUNDARY)
    if code is _TASK_EDGE:
        return dict(_TASK_BOUNDARY)
    # Pseudo files such as "<frozen runpy>" must not be resolved against the cwd.
    name = code.co_filename
    return {
        "file": name if name.startswith("<") else os.path.realpath(name),
        "function": code.co_name,
        "qualname": code.co_qualname,
    }


def _stack(frame) -> list[dict[str, str]]:
    """Logical frames from the outermost caller to the innermost, as plain dicts."""
    return [_frame_dict(code) for code in _capture(frame)]


def _patch_handoffs() -> None:
    thread_start = threading.Thread.start
    pool_submit = ThreadPoolExecutor.submit
    copy_context = contextvars.copy_context
    loop_create_task = asyncio.BaseEventLoop.create_task

    def start(self, *args, **kwargs):
        setattr(self, _THREAD_ORIGIN, _capture(sys._getframe(1)))
        return thread_start(self, *args, **kwargs)

    def submit(self, fn, /, *args, **kwargs):
        origin = _capture(sys._getframe(1))

        def run_with_origin(*a, **kw):
            previous = getattr(_local, "origin", None)
            _local.origin = origin
            try:
                return fn(*a, **kw)
            finally:
                _local.origin = previous

        return pool_submit(self, run_with_origin, *args, **kwargs)

    def copy_context_with_origin():
        context = copy_context()
        context.run(_ORIGIN.set, (threading.get_ident(), _capture(sys._getframe(1))))
        return context

    def create_task(self, coro, *args, **kwargs):
        try:
            _TASK_ORIGINS[coro] = _capture(sys._getframe(1))
        except TypeError:
            pass  # not weak-referenceable: the task keeps its real stack
        return loop_create_task(self, coro, *args, **kwargs)

    threading.Thread.start = start
    ThreadPoolExecutor.submit = submit
    contextvars.copy_context = copy_context_with_origin
    asyncio.BaseEventLoop.create_task = create_task


def _fresh_symlink(path: str, since: float) -> tuple[str, str] | None:
    """The first symlink created at or after ``since`` that opening ``path`` goes through.

    ``path`` is absolute and not normalised. It is resolved the way the kernel does: one
    component at a time, following every symlink met (including links inside other links'
    targets) and applying ``..`` to the physical directory reached so far. A link counts as
    created during the run if ``max(st_ctime, st_mtime) >= since``; ctime cannot be set
    back from user space, so backdating a link's mtime does not hide it. Symlinks older than
    ``since``, such as ones committed in the repository and checked out before the run, are
    followed but not reported. Returns ``(link, target)`` or ``None``.
    """
    parts = path.split("/")
    parts.reverse()  # a stack: the next component to resolve is last
    resolved = "/"
    hops = 0
    while parts:
        name = parts.pop()
        if name in ("", "."):
            continue
        if name == "..":
            resolved = os.path.dirname(resolved)
            continue
        candidate = os.path.join(resolved, name)
        st = os.lstat(candidate)
        if not stat.S_ISLNK(st.st_mode):
            resolved = candidate
            continue
        target = os.readlink(candidate)
        if max(st.st_ctime, st.st_mtime) >= since:
            return candidate, target
        hops += 1
        if hops > _MAX_SYMLINK_HOPS:
            raise OSError("too many levels of symbolic links")
        if target.startswith("/"):
            resolved = "/"
        parts.extend(reversed(target.split("/")))
    return None


def _symlink_fields(requested: str, since: float) -> dict[str, object]:
    """``via_symlink`` and, if set, the offending link and its target as short strings.

    If the path cannot be walked the event is flagged too (fail closed): the oracle must
    not vouch for a read it could not check.
    """
    try:
        absolute = requested if os.path.isabs(requested) else os.path.join(os.getcwd(), requested)
        found = _fresh_symlink(absolute, since)
    except (OSError, ValueError) as exc:
        found = (f"<unverified: {type(exc).__name__}>", "")
    if found is None:
        return {"via_symlink": False}
    link, target = found
    return {"via_symlink": True, "symlink": link[:_MAX_FIELD], "symlink_target": target[:_MAX_FIELD]}


def key_message(key: bytes) -> bytes:
    """What the orchestrator writes to the plugin's stdin to hand it ``key``."""
    return KEY_MAGIC + key.hex().encode("ascii") + b"\n"


def _signed_bytes(seq: int, body: dict) -> bytes:
    """The bytes an event's signature covers: its seq and the canonical JSON of its body."""
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{seq}\n{canonical}".encode("ascii")


def sign_event(key: bytes | None, seq: int, body: dict) -> dict:
    """The line written for one event; with no key the signature is empty (unsigned)."""
    sig = hmac.new(key, _signed_bytes(seq, body), hashlib.sha256).hexdigest() if key else ""
    return {"body": body, "seq": seq, "sig": sig}


def verify_lines(lines, key: bytes) -> tuple[list[dict], list[str]]:
    """Bodies of the lines that verify under ``key``, and a reason for each dropped line.

    A line is dropped if it is not ``{"body": object, "seq": int, "sig": str}``, if it is
    unsigned, if its signature does not match, or if its seq is not greater than the last
    accepted one (a replayed or reordered line). Blank lines are ignored.
    """
    bodies: list[dict] = []
    rejected: list[str] = []
    last = -1
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            rejected.append("malformed line")
            continue
        if (
            not isinstance(item, dict)
            or set(item) != {"body", "seq", "sig"}
            or not isinstance(item["body"], dict)
            or type(item["seq"]) is not int
            or not isinstance(item["sig"], str)
        ):
            rejected.append("malformed line")
            continue
        if not item["sig"]:
            rejected.append("unsigned event")
            continue
        try:
            expected = hmac.new(key, _signed_bytes(item["seq"], item["body"]), hashlib.sha256).hexdigest()
        except (TypeError, ValueError):
            rejected.append("malformed line")
            continue
        if not hmac.compare_digest(expected, item["sig"]):
            rejected.append("bad signature")
            continue
        if item["seq"] <= last:
            rejected.append("repeated or out-of-order seq")
            continue
        last = item["seq"]
        bodies.append(item["body"])
    return bodies, rejected


def _read_key() -> bytes | None:
    """Read the run key from stdin, once; ``None`` (unsigned mode) if none was supplied.

    Only a pipe or a regular file is read: a terminal or ``/dev/null`` means no key, and
    reading a terminal would block. The orchestrator closes the pipe after writing, so the
    read ends; the data is consumed from the pipe and cannot be read again from fd 0.
    """
    try:
        mode = os.fstat(0).st_mode
    except OSError:
        return None
    if not (stat.S_ISFIFO(mode) or stat.S_ISREG(mode) or stat.S_ISSOCK(mode)):
        return None
    chunks = []
    size = 0
    try:
        while size <= _MAX_STDIN:
            chunk = os.read(0, _MAX_STDIN)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError:
        return None
    data = b"".join(chunks)
    if not data.startswith(KEY_MAGIC) or not data.endswith(b"\n"):
        return None
    try:
        key = bytes.fromhex(data[len(KEY_MAGIC):-1].decode("ascii"))
    except ValueError:
        return None
    return key if len(key) == KEY_BYTES else None


def _install(canary: str, events_path: str, key: bytes | None) -> None:
    global _installed
    if _installed:
        return
    _installed = True
    since = time.time() - _SYMLINK_SLACK
    canary = os.path.realpath(canary)
    # Opened before the audit hook exists, so this open is not observed; every write goes
    # through this descriptor and the path is not kept anywhere the test can look it up.
    fd = os.open(events_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    seq = [0]
    lock = threading.Lock()

    def hook(event: str, args: tuple) -> None:
        if event != "open":
            return
        target = args[0]
        if not isinstance(target, (str, bytes, os.PathLike)):
            return  # an integer file descriptor, not a path
        try:
            requested = os.fsdecode(target)
            if os.path.realpath(requested) != canary:
                return
        except (OSError, ValueError):
            return
        record = {"path": canary, "mode": str(args[1]), "stack": _stack(sys._getframe(1))}
        record.update(_symlink_fields(requested, since))
        with lock:
            line = json.dumps(sign_event(key, seq[0], record)) + "\n"
            seq[0] += 1
            os.write(fd, line.encode("utf-8"))

    _patch_handoffs()
    sys.addaudithook(hook)


def _install_from_env() -> None:
    if _installed:
        return
    canary = os.environ.get(ENV_CANARY)
    events_path = os.environ.get(ENV_EVENTS)
    if canary and events_path:
        # stdin is read only in a run the orchestrator set up (both variables present), so
        # importing this module elsewhere (the orchestrator itself) never touches its stdin.
        _install(canary, events_path, _read_key())
        # The canary path stays: it is the target, not the channel, and exploits derive it
        # from the allowed directory anyway. /proc/self/environ still shows the variable as
        # set at exec; that is why nothing secret is ever put in the environment.
        os.environ.pop(ENV_EVENTS, None)


# Install on import, not only at configure time: ``-p`` plugins are imported before
# entry-point plugins, so modules that bind ``copy_context`` by name at import (anyio does)
# pick up the patched function. Importing is also before pytest starts capturing (which
# points fd 0 at /dev/null), so the key is still on stdin.
_install_from_env()


def pytest_configure(config) -> None:
    _install_from_env()
