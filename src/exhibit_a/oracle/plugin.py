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

The module stays self-contained (stdlib only): the sandbox mounts it as a single file.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import os
import sys
import threading
import weakref
from concurrent.futures import ThreadPoolExecutor

ENV_CANARY = "EXHIBIT_A_CANARY"
ENV_EVENTS = "EXHIBIT_A_EVENTS"

_MAX_FRAMES = 200
_BOUNDARY = {"file": "<thread>", "function": "<thread boundary>", "qualname": "<thread boundary>"}
_TASK_BOUNDARY = {"file": "<task>", "function": "<task boundary>", "qualname": "<task boundary>"}
_TASK_EDGE = "task"

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


def _install(canary: str, events_path: str) -> None:
    global _installed
    if _installed:
        return
    _installed = True
    canary = os.path.realpath(canary)

    def hook(event: str, args: tuple) -> None:
        if event != "open":
            return
        target = args[0]
        if not isinstance(target, (str, bytes, os.PathLike)):
            return  # an integer file descriptor, not a path
        try:
            if os.path.realpath(os.fsdecode(target)) != canary:
                return
        except (OSError, ValueError):
            return
        record = {"path": canary, "mode": str(args[1]), "stack": _stack(sys._getframe(1))}
        with open(events_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    _patch_handoffs()
    sys.addaudithook(hook)


def _install_from_env() -> None:
    canary = os.environ.get(ENV_CANARY)
    events_path = os.environ.get(ENV_EVENTS)
    if canary and events_path:
        _install(canary, events_path)


# Install on import, not only at configure time: ``-p`` plugins are imported before
# entry-point plugins, so modules that bind ``copy_context`` by name at import (anyio does)
# pick up the patched function.
_install_from_env()


def pytest_configure(config) -> None:
    _install_from_env()
