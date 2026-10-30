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

Frames are admitted as application code only against the staged app (docs/oracle-provenance.md).
The orchestrator hashes the app tree before the test runs and sends that manifest on stdin
after the key. When the canary is read, a frame whose file lies under the app root is admitted
only if the file is in the manifest, its current content still has the manifest digest, the
staged source has a function with the frame's qualname at the frame's first line (``ast``), and
the frame's code object equals the one compiled from that source. A function the test built
with ``compile``/``exec`` under an app file name fails the last two checks; a module the test
wrote into the app root fails the first. Every frame under the root carries ``admitted`` and,
when rejected, ``admission`` (why); the judge re-checks the first three on the host.

``os.open`` is wrapped so the hook knows the ``dir_fd`` an open is relative to: the audit event
carries only the relative name, which used to be resolved against the cwd (a missed read).

Each event records how the canary was reached (finding A-11 F2/F4/F5): ``op`` (``open``,
``rename`` for ``os.rename``/``os.replace``, ``link`` for ``os.link``), the raw ``flags`` of an
open, the ``access`` they mean on this platform (``read``, ``write``, ``read_write`` or
``unknown``; classified here because the judge may run on another OS with other flag values),
and ``requested``: the path as the code asked for it, made absolute but not resolved. The judge
uses ``requested`` to require that the canary was reached through the allowed directory.

The module stays self-contained (stdlib only): the sandbox mounts it as a single file.
"""

from __future__ import annotations

import ast
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
# Optional second line (channel v2): the staged app manifest as one line of JSON,
# {"root": <app root as this process sees it>, "files": {<relative path>: <digest>}}.
MANIFEST_MAGIC = b"EXHIBIT-A-MANIFEST "
_MAX_STDIN = 64 * 1024 * 1024
_MAX_MANIFEST_ENTRIES = 200_000
_MAX_SOURCE = 8 * 1024 * 1024

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
_MAX_PATH = 1024  # MAXPATHLEN on macOS, the buffer size F_GETPATH writes into
_MAX_REQUESTED = 4096  # a longer requested path is recorded as None (the judge fails closed)
# Audit events that can put content at the canary's path, and the ``op`` each is recorded as.
# os.replace raises "os.rename" too.
_OBSERVED = {"open": "open", "os.rename": "rename", "os.link": "link"}

# A captured stack is a tuple of code objects, outermost first; None marks a thread boundary
# and _TASK_EDGE a task boundary.
# Code objects are cheap to collect and are only turned into paths when the canary is read.
_ORIGIN: contextvars.ContextVar[tuple[int, tuple] | None] = contextvars.ContextVar(
    "exhibit_a_origin", default=None
)
_local = threading.local()
_THREAD_ORIGIN = "_exhibit_a_origin"
# Bound at import, before any test code runs, like the primitives _Admission keeps.
_COMPILE = compile
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


def _frame_dict(code, admission: _Admission | None = None) -> dict[str, object]:
    if code is None:
        return dict(_BOUNDARY)
    if code is _TASK_EDGE:
        return dict(_TASK_BOUNDARY)
    # Pseudo files such as "<frozen runpy>" must not be resolved against the cwd.
    name = code.co_filename
    real = name if name.startswith("<") else os.path.realpath(name)
    out: dict[str, object] = {
        "file": real,
        "function": code.co_name,
        "qualname": code.co_qualname,
        "line": code.co_firstlineno,
    }
    if admission is not None and not name.startswith("<"):
        rel = admission.relative(real)
        if rel is not None:
            why = admission.check(rel, code)
            out["admitted"] = why is None
            if why is not None:
                out["admission"] = why[:_MAX_FIELD]
    return out


def _stack(frame, admission: _Admission | None = None) -> list[dict[str, object]]:
    """Logical frames from the outermost caller to the innermost, as plain dicts."""
    return [_frame_dict(code, admission) for code in _capture(frame)]


def code_keys(source: bytes) -> frozenset[tuple[str, int]]:
    """``(qualname, first line)`` of every code object ``source`` defines.

    Two readings are combined. The ``ast`` walk names functions, classes, lambdas and
    comprehensions in every scope, listing comprehensions even where 3.12+ inlines them. The
    compiled module, walked through ``co_consts``, adds whatever else the running interpreter
    creates from this source, such as 3.14 ``__annotate__`` functions (PEP 649) and 3.12+
    type-parameter scopes (PEP 695). Either way the key comes from ``source`` itself; a frame is
    still admitted only if its code object equals one compiled from it (``_Admission.check``).
    The first line is what CPython puts in ``co_firstlineno``: the first decorator's line for a
    decorated function or class. Raises ``SyntaxError``/``ValueError`` if ``source`` is not
    Python.
    """
    keys = {("<module>", 1)}
    compiled = [_COMPILE(source, "<staged>", "exec", dont_inherit=True)]
    while compiled:
        code = compiled.pop()
        keys.add((code.co_qualname, code.co_firstlineno))
        compiled.extend(c for c in code.co_consts if hasattr(c, "co_code"))
    comprehensions = {
        ast.GeneratorExp: "<genexpr>",
        ast.ListComp: "<listcomp>",
        ast.SetComp: "<setcomp>",
        ast.DictComp: "<dictcomp>",
    }
    # Each item is a node to classify and the qualname prefix of the scope it sits in.
    todo: list[tuple[ast.AST, str]] = [(c, "") for c in ast.iter_child_nodes(ast.parse(source))]
    while todo:
        node, prefix = todo.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            qual = prefix + node.name
            keys.add((qual, min([node.lineno, *(d.lineno for d in node.decorator_list)])))
            inner = qual + ("." if isinstance(node, ast.ClassDef) else ".<locals>.")
            body = set(map(id, node.body))
            # Decorators, defaults, bases and annotations run in the enclosing scope.
            for c in ast.iter_child_nodes(node):
                todo.append((c, inner if id(c) in body else prefix))
        elif isinstance(node, ast.Lambda):
            keys.add((prefix + "<lambda>", node.lineno))
            todo.extend((c, prefix + "<lambda>.<locals>.") for c in ast.iter_child_nodes(node))
        elif type(node) in comprehensions:
            name = comprehensions[type(node)]
            keys.add((prefix + name, node.lineno))
            todo.extend((c, prefix + name + ".<locals>.") for c in ast.iter_child_nodes(node))
            if not isinstance(node, ast.GeneratorExp):
                # 3.12+ inlines list/set/dict comprehensions (PEP 709): what they contain is
                # named in the enclosing scope there. Both namings are listed.
                todo.extend((c, prefix) for c in ast.iter_child_nodes(node))
        else:
            todo.extend((c, prefix) for c in ast.iter_child_nodes(node))
    return frozenset(keys)


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


class _Admission:
    """Decides, in this process, whether a code object is staged application code.

    The primitives it uses are bound when it is created, at install, before any test code
    runs: a test that later rebinds ``os.open``, ``hashlib.sha256`` or ``compile`` does not
    change what admission calls. That is a tripwire against casual patching, not a boundary
    (the test shares this process; see docs/oracle-provenance.md, residual limits).
    """

    def __init__(self, root: str, files: dict[str, str]) -> None:
        self.root = os.path.realpath(root)
        self.files = {rel: digest for rel, digest in files.items() if _is_digest(digest)}
        self._open, self._read, self._close = os.open, os.read, os.close
        self._sha256 = hashlib.sha256
        self._compile = compile
        self._code_keys = code_keys
        # Compiled code per content digest: keyed by content, never by path, so a file that
        # changes between reads is looked up again under its new digest.
        self._index: dict[str, tuple[frozenset, dict] | str] = {}

    def relative(self, real: str) -> str | None:
        """``real`` relative to the app root (POSIX separators), or None if outside it."""
        if real == self.root or not real.startswith(self.root.rstrip("/") + "/"):
            return None
        return real[len(self.root.rstrip("/")) + 1:]

    def _read_file(self, path: str) -> bytes:
        fd = self._open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            chunks, size = [], 0
            while True:
                chunk = self._read(fd, 1 << 20)
                if not chunk:
                    return b"".join(chunks)
                size += len(chunk)
                if size > _MAX_SOURCE:
                    raise OSError("source file too large")
                chunks.append(chunk)
        finally:
            self._close(fd)

    def _entry(self, digest: str, data: bytes, path: str):
        entry = self._index.get(digest)
        if entry is None:
            try:
                keys = self._code_keys(data)
                codes: dict[tuple[str, int], list] = {}
                todo = [self._compile(data, path, "exec", dont_inherit=True)]
                while todo:
                    code = todo.pop()
                    codes.setdefault((code.co_qualname, code.co_firstlineno), []).append(code)
                    todo.extend(c for c in code.co_consts if hasattr(c, "co_code"))
                entry = (keys, codes)
            except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
                entry = "the staged file is not Python source"
            self._index[digest] = entry
        return entry

    def check(self, rel: str, code) -> str | None:
        """Why ``code`` (from ``root/rel``) is not admitted, or None if it is."""
        digest = self.files.get(rel)
        if digest is None:
            return "file not in the staged app manifest"
        path = os.path.join(self.root, rel)
        try:
            data = self._read_file(path)
        except OSError as exc:
            return f"file unreadable at admission ({type(exc).__name__})"
        if self._sha256(data).hexdigest() != digest:
            return "file content changed since staging"
        entry = self._entry(digest, data, path)
        if isinstance(entry, str):
            return entry
        keys, codes = entry
        key = (code.co_qualname, code.co_firstlineno)
        if key not in keys:
            return f"staged source has no '{key[0]}' starting at line {key[1]}"
        # Code equality covers bytecode, constants, names and line table (not the file name):
        # a same-named function compiled from other source at the same line fails here.
        if not any(candidate == code for candidate in codes.get(key, ())):
            return "code object differs from the staged source (built by compile/exec?)"
        return None


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
        try:
            st = os.lstat(candidate)
        except FileNotFoundError:
            # A name that does not exist cannot be a symlink. This is the normal case for the
            # final component of an open for writing (the file is being created now), so it
            # must not be flagged; other OSErrors still propagate and fail closed.
            resolved = candidate
            continue
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


def _link_to_canary(event: str, args: tuple, canary: str, canary_id: tuple[int, int]) -> tuple[str, str] | None:
    """``(link, target)`` if this ``os.symlink`` / ``os.link`` audit event links to the canary.

    A symlink counts when its target, taken lexically against the link's directory or
    resolved through the links that already exist, is the canary or any directory above it
    (a link to ``outside/`` or to the work directory reaches the canary just as well). A hard
    link counts when its source is the canary. Anything that cannot be worked out counts too
    (fail closed): the flag can only turn a proof into a non-proof.
    """
    try:
        if event == "os.symlink":
            src, dst, dir_fd = args[0], args[1], args[2] if len(args) > 2 else None
            target = os.fsdecode(src)
            link = _absolute(os.fsdecode(dst), dir_fd if isinstance(dir_fd, int) and dir_fd >= 0 else None)
            if link is None:
                return "<symlink with a dir_fd of unknown origin>", target
            absolute_target = target if os.path.isabs(target) else os.path.join(os.path.dirname(link), target)
            for candidate in {os.path.normpath(absolute_target), os.path.realpath(absolute_target)}:
                if candidate == canary or canary.startswith(candidate.rstrip("/") + "/") or candidate == "/":
                    return link, target
            return None
        src = os.fsdecode(args[0])
        src_dir_fd = args[2] if len(args) > 2 and isinstance(args[2], int) and args[2] >= 0 else None
        source = _absolute(src, src_dir_fd)
        if source is None:
            return "<hard link with a dir_fd of unknown origin>", src
        st = os.stat(source)
        if (st.st_dev, st.st_ino) == canary_id or os.path.realpath(source) == canary:
            return os.fsdecode(args[1]), src
        return None
    except FileNotFoundError:
        return None  # a hard link from a name that does not exist creates nothing
    except (OSError, ValueError, TypeError, IndexError) as exc:
        return f"<unverified link: {type(exc).__name__}>", ""


def _symlink_fields(absolute: str | None, since: float) -> dict[str, object]:
    """``via_symlink`` and, if set, the offending link and its target as short strings.

    ``absolute`` is the path as it was requested, made absolute (see ``_resolve``); None when
    that is unknown (a ``dir_fd`` of unknown origin). If the path cannot be walked the event is
    flagged too (fail closed): the oracle must not vouch for a read it could not check.
    """
    try:
        if absolute is None:
            raise LookupError("dir_fd of unknown origin")
        found = _fresh_symlink(absolute, since)
    except LookupError:
        found = ("<unverified: dir_fd of unknown origin>", "")
    except (OSError, ValueError) as exc:
        found = (f"<unverified: {type(exc).__name__}>", "")
    if found is None:
        return {"via_symlink": False}
    link, target = found
    return {"via_symlink": True, "symlink": link[:_MAX_FIELD], "symlink_target": target[:_MAX_FIELD]}


def access_of(flags: object) -> str:
    """What an open with these ``os.open`` flags may do: read, write, read_write or unknown.

    The access mode (``O_RDONLY``/``O_WRONLY``/``O_RDWR``) gives read and write; ``O_CREAT``,
    ``O_TRUNC`` and ``O_APPEND`` also count as a write. ``O_PATH`` (Linux) opens without
    either, and anything that is not an int is not classified: both are ``unknown``.
    """
    if not isinstance(flags, int) or isinstance(flags, bool):
        return "unknown"
    if flags & getattr(os, "O_PATH", 0):
        return "unknown"
    accmode = flags & getattr(os, "O_ACCMODE", os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
    read = accmode in (os.O_RDONLY, os.O_RDWR)
    write = accmode in (os.O_WRONLY, os.O_RDWR) or bool(flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND))
    if read and write:
        return "read_write"
    return "write" if write else "read" if read else "unknown"


def key_message(key: bytes, *, app_root: str | None = None, manifest: dict | None = None) -> bytes:
    """What the orchestrator writes to the plugin's stdin: ``key`` and, optionally, the manifest.

    Without ``manifest`` this is the v1 message (one line). With it a second line carries
    ``{"root": app_root, "files": manifest}`` as ASCII JSON (no raw newline can occur in it).
    """
    message = KEY_MAGIC + key.hex().encode("ascii") + b"\n"
    if manifest is not None:
        if not app_root:
            raise ValueError("a manifest needs the app root it is relative to")
        app = {"root": app_root, "files": dict(manifest)}
        message += MANIFEST_MAGIC + json.dumps(app, sort_keys=True, ensure_ascii=True).encode("ascii") + b"\n"
    return message


def _valid_app(app: object) -> bool:
    return (
        isinstance(app, dict)
        and set(app) == {"root", "files"}
        and isinstance(app["root"], str)
        and app["root"].startswith("/")
        and isinstance(app["files"], dict)
        and len(app["files"]) <= _MAX_MANIFEST_ENTRIES
        and all(isinstance(k, str) and isinstance(v, str) for k, v in app["files"].items())
    )


def parse_channel(data: bytes) -> tuple[bytes | None, dict | None]:
    """The key and the app manifest (or None) from what arrived on stdin.

    Accepts the v1 message (key line only: no manifest, so no frame can be admitted) and the
    v2 message (key line, manifest line). Anything else, including a malformed manifest line,
    yields ``(None, None)``: unsigned mode, so the run can prove nothing (fail closed).
    """
    if not data.endswith(b"\n"):
        return None, None
    lines = data[:-1].split(b"\n")
    if len(lines) > 2 or not lines[0].startswith(KEY_MAGIC):
        return None, None
    try:
        key = bytes.fromhex(lines[0][len(KEY_MAGIC):].decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None, None
    if len(key) != KEY_BYTES:
        return None, None
    if len(lines) == 1:
        return key, None
    if not lines[1].startswith(MANIFEST_MAGIC):
        return None, None
    try:
        app = json.loads(lines[1][len(MANIFEST_MAGIC):].decode("ascii"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, None
    if not _valid_app(app):
        return None, None
    return key, app


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


def _read_channel() -> tuple[bytes | None, dict | None]:
    """Read the run key and app manifest from stdin, once (see ``parse_channel``).

    Only a pipe or a regular file is read: a terminal or ``/dev/null`` means no key, and
    reading a terminal would block. The orchestrator closes the pipe after writing, so the
    read ends; the data is consumed from the pipe and cannot be read again from fd 0.
    """
    try:
        mode = os.fstat(0).st_mode
    except OSError:
        return None, None
    if not (stat.S_ISFIFO(mode) or stat.S_ISREG(mode) or stat.S_ISSOCK(mode)):
        return None, None
    chunks = []
    size = 0
    try:
        while size <= _MAX_STDIN:
            chunk = os.read(0, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError:
        return None, None
    if size > _MAX_STDIN:
        return None, None
    return parse_channel(b"".join(chunks))


# Directory descriptors opened through the wrapped os.open: fd -> (st_dev, st_ino, absolute
# path as requested). The identity check catches a closed and reused descriptor.
_DIR_ORIGINS: dict[int, tuple[int, int, str | None]] = {}


def _dir_origin(dir_fd: int) -> str | None:
    """The path a directory descriptor was opened by, if it was opened through os.open."""
    held = _DIR_ORIGINS.get(dir_fd)
    if held is None:
        return None
    try:
        st = os.fstat(dir_fd)
    except OSError:
        return None
    return held[2] if (st.st_dev, st.st_ino) == held[:2] else None


def _absolute(requested: str, dir_fd: int | None) -> str | None:
    """``requested`` made absolute without resolving symlinks, or None if that is unknown."""
    if os.path.isabs(requested):
        return requested
    if dir_fd is None:
        return os.path.join(os.getcwd(), requested)
    base = _dir_origin(dir_fd)
    return None if base is None else os.path.join(base, requested)


def _dir_fd_path(dir_fd: int) -> str | None:
    """The absolute path of the directory ``dir_fd`` refers to, or None if it cannot be read.

    Linux exposes it as ``/proc/self/fd/<dir_fd>``; macOS has no ``/proc`` and answers
    ``fcntl(F_GETPATH)`` instead. Anything but a complete absolute path is None.
    """
    try:
        base = os.readlink(f"/proc/self/fd/{dir_fd}")
    except OSError:
        base = None
    if base is None:
        try:
            import fcntl
        except ImportError:
            return None
        get_path = getattr(fcntl, "F_GETPATH", None)
        if get_path is None:
            return None
        try:
            raw = fcntl.fcntl(dir_fd, get_path, bytes(_MAX_PATH))
        except (OSError, ValueError, TypeError):
            return None
        end = raw.find(b"\0")
        if end < 0:
            return None  # no terminator: the path may have been cut short
        base = os.fsdecode(raw[:end])
    return base if base.startswith("/") else None


def _resolve(
    requested: str, dir_fd: int | None, canary_id: tuple[int, int], canary: str | None = None
) -> str | None:
    """The real path an open of ``requested`` (relative to ``dir_fd``, if set) reaches.

    With a ``dir_fd`` and a relative name the directory's path is read from the descriptor
    (``_dir_fd_path``). Where that is unavailable the opened file is compared to the canary by
    identity instead and, on a match, ``canary`` (its real path) is returned; that comparison is
    used only while the canary has a single link, so a hard link elsewhere cannot be mistaken
    for it. Never returns a synthetic or partial path: None when unresolvable.
    """
    if dir_fd is None or os.path.isabs(requested):
        return os.path.realpath(requested)
    base = _dir_fd_path(dir_fd)
    if base is not None:
        return os.path.realpath(os.path.join(base, requested))
    if canary is None:
        return None
    st = os.stat(requested, dir_fd=dir_fd)
    if (st.st_dev, st.st_ino) == canary_id and st.st_nlink == 1:
        return canary
    return None


def _patch_os_open() -> None:
    """Wrap ``os.open`` so the audit hook can see the ``dir_fd`` of the open it observes."""
    real_open = os.open

    def open_(path, flags, mode=0o777, *, dir_fd=None):
        previous = getattr(_local, "dir_fd", None)
        _local.dir_fd = dir_fd
        try:
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
        finally:
            _local.dir_fd = previous
        try:
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                _DIR_ORIGINS[fd] = (st.st_dev, st.st_ino, _absolute(os.fsdecode(path), dir_fd))
            else:
                _DIR_ORIGINS.pop(fd, None)
        except (OSError, TypeError, ValueError):
            _DIR_ORIGINS.pop(fd, None)
        return fd

    open_.__name__ = "open"
    open_.__qualname__ = "open"
    open_.__doc__ = real_open.__doc__
    os.open = open_


def _install(canary: str, events_path: str, key: bytes | None, app: dict | None = None) -> None:
    global _installed
    if _installed:
        return
    _installed = True
    since = time.time() - _SYMLINK_SLACK
    canary = os.path.realpath(canary)
    try:
        st = os.stat(canary)
        canary_id = (st.st_dev, st.st_ino)
    except OSError:
        canary_id = (-1, -1)
    admission = _Admission(app["root"], app["files"]) if app else None
    # Opened before the audit hook exists, so this open is not observed; every write goes
    # through this descriptor and the path is not kept anywhere the test can look it up.
    fd = os.open(events_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    seq = [0]
    lock = threading.Lock()

    # Set once the process creates a link to the canary (see _link_to_canary). Every canary
    # access after that is flagged via_symlink, whatever the opened path looks like when it
    # is checked: a link that is swapped in and out cannot win a race against this flag.
    tainted: list[tuple[str, str]] = []

    def hook(event: str, args: tuple) -> None:
        if getattr(_local, "busy", False):
            return  # busy: admission reading an app file from inside this hook
        if event in ("os.symlink", "os.link") and not tainted:
            _local.busy = True
            try:
                found = _link_to_canary(event, args, canary, canary_id)
            finally:
                _local.busy = False
            if found is not None:
                tainted.append(found)
        if event not in _OBSERVED:
            return
        if event == "open":
            target = args[0]
            dir_fd = getattr(_local, "dir_fd", None)
        else:
            # os.rename/os.replace and os.link: (src, dst, src_dir_fd, dst_dir_fd); only a
            # destination that is the canary puts content there.
            target = args[1]
            dir_fd = args[3] if isinstance(args[3], int) and args[3] >= 0 else None
        if not isinstance(target, (str, bytes, os.PathLike)):
            return  # an integer file descriptor, not a path
        try:
            requested = os.fsdecode(target)
            if _resolve(requested, dir_fd, canary_id, canary) != canary:
                return
        except (OSError, ValueError, TypeError):
            return
        _local.busy = True
        try:
            absolute = _absolute(requested, dir_fd)
            if event == "open":
                flags = args[2] if isinstance(args[2], int) and not isinstance(args[2], bool) else None
                fields = {"op": "open", "mode": str(args[1]), "flags": flags, "access": access_of(flags)}
            else:
                fields = {"op": _OBSERVED[event], "mode": event, "flags": None, "access": "write"}
            record = {"path": canary, **fields, "stack": _stack(sys._getframe(1), admission)}
            record["requested"] = absolute if absolute is not None and len(absolute) <= _MAX_REQUESTED else None
            record.update(_symlink_fields(absolute, since))
            if tainted and not record["via_symlink"]:
                link, target = tainted[0]
                record.update({
                    "via_symlink": True,
                    "symlink": f"<link to the canary created during the run: {link}>"[:_MAX_FIELD],
                    "symlink_target": target[:_MAX_FIELD],
                })
        finally:
            _local.busy = False
        with lock:
            line = json.dumps(sign_event(key, seq[0], record)) + "\n"
            seq[0] += 1
            os.write(fd, line.encode("utf-8"))

    _patch_handoffs()
    _patch_os_open()
    sys.addaudithook(hook)


def _install_from_env() -> None:
    if _installed:
        return
    canary = os.environ.get(ENV_CANARY)
    events_path = os.environ.get(ENV_EVENTS)
    if canary and events_path:
        # stdin is read only in a run the orchestrator set up (both variables present), so
        # importing this module elsewhere (the orchestrator itself) never touches its stdin.
        key, app = _read_channel()
        _install(canary, events_path, key, app)
        # Neither path is left for the test. The canary path is not part of the test contract
        # (finding A-11 F2: a test that knows it can root a safe app at the canary's
        # directory); a real exploit reaches it from the allowed directory. /proc/self/environ
        # still shows both as set at exec; that is why nothing secret is ever put in the
        # environment, and why the static guard also rejects any mention of them.
        os.environ.pop(ENV_EVENTS, None)
        os.environ.pop(ENV_CANARY, None)


# Install on import, not only at configure time: ``-p`` plugins are imported before
# entry-point plugins, so modules that bind ``copy_context`` by name at import (anyio does)
# pick up the patched function. Importing is also before pytest starts capturing (which
# points fd 0 at /dev/null), so the key is still on stdin.
_install_from_env()


def pytest_configure(config) -> None:
    _install_from_env()
