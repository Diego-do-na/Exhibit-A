"""Run sources for the dashboard: one interface, a local and a GitHub backend.

A ``RunSource`` lists recorded runs (``RunRef``) and loads one run's ledger
events plus its optional CI result (``RunData``). Every byte a source reads
is untrusted: files are opened without following symlinks, sizes are capped
before parsing, every ledger line must validate as an ``Event``, and the CI
result is validated against a small schema of the fields the dashboard uses.
A run that fails validation is reported as unreadable as a whole; the
dashboard never shows a partial ledger, because a dropped ``verdict`` line
could turn a proven finding into "nothing could be proven".

``GitHubSource`` talks to GitHub only through the user's own ``gh`` CLI,
started with a fixed argv list (never a shell), a timeout and an output cap.
Artifacts are downloaded as zip bytes on stdout and read in memory, so the
dashboard writes no files.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import zipfile
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..schemas import Event

# -- limits -------------------------------------------------------------------------

#: Largest ledger file accepted, in bytes.
MAX_LEDGER_BYTES = 8 * 1024 * 1024
#: Largest single ledger line accepted, in bytes.
MAX_LINE_BYTES = 256 * 1024
#: Most events accepted in one ledger.
MAX_EVENTS = 20_000
#: Largest CI result JSON accepted, in bytes.
MAX_RESULT_BYTES = 256 * 1024
#: Largest runs.jsonl index accepted, in bytes.
MAX_INDEX_BYTES = 2 * 1024 * 1024
#: Most runs a source lists.
MAX_RUNS = 1000
#: Largest stdout accepted from one gh call (an artifact zip), in bytes.
MAX_GH_OUTPUT = 24 * 1024 * 1024
#: Largest stderr kept from one gh call, in bytes.
MAX_GH_STDERR = 16 * 1024
#: Most entries inspected inside one artifact zip.
MAX_ZIP_ENTRIES = 64
#: Seconds one gh call may take.
GH_TIMEOUT = 30.0
#: Runs kept in memory by a source cache.
CACHE_SIZE = 128
#: Seconds a GitHub run listing stays fresh.
LIST_TTL = 60.0

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}\Z")
ARTIFACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}\Z")
_TOKEN_RE = re.compile(r"(gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})")

LEDGER_NAME = "ledger.jsonl"
RESULT_NAME = "result.json"
INDEX_NAME = "runs.jsonl"
DEFAULT_ARTIFACT = "exhibit-a-ledger"


class SourceError(Exception):
    """A run or listing could not be read or did not validate."""


class GhError(SourceError):
    """The gh CLI failed, timed out, or produced too much output."""


# -- data -------------------------------------------------------------------------


@dataclass(frozen=True)
class RunRef:
    """Cheap metadata about one run, known before its ledger is loaded."""

    run_id: str
    repo: str = ""
    pr: str = ""
    commit: str = ""
    branch: str = ""
    started_at: str = ""
    url: str = ""
    synthetic: bool = False


@dataclass
class RunData:
    """One loaded run: validated events of a single run id plus the CI result."""

    ref: RunRef
    events: list[Event] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str = ""
    tree: Path | None = None


class RunSource(Protocol):
    """Where recorded runs come from. Implementations are read-only."""

    #: Short description shown in the UI, e.g. ``local: runs`` (no secrets).
    label: str

    def list_runs(self) -> list[RunRef]:
        """Every known run, at most ``MAX_RUNS``; order is not significant."""
        ...

    def load_run(self, run_id: str) -> RunData:
        """Load one run. Raises ``KeyError`` for an unknown id.

        A run that exists but does not validate comes back with ``error`` set
        and no events, never as partial data.
        """
        ...


# -- validation helpers ----------------------------------------------------------


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} is not allowed")


def _loads(text: str) -> Any:
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise ValueError("JSON nested too deeply") from exc


def parse_ledger(data: bytes) -> list[Event]:
    """Validate raw ledger bytes into events, enforcing every cap.

    Raises ``SourceError`` naming the first offending line. Blank lines are
    skipped, like ``Ledger.read_all``.
    """
    if len(data) > MAX_LEDGER_BYTES:
        raise SourceError(f"ledger larger than {MAX_LEDGER_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceError("ledger is not valid UTF-8") from exc
    events: list[Event] = []
    for lineno, raw in enumerate(text.split("\n"), start=1):
        if not raw.strip():
            continue
        if len(raw.encode("utf-8")) > MAX_LINE_BYTES:
            raise SourceError(f"ledger line {lineno} longer than {MAX_LINE_BYTES} bytes")
        if len(events) >= MAX_EVENTS:
            raise SourceError(f"ledger has more than {MAX_EVENTS} events")
        try:
            obj = _loads(raw)
        except ValueError as exc:
            raise SourceError(f"ledger line {lineno}: not valid JSON") from exc
        try:
            events.append(Event.model_validate(obj))
        except ValidationError as exc:
            raise SourceError(f"ledger line {lineno}: not a valid Event") from exc
    return events


class _Risk(BaseModel):
    model_config = ConfigDict(extra="ignore")

    risk: Literal["low", "medium", "high"]
    should_run_exploits: bool | None = None


class _Result(BaseModel):
    """The fields of ``ci/summary.py``'s result.json that the dashboard uses.

    Counts are deliberately absent: they are recomputed from the ledger, the
    source of truth, so a result file cannot claim more than the ledger shows.
    """

    model_config = ConfigDict(extra="ignore")

    schema_version: str = Field(max_length=16)
    run_id: str = Field(default="", max_length=256)
    status: Literal["completed", "aborted", "timed_out", "not_run", "skipped"]
    skipped_reason: str = Field(default="", max_length=2000)
    engine_exit: int | None = Field(default=None, ge=-1024, le=1024)
    risk: _Risk | None = None


def parse_result(data: bytes) -> dict[str, Any]:
    """Validate a CI result JSON; returns only the fields the dashboard uses."""
    if len(data) > MAX_RESULT_BYTES:
        raise SourceError(f"result JSON larger than {MAX_RESULT_BYTES} bytes")
    try:
        obj = _loads(data.decode("utf-8"))
        model = _Result.model_validate(obj)
    except (UnicodeDecodeError, ValueError) as exc:  # ValidationError is a ValueError
        raise SourceError("result JSON is not valid") from exc
    return model.model_dump(mode="json")


def select_run(events: list[Event], result: dict[str, Any] | None) -> list[Event]:
    """Keep the events of one run id: the result's, else the last event's."""
    if not events:
        return []
    wanted = (result or {}).get("run_id") or events[-1].run_id
    own = [e for e in events if e.run_id == wanted]
    return own or [e for e in events if e.run_id == events[-1].run_id]


def _short(value: Any, limit: int) -> str:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    return text[:limit]


def _read_capped(path: Path, cap: int) -> bytes | None:
    """Read a regular file without following symlinks; None when absent.

    Raises ``SourceError`` for a symlink, a non-regular file or an oversized one.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SourceError(f"{path.name}: cannot open (symlink or unreadable)") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SourceError(f"{path.name}: not a regular file")
        if info.st_size > cap:
            raise SourceError(f"{path.name}: larger than {cap} bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise SourceError(f"{path.name}: larger than {cap} bytes")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _build_run(ref: RunRef, ledger: bytes | None, result: bytes | None) -> RunData:
    if ledger is None:
        return RunData(ref=ref, error="ledger.jsonl is missing")
    try:
        parsed_result = parse_result(result) if result is not None else None
        events = parse_ledger(ledger)
    except SourceError as exc:
        return RunData(ref=ref, error=str(exc))
    return RunData(ref=ref, events=select_run(events, parsed_result), result=parsed_result)


class _Cache:
    """A tiny thread-safe LRU of loaded runs."""

    def __init__(self, size: int = CACHE_SIZE) -> None:
        self._size = size
        self._items: OrderedDict[str, RunData] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> RunData | None:
        with self._lock:
            item = self._items.get(key)
            if item is not None:
                self._items.move_to_end(key)
            return item

    def put(self, key: str, value: RunData) -> None:
        with self._lock:
            self._items[key] = value
            self._items.move_to_end(key)
            while len(self._items) > self._size:
                self._items.popitem(last=False)


# -- local ------------------------------------------------------------------------


class LocalRunsSource:
    """A directory of run folders, each holding ``ledger.jsonl`` (+ ``result.json``).

    When a ``runs.jsonl`` index sits in the directory it is read for extra
    metadata (repo, pr, commit, branch, started_at) but never required: run
    folders are always discovered by scanning. Index lines that are not JSON
    objects, or that point outside the directory, are ignored.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise SourceError(f"not a directory: {root}")
        self.label = f"local: {self.root.name or self.root}"
        self._cache = _Cache()

    def _index(self) -> dict[str, dict[str, Any]]:
        try:
            raw = _read_capped(self.root / INDEX_NAME, MAX_INDEX_BYTES)
        except SourceError:
            return {}
        if raw is None:
            return {}
        entries: dict[str, dict[str, Any]] = {}
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if not line.strip() or len(line) > MAX_LINE_BYTES:
                continue
            try:
                obj = _loads(line)
            except ValueError:
                continue
            if not isinstance(obj, dict):
                continue
            key = obj.get("dir") or obj.get("path") or obj.get("run_id")
            if isinstance(key, str) and RUN_ID_RE.match(key):
                entries[key] = obj
        return entries

    def _ref(self, name: str, meta: dict[str, Any]) -> RunRef:
        commit = _short(meta.get("commit") or meta.get("head_sha"), 64)
        return RunRef(
            run_id=name,
            repo=_short(meta.get("repo"), 140),
            pr=_short(meta.get("pr"), 64),
            commit=commit if _SHA_RE.match(commit) else "",
            branch=_short(meta.get("branch"), 200),
            started_at=_short(meta.get("started_at") or meta.get("ts"), 64),
            synthetic=meta.get("synthetic") is True,
        )

    def list_runs(self) -> list[RunRef]:
        index = self._index()
        refs: list[RunRef] = []
        with os.scandir(self.root) as entries:
            for entry in entries:
                if len(refs) >= MAX_RUNS:
                    break
                if not RUN_ID_RE.match(entry.name) or not entry.is_dir(follow_symlinks=False):
                    continue
                if not os.path.lexists(os.path.join(entry.path, LEDGER_NAME)):
                    continue
                refs.append(self._ref(entry.name, index.get(entry.name, {})))
        return refs

    def load_run(self, run_id: str) -> RunData:
        if not RUN_ID_RE.match(run_id):
            raise KeyError(run_id)
        folder = self.root / run_id
        try:
            info = os.lstat(folder)
        except OSError as exc:
            raise KeyError(run_id) from exc
        if not stat.S_ISDIR(info.st_mode):
            raise KeyError(run_id)
        ref = self._ref(run_id, self._index().get(run_id, {}))
        # Cache key includes the ledger's size and mtime so an appended ledger reloads.
        try:
            lst = os.lstat(folder / LEDGER_NAME)
            stamp = f"{run_id}:{lst.st_size}:{lst.st_mtime_ns}"
        except OSError:
            stamp = f"{run_id}:missing"
        cached = self._cache.get(stamp)
        if cached is not None:
            return cached
        try:
            ledger = _read_capped(folder / LEDGER_NAME, MAX_LEDGER_BYTES)
            result = _read_capped(folder / RESULT_NAME, MAX_RESULT_BYTES)
        except SourceError as exc:
            data = RunData(ref=ref, error=str(exc))
        else:
            data = _build_run(ref, ledger, result)
            if not data.error:
                # Local replay archives may carry the staged repository under one of
                # these names.  The graph builder only parses this tree; it never runs it.
                for name in ("tree", "repo", "case", "clone", "vulnerable", "app"):
                    candidate = folder / name
                    if candidate.is_dir() and not candidate.is_symlink():
                        data.tree = candidate.resolve()
                        break
                if data.tree is None and any(folder.glob("*.py")):
                    data.tree = folder
        self._cache.put(stamp, data)
        return data


# -- GitHub -------------------------------------------------------------------------

#: ``gh(argv, timeout, max_bytes) -> stdout``; argv excludes the "gh" itself.
GhRunner = Callable[[Sequence[str], float, int], bytes]


def _redact(text: str) -> str:
    return _TOKEN_RE.sub("[redacted]", text)


def run_gh(argv: Sequence[str], timeout: float, max_bytes: int) -> bytes:
    """Run the user's ``gh`` with a fixed argv list, a timeout and an output cap."""
    exe = shutil.which("gh")
    if exe is None:
        raise GhError("the gh CLI was not found on PATH")
    env = dict(os.environ)
    env.update({"GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1", "GH_PAGER": ""})
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [exe, *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        shell=False,
    )
    out = bytearray()
    err = bytearray()
    overflow = threading.Event()

    def pump(stream: Any, sink: bytearray, cap: int, flag: bool) -> None:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            if len(sink) + len(chunk) > cap:
                if flag:
                    overflow.set()
                    proc.kill()
                    return
                sink.extend(chunk[: max(0, cap - len(sink))])
                continue
            sink.extend(chunk)

    readers = [
        threading.Thread(target=pump, args=(proc.stdout, out, max_bytes, True), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, err, MAX_GH_STDERR, False), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait()
        raise GhError(f"gh timed out after {timeout:.0f}s") from exc
    finally:
        for reader in readers:
            reader.join(timeout=2)
    if overflow.is_set():
        raise GhError(f"gh output larger than {max_bytes} bytes")
    if proc.returncode != 0:
        lines = err.decode("utf-8", errors="replace").strip().splitlines()
        first = _redact(lines[0]) if lines else ""
        raise GhError(f"gh exited with {proc.returncode}: {first[:200]}")
    return bytes(out)


class _WorkflowRun(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int = Field(ge=1)
    head_branch: str | None = Field(default=None, max_length=255)
    head_sha: str | None = Field(default=None, max_length=64)


class _Artifact(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int = Field(ge=1)
    name: str = Field(max_length=256)
    size_in_bytes: int = Field(ge=0)
    expired: bool = False
    created_at: str | None = Field(default=None, max_length=64)
    workflow_run: _WorkflowRun | None = None


class _ArtifactList(BaseModel):
    model_config = ConfigDict(extra="ignore")

    artifacts: list[_Artifact] = Field(max_length=1000)


class _PullRef(BaseModel):
    model_config = ConfigDict(extra="ignore")

    number: int = Field(ge=1)


class _RunInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int = Field(ge=1)
    head_sha: str | None = Field(default=None, max_length=64)
    head_branch: str | None = Field(default=None, max_length=255)
    html_url: str | None = Field(default=None, max_length=500)
    run_started_at: str | None = Field(default=None, max_length=64)
    created_at: str | None = Field(default=None, max_length=64)
    pull_requests: list[_PullRef] = Field(default_factory=list, max_length=50)


def read_artifact_zip(data: bytes) -> tuple[bytes | None, bytes | None]:
    """Pull ``ledger.jsonl`` and ``result.json`` out of artifact zip bytes, in memory.

    Only top-level entries with those exact names are read. Declared and
    actual uncompressed sizes are both capped, so a zip bomb stops at the cap.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise SourceError("artifact is not a valid zip") from exc
    caps = {LEDGER_NAME: MAX_LEDGER_BYTES, RESULT_NAME: MAX_RESULT_BYTES}
    found: dict[str, bytes] = {}
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise SourceError(f"artifact has more than {MAX_ZIP_ENTRIES} entries")
        for info in infos:
            cap = caps.get(info.filename)
            if cap is None or info.is_dir() or info.flag_bits & 0x1:
                continue
            if info.file_size > cap:
                raise SourceError(f"{info.filename} in artifact larger than {cap} bytes")
            try:
                with archive.open(info) as handle:
                    body = handle.read(cap + 1)
            except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as exc:
                raise SourceError(f"{info.filename} in artifact is unreadable") from exc
            if len(body) > cap:
                raise SourceError(f"{info.filename} in artifact larger than {cap} bytes")
            found[info.filename] = body
    return found.get(LEDGER_NAME), found.get(RESULT_NAME)


class GitHubSource:
    """Runs whose ledger artifact lives in GitHub Actions, read through ``gh``.

    Listing is one call to the artifacts API filtered by artifact name; loading
    a run fetches its run metadata (commit, branch, PR) and its artifact zip.
    ``gh`` is injectable so tests never touch the network or a real token.
    """

    def __init__(
        self,
        repo: str,
        *,
        artifact: str = DEFAULT_ARTIFACT,
        gh: GhRunner | None = None,
        timeout: float = GH_TIMEOUT,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not REPO_RE.match(repo) or repo.split("/")[1] in (".", ".."):
            raise SourceError(f"invalid repository {repo!r}: expected owner/name")
        if not ARTIFACT_RE.match(artifact):
            raise SourceError(f"invalid artifact name {artifact!r}")
        self.repo = repo
        self.artifact = artifact
        self.label = f"github: {repo}"
        self._gh = gh or run_gh
        self._timeout = timeout
        self._clock = clock
        self._cache = _Cache()
        self._lock = threading.Lock()
        self._listed: tuple[float, dict[str, tuple[RunRef, _Artifact]]] | None = None

    def _call(self, argv: list[str], max_bytes: int = 4 * 1024 * 1024) -> bytes:
        return self._gh(argv, self._timeout, max_bytes)

    def _json(self, argv: list[str], model: type[BaseModel]) -> Any:
        raw = self._call(argv)
        try:
            return model.model_validate(_loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, ValueError) as exc:
            raise GhError("gh returned data that does not match the expected schema") from exc

    def _listing(self) -> dict[str, tuple[RunRef, _Artifact]]:
        with self._lock:
            if self._listed is not None and self._clock() - self._listed[0] < LIST_TTL:
                return self._listed[1]
        listing: _ArtifactList = self._json(
            [
                "api", "--method", "GET", f"repos/{self.repo}/actions/artifacts",
                "-f", f"name={self.artifact}", "-f", "per_page=100",
            ],
            _ArtifactList,
        )
        runs: dict[str, tuple[RunRef, _Artifact]] = {}
        for art in listing.artifacts:
            if art.name != self.artifact or art.expired or art.workflow_run is None:
                continue
            run_id = str(art.workflow_run.id)
            previous = runs.get(run_id)
            if previous is not None and previous[1].id > art.id:
                continue  # keep the newest artifact of a re-run
            sha = art.workflow_run.head_sha or ""
            ref = RunRef(
                run_id=run_id,
                repo=self.repo,
                commit=sha if _SHA_RE.match(sha) else "",
                branch=art.workflow_run.head_branch or "",
                started_at=art.created_at or "",
                url=f"https://github.com/{self.repo}/actions/runs/{run_id}",
            )
            runs[run_id] = (ref, art)
            if len(runs) >= MAX_RUNS:
                break
        with self._lock:
            self._listed = (self._clock(), runs)
        return runs

    def list_runs(self) -> list[RunRef]:
        return [ref for ref, _ in self._listing().values()]

    def load_run(self, run_id: str) -> RunData:
        if not run_id.isdigit() or len(run_id) > 20:
            raise KeyError(run_id)
        cached = self._cache.get(run_id)
        if cached is not None:
            return cached
        entry = self._listing().get(run_id)
        if entry is None:
            raise KeyError(run_id)
        ref, art = entry
        try:
            info: _RunInfo = self._json(
                ["api", "--method", "GET", f"repos/{self.repo}/actions/runs/{int(run_id)}"], _RunInfo
            )
            sha = info.head_sha or ""
            ref = replace(
                ref,
                commit=sha if _SHA_RE.match(sha) else ref.commit,
                branch=info.head_branch or ref.branch,
                pr=str(info.pull_requests[0].number) if info.pull_requests else "",
                started_at=info.run_started_at or info.created_at or ref.started_at,
            )
            if art.size_in_bytes > MAX_GH_OUTPUT:
                raise SourceError(f"artifact larger than {MAX_GH_OUTPUT} bytes")
            blob = self._call(
                ["api", "--method", "GET", f"repos/{self.repo}/actions/artifacts/{art.id}/zip"],
                MAX_GH_OUTPUT,
            )
            ledger, result = read_artifact_zip(blob)
        except SourceError as exc:
            # Not cached: a transient gh failure should be retried on the next view.
            return RunData(ref=ref, error=str(exc))
        data = _build_run(ref, ledger, result)
        self._cache.put(run_id, data)
        return data


# -- parsing the --source flag ----------------------------------------------------------


def parse_source(spec: str, *, artifact: str = DEFAULT_ARTIFACT, gh: GhRunner | None = None) -> RunSource:
    """Build a source from ``local:<dir>`` or ``github:<owner/repo>``."""
    kind, sep, value = spec.partition(":")
    if not sep or not value:
        raise SourceError("source must be local:<dir> or github:<owner/repo>")
    if kind == "local":
        return LocalRunsSource(value)
    if kind == "github":
        return GitHubSource(value, artifact=artifact, gh=gh)
    raise SourceError(f"unknown source kind {kind!r}: use local or github")
