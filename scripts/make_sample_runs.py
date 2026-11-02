"""Generate SYNTHETIC run folders for the local dashboard.

Every run written here is made up: realistic in shape (the same ledger event
payloads ``loop/pipeline.py`` emits, the same result.json ``ci/summary.py``
writes) but not the output of a real Exhibit A run. Each run is labelled
synthetic three times: ``synthetic: true`` in its ``pr_opened`` payload, in
the ``runs.jsonl`` index, and in the README written next to the runs.

Two cases are covered, matching the corpus:

- Starlette ``StaticFiles`` path traversal (CVE-2023-29159), effect
  ``canary_read``: proven on the vulnerable release, nothing proven on the
  fixed one.
- Archive extraction path traversal (zip-slip, analog of CVE-2007-4559),
  effect ``canary_write``: proven, plus an incomplete fix that a defender
  bypass variant defeats.

- Billing API command injection and SQL injection (effects ``canary_exec``
  and ``canary_sql``), on a third repository.

Plus the outcomes a dashboard must word carefully: an aborted baseline, a
risk-gate skip, flaky and env_failure verdicts.

Each run folder also carries a small, made-up Python code tree (``tree/``)
and the pull request diff (``pr.diff``), so the dashboard's code graph has a
real call graph to parse: entry points, sinks, and reach paths through the
changed functions. The trees are parsed by the dashboard, never run. Most of
their functions are generated from a fixed seed; the files that hold the
suspicions are written out by hand below.

Usage::

    python scripts/make_sample_runs.py runs-sample
    python -m exhibit_a.dashboard --source local:runs-sample
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from exhibit_a.ci.summary import build_result  # noqa: E402
from exhibit_a.ledger import Ledger  # noqa: E402
from exhibit_a.schemas import Event  # noqa: E402

MODEL = "synthetic-model"
STARLETTE_REPO = "example-org/starlette-app (synthetic)"
ARCHIVE_REPO = "example-org/archive-service (synthetic)"
BILLING_REPO = "example-org/billing-api (synthetic)"
START = datetime(2026, 10, 15, 14, 0, tzinfo=timezone.utc)
FULL_FLAGS = {"naive": False, "oracle": True, "differential": True, "defender": True}


class RunWriter:
    """Builds one synthetic run: events with a running clock, then files."""

    def __init__(self, name: str, run_id: str, start: datetime) -> None:
        self.name = name
        self.run_id = run_id
        self.clock = start
        self.events: list[Event] = []

    def emit(self, type_: str, seconds: float = 1.0, role: str = "", tokens: tuple[int, int] = (0, 0), **payload: Any) -> None:
        self.clock += timedelta(seconds=seconds)
        cost = round((tokens[0] * 0.2 + tokens[1] * 0.6) / 1_000_000, 6)
        self.events.append(
            Event(
                ts=self.clock.isoformat(),
                run_id=self.run_id,
                type=type_,
                role=role,
                model=MODEL if role else "",
                tokens_in=tokens[0],
                tokens_out=tokens[1],
                cost_usd=cost,
                latency_ms=int(seconds * 1000) if role else 0,
                payload=payload,
            )
        )

    def write(
        self,
        out: Path,
        meta: dict[str, Any],
        risk: str,
        engine_exit: int = 0,
        skipped: str = "",
        tree: dict[str, str] | None = None,
        diff: str = "",
    ) -> dict[str, Any]:
        folder = out / self.name
        folder.mkdir(parents=True, exist_ok=True)
        if tree is not None:
            write_tree(folder, tree)
        if diff:
            (folder / "pr.diff").write_text(diff, encoding="utf-8")
        ledger_path = folder / "ledger.jsonl"
        if ledger_path.exists():
            ledger_path.unlink()  # the ledger API only appends; start each sample fresh
        ledger_path.touch()
        ledger = Ledger(ledger_path)
        for event in self.events:
            ledger.append(event)
        result = build_result(
            self.events,
            run_id=self.run_id,
            engine_exit=engine_exit,
            risk={"risk": risk, "should_run_exploits": risk != "low", "reasons": {}},
            skipped_reason=skipped,
        )
        (folder / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        stamp = (self.events[-1] if self.events else None)
        when = datetime.fromisoformat(stamp.ts) if stamp else self.clock
        os.utime(ledger_path, (when.timestamp(), when.timestamp()))
        return {"dir": self.name, "run_id": self.run_id, "started_at": self.clock_start, "synthetic": True, **meta}

    @property
    def clock_start(self) -> str:
        return self.events[0].ts if self.events else self.clock.isoformat()


def frame(file: str, function: str, qualname: str, line: int, admitted: bool | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"file": file, "function": function, "qualname": qualname, "line": line}
    if admitted is not None:
        out["admitted"] = admitted
        out["admission"] = "staged app code" if admitted else "outside the app tree"
    return out




def suspicion(sid: str, cls: str, file: str, line: int, entry: str, hypothesis: str) -> dict[str, Any]:
    return {"id": sid, "class": cls, "location": {"file": file, "line": line}, "entry_point": entry, "hypothesis": hypothesis, "source": "adversary"}


def opening(w: RunWriter, meta: dict[str, Any], baseline_ok: bool = True) -> None:
    w.emit("pr_opened", 0, repo=meta["repo"], pr=meta["pr"], commit=meta["commit"], branch=meta["branch"], synthetic=True, title=meta["title"])
    w.emit("scan_done", 2, language="python", test_cmd="pytest -q", framework=meta.get("framework", ""))
    w.emit("baseline_done", 41 if baseline_ok else 23, ok=baseline_ok, outcome="passed" if baseline_ok else "failed", flags=FULL_FLAGS)


def proven_chain(
    w: RunWriter,
    s: dict[str, Any],
    *,
    canary: str,
    mode: str,
    stack: list[dict[str, Any]],
    reason: str,
    bypasses: list[tuple[str, bool]],
    fix_holds: bool = True,
    effect: str = "canary_read",
) -> None:
    sid = s["id"]
    w.emit("exploit_written", 14, role="test_writer", tokens=(5200, 900), suspicion_id=sid, test_path=f"work/{sid.lower()}/test_exploit.py")
    for n in (1, 2, 3):
        w.emit("run_started", 1, suspicion_id=sid, run=n, of=3)
        event = {"type": effect, "path": canary, "mode": mode, "stack": stack, "via_symlink": False, "symlink": None, "symlink_target": None}
        w.emit("oracle_event", 9, suspicion_id=sid, run=n, event=event)
    w.emit("verdict", 1, suspicion_id=sid, verdict="proven", reason=reason)
    w.emit("fix_proposed", 19, role="fixer", tokens=(6100, 1400), suspicion_id=sid, applied=True)
    for n in (1, 2, 3):
        w.emit("run_started", 8, suspicion_id=sid, on="fixed", run=n, of=3)
    w.emit("baseline_done", 38, suspicion_id=sid, on="fixed", ok=True)
    for i, (name, bypassed) in enumerate(bypasses):
        w.emit("bypass_attempt", 12 if i == 0 else 1, role="defender" if i == 0 else "", tokens=(4800, 1100) if i == 0 else (0, 0), suspicion_id=sid, name=name)
        w.emit("bypass_result", 9, suspicion_id=sid, name=name, bypassed=bypassed)
    w.emit("packaged", 1, suspicion_id=sid, path=f"packages/{sid.lower()}", fix_verified=fix_holds)


def discarded(w: RunWriter, s: dict[str, Any], verdict: str, reason: str, runs: int = 1) -> None:
    sid = s["id"]
    if verdict != "invalid_test":
        w.emit("exploit_written", 11, role="test_writer", tokens=(4300, 700), suspicion_id=sid, test_path=f"work/{sid.lower()}/test_exploit.py")
        for n in range(1, runs + 1):
            w.emit("run_started", 1, suspicion_id=sid, run=n, of=3)
            if verdict == "flaky" and n == 1:
                event = {"type": "canary_read", "path": "/tmp/exhibit_a_oracle/outside/canary.txt", "mode": "r", "stack": STARLETTE_STACK, "via_symlink": False}
                w.emit("oracle_event", 7, suspicion_id=sid, run=n, event=event)
    w.emit("verdict", 4, suspicion_id=sid, verdict=verdict, reason=reason)


# -- code trees ----------------------------------------------------------------------
#
# A tree is {relative path: source text}. The dashboard parses it with the ast-only
# graph builder (exhibit_a.graph.build_graph) and never imports or runs it.

Tree = dict[str, str]

VERBS = ("load", "fetch", "build", "resolve", "render", "parse", "check", "store", "format", "collect",
         "merge", "normalize", "lookup", "apply", "prepare", "validate", "compute", "encode", "decode", "sync")
NOUNS = ("user", "token", "record", "path", "batch", "entry", "report", "invoice", "member", "payload",
         "header", "session", "quota", "limit", "cache", "index", "chunk", "manifest", "profile", "page")
PARAMS = ("item", "name", "value", "request", "options", "key", "data", "target", "query", "size")


def _generated_module(rng: random.Random, module: str, count: int, lower: list[tuple[str, list[str]]],
                      sinks: tuple[str, ...] = (), routes: str = "") -> tuple[str, list[str]]:
    """One filler module: functions that call functions of lower layers (imported by name)."""
    names: list[str] = []
    while len(names) < count:
        name = f"{rng.choice(VERBS)}_{rng.choice(NOUNS)}"
        if name not in names:
            names.append(name)
    imports: dict[str, set[str]] = {}
    bodies: list[str] = []
    needs_os = needs_subprocess = needs_sqlite = False
    # Like real modules, each one depends on a few lower modules, not on all of them.
    deps = rng.sample(lower, min(len(lower), rng.randint(2, 3))) if lower else []
    for index, name in enumerate(names):
        params = rng.sample(PARAMS, rng.randint(1, 2))
        lines = [f'    """{name.replace("_", " ").capitalize()} ({module}, synthetic)."""']
        value = params[0]
        calls = []
        if deps:
            for _ in range(rng.randint(1, 2)):
                mod, funcs = rng.choice(deps)
                calls.append((mod, rng.choice(funcs)))
        for mod, func in calls:
            imports.setdefault(mod, set()).add(func)
            lines.append(f"    {value} = {func}({value})")
        if index > 0 and rng.random() < 0.55:
            sibling = rng.choice(names[:index])
            lines.append(f"    {value} = {sibling}({value})")
        if sinks and index % 3 == 0:
            sink = sinks[(index // 3) % len(sinks)]
            if sink == "read":
                needs_os = True
                lines.append(f'    with open(os.path.join("data", str({value})), "rb") as handle:')
                lines.append(f"        {value} = handle.read()")
            elif sink == "write":
                needs_os = True
                lines.append(f'    with open(os.path.join("out", str({params[0]})), "wb") as handle:')
                lines.append(f"        handle.write(bytes(str({value}), 'utf-8'))")
            elif sink == "exec":
                needs_subprocess = True
                lines.append(f'    subprocess.run(f"convert {{{value}}}", shell=True, check=False)')
            elif sink == "sql":
                needs_sqlite = True
                lines.append('    conn = sqlite3.connect("app.db")')
                lines.append(f'    {value} = conn.execute(f"SELECT * FROM items WHERE name = \'{{{value}}}\'").fetchall()')
        lines.append(f"    return {value}")
        deco = f'@router.get("/{module.rsplit(".", 1)[-1]}/{name.split("_", 1)[1]}")\n' if routes and index % 2 == 0 else ""
        bodies.append(f"{deco}def {name}({', '.join(params)}):\n" + "\n".join(lines) + "\n")
    head = [f'"""{module} (synthetic sample module, generated)."""', ""]
    if needs_os:
        head.append("import os")
    if needs_sqlite:
        head.append("import sqlite3")
    if needs_subprocess:
        head.append("import subprocess")
    if needs_os or needs_sqlite or needs_subprocess:
        head.append("")
    if routes:
        head.append(f"from {routes} import router")
    for mod in sorted(imports):
        head.append(f"from {mod} import {', '.join(sorted(imports[mod]))}")
    return "\n".join(head) + "\n\n\n" + "\n\n".join(bodies), names


def _layered_tree(seed: int, layers: list[list[tuple[str, int, tuple[str, ...]]]], routes: str = "") -> Tree:
    """Modules in layers; a layer only calls the layers below it (index + 1 and further)."""
    rng = random.Random(seed)
    tree: Tree = {}
    known: list[list[tuple[str, list[str]]]] = [[] for _ in layers]
    for depth in range(len(layers) - 1, -1, -1):
        lower = [entry for deeper in known[depth + 1:] for entry in deeper]
        for module, count, sinks in layers[depth]:
            text, names = _generated_module(rng, module, count, lower, sinks, routes if depth == 0 else "")
            tree[module.replace(".", "/") + ".py"] = text
            known[depth].append((module, names))
    return tree


STARLETTE_STATICFILES = '''"""Static file serving (synthetic sample of a vulnerable StaticFiles)."""

import os
import stat

from starlette.responses import FileResponse, PlainTextResponse


class StaticFiles:
    def __init__(self, directory, check_dir=True):
        self.directory = directory
        self.all_directories = self.get_directories(directory)
        if check_dir:
            self.check_config()

    def get_directories(self, directory):
        return [os.path.realpath(directory)]

    def check_config(self):
        info = os.stat(self.directory)
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"StaticFiles directory {self.directory!r} is not a directory")

    async def __call__(self, scope, receive, send):
        response = await self.get_response(self.get_path(scope), scope)
        await response(scope, receive, send)

    def get_path(self, scope):
        return os.path.normpath(os.path.join(*scope["path"].split("/")))

    async def get_response(self, path, scope):
        full_path, stat_result = self.lookup_path(path)
        if stat_result is None:
            return PlainTextResponse("Not Found", status_code=404)
        return self.file_response(full_path, stat_result, scope)

    def lookup_path(self, path):
        for directory in self.all_directories:
            full_path = os.path.realpath(os.path.join(directory, path))
            # commonprefix compares characters, not path segments: "static_secret"
            # shares the prefix of "static".
            if os.path.commonprefix([full_path, directory]) != directory:
                continue
            try:
                return full_path, os.stat(full_path)
            except (FileNotFoundError, NotADirectoryError):
                continue
        return "", None

    def file_response(self, full_path, stat_result, scope):
        return FileResponse(full_path, stat_result=stat_result)
'''

STARLETTE_RESPONSES = '''"""Responses (synthetic sample)."""

import os


class Response:
    media_type = None

    def __init__(self, content=b"", status_code=200, headers=None):
        self.status_code = status_code
        self.body = self.render(content)
        self.init_headers(headers)

    def render(self, content):
        return content if isinstance(content, bytes) else str(content).encode("utf-8")

    def init_headers(self, headers):
        raw = []
        for key, value in (headers or {}).items():
            raw.append((key.lower().encode("latin-1"), value.encode("latin-1")))
        self.raw_headers = raw

    async def __call__(self, scope, receive, send):
        await send({"type": "http.response.start", "status": self.status_code, "headers": self.raw_headers})
        await send({"type": "http.response.body", "body": self.body})


class PlainTextResponse(Response):
    media_type = "text/plain"


class FileResponse(Response):
    def __init__(self, path, stat_result=None, filename=None):
        self.path = path
        self.stat_result = stat_result
        headers = {"content-disposition": f"attachment; filename={filename}"} if filename else {}
        super().__init__(b"", 200, headers)

    async def __call__(self, scope, receive, send):
        with open(self.path, "rb") as handle:
            self.body = handle.read()
        await super().__call__(scope, receive, send)
'''

STARLETTE_MAIN = '''"""Application wiring (synthetic sample)."""

from starlette.routing import Mount, Route, Router
from starlette.staticfiles import StaticFiles
from app.views import homepage, show_avatar, export_rows, health


routes = [
    Route("/", homepage),
    Route("/avatars/{name}", show_avatar),
    Route("/exports/{name}", export_rows),
    Route("/health", health),
    Mount("/static", app=StaticFiles(directory="static")),
]

app = Router(routes=routes)
'''

STARLETTE_ROUTING = '''"""Routing (synthetic sample)."""


class Route:
    def __init__(self, path, endpoint):
        self.path = path
        self.endpoint = endpoint

    def matches(self, scope):
        return scope.get("path", "").startswith(self.path.split("{", 1)[0])


class Mount(Route):
    def __init__(self, path, app):
        super().__init__(path, app)
        self.app = app


class Router:
    def __init__(self, routes):
        self.routes = routes

    async def __call__(self, scope, receive, send):
        for route in self.routes:
            if route.matches(scope):
                await route.endpoint(scope, receive, send)
                return
'''

STARLETTE_VIEWS = '''"""Request handlers (synthetic sample)."""

from starlette.responses import FileResponse, PlainTextResponse
from app.services.avatars import avatar_path, normalize_profile
from app.services.exports import export_path, collect_rows
from app.services.audit import record_access


async def homepage(request):
    record_access(request, "home")
    return PlainTextResponse("ok")


async def show_avatar(request):
    name = normalize_profile(request.path_params["name"])
    record_access(request, name)
    return FileResponse(avatar_path(name))


async def export_rows(request):
    rows = collect_rows(request.path_params["name"])
    return FileResponse(export_path(request.path_params["name"]), filename=f"{len(rows)}.csv")


async def health(request):
    return PlainTextResponse("healthy")
'''


def starlette_tree() -> Tree:
    tree = _layered_tree(41, [
        [("app.services.avatars", 6, ("read",)), ("app.services.exports", 6, ("write",)),
         ("app.services.audit", 5, ())],
        [("app.storage", 7, ("read", "write")), ("app.cache", 6, ()), ("app.auth", 6, ())],
        [("app.settings", 5, ()), ("app.util", 7, ())],
    ])
    # the views import these two names; make sure they exist with these exact names
    tree["app/services/avatars.py"] += '''

def avatar_path(name):
    """Path of an avatar file (synthetic)."""
    return "avatars/" + name


def normalize_profile(name):
    """Lowercase profile name (synthetic)."""
    return name.lower()
'''
    tree["app/services/exports.py"] += '''

def export_path(name):
    """Path of an export file (synthetic)."""
    return "exports/" + name


def collect_rows(name):
    """Rows of an export (synthetic)."""
    return [name]
'''
    tree["app/services/audit.py"] += '''

def record_access(request, name):
    """Remember who read what (synthetic)."""
    return (request, name)
'''
    tree.update({
        "app/__init__.py": "",
        "app/services/__init__.py": "",
        "app/main.py": STARLETTE_MAIN,
        "app/views.py": STARLETTE_VIEWS,
        "starlette/__init__.py": "",
        "starlette/staticfiles.py": STARLETTE_STATICFILES,
        "starlette/responses.py": STARLETTE_RESPONSES,
        "starlette/routing.py": STARLETTE_ROUTING,
    })
    return tree


ARCHIVE_CORE = '''"""Bulk import of archives (synthetic sample of a zip-slip)."""

import os
import zipfile

from importer.pipeline import prepare_batch, store_manifest
from importer.limits import check_quota


def _write_member(destination, member, data):
    target = os.path.join(destination, member)
    with open(target, "wb") as handle:
        handle.write(data)
    return target


def extract_all(archive_path, destination):
    written = []
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.namelist():
            # member names are joined without a containment check: "../x" escapes
            written.append(_write_member(destination, member, archive.read(member)))
    total = sum(os.path.getsize(path) for path in written)
    check_quota(total)
    return written


class App:
    def __init__(self, root):
        self.root = root

    def handle_request(self, request):
        batch = prepare_batch(request)
        written = extract_all(request["archive"], os.path.join(self.root, batch))
        store_manifest(batch, written)
        return {"status": 200, "files": len(written)}
'''


def archive_tree() -> Tree:
    # The large tree of the set (~450 graph nodes): it exercises the graph view at scale.
    layers = [
        [(f"importer.api.{name}", 9, ()) for name in ("uploads", "batches", "admin", "exports", "status", "webhooks",
                                                     "reports", "search")],
        [(f"importer.{name}", 12, sinks) for name, sinks in (
            ("pipeline", ("write",)), ("limits", ()), ("formats", ("read",)), ("scan", ("exec",)),
            ("catalog", ("sql",)), ("thumbnails", ("exec", "write")), ("checksums", ("read",)),
        )],
        [(f"importer.store.{name}", 12, sinks) for name, sinks in (
            ("blobs", ("read", "write")), ("index", ("sql",)), ("locks", ()), ("tmp", ("write",)),
            ("quota", ()), ("events", ()),
        )],
        [(f"importer.lib.{name}", 12, ()) for name in (
            "paths", "text", "timeutil", "retry", "config", "hashing", "units", "naming", "ids", "logs",
            "mime", "compress", "intervals", "slugs", "pool", "metrics",
        )],
    ]
    tree = _layered_tree(9, layers, routes="importer.api.router")
    tree["importer/pipeline.py"] += '''

def prepare_batch(request):
    """Batch folder name for a request (synthetic)."""
    return str(request.get("batch", "default"))


def store_manifest(batch, written):
    """Record what a batch wrote (synthetic)."""
    return (batch, written)
'''
    tree["importer/limits.py"] += '''

def check_quota(total):
    """Refuse oversized imports (synthetic)."""
    return total < 10_000_000
'''
    tree["importer/api/router.py"] = '''"""Route registry (synthetic)."""


class Router:
    def get(self, path):
        def register(func):
            return func
        return register


router = Router()
'''
    for package in ("importer", "importer/api", "importer/store", "importer/lib"):
        tree[f"{package}/__init__.py"] = ""
    tree["archive.py"] = ARCHIVE_CORE
    return tree


BILLING_REPORTS = '''"""Invoice report export (synthetic sample of a command injection)."""

import subprocess

from billing.ledger import load_invoice, format_total


def render_pdf(invoice_id, template):
    invoice = load_invoice(invoice_id)
    output = f"/tmp/{invoice_id}.pdf"
    # the template name reaches a shell command line unquoted
    subprocess.run(f"wkhtmltopdf templates/{template}.html {output}", shell=True, check=False)
    return output, format_total(invoice)


def export_report(request):
    return render_pdf(request["invoice"], request.get("template", "default"))
'''

BILLING_SEARCH = '''"""Invoice search (synthetic sample of a SQL injection)."""

import sqlite3

from billing.ledger import format_total


def search_invoices(term):
    conn = sqlite3.connect("billing.db")
    # the search term is formatted into the statement instead of bound as a parameter
    rows = conn.execute(f"SELECT id, total FROM invoices WHERE customer LIKE '%{term}%'").fetchall()
    return [format_total(row) for row in rows]
'''

BILLING_API = '''"""HTTP routes (synthetic sample)."""

from billing.app import api
from billing.reports import export_report
from billing.search import search_invoices
from billing.ledger import load_invoice


@api.get("/invoices/{invoice_id}/pdf")
def invoice_pdf(request):
    return export_report(request)


@api.get("/invoices/search")
def invoice_search(request):
    return search_invoices(request["q"])


@api.get("/invoices/{invoice_id}")
def invoice_detail(request):
    return load_invoice(request["invoice_id"])
'''

BILLING_APP = '''"""Application object (synthetic)."""


class Api:
    def get(self, path):
        def register(func):
            return func
        return register


api = Api()
'''


def billing_tree() -> Tree:
    tree = _layered_tree(17, [
        [("billing.webhooks", 6, ()), ("billing.dunning", 6, ())],
        [("billing.ledger_ops", 7, ("sql",)), ("billing.tax", 7, ()), ("billing.mailer", 6, ("exec",))],
        [("billing.money", 6, ()), ("billing.dates", 6, ())],
    ])
    tree.update({
        "billing/__init__.py": "",
        "billing/app.py": BILLING_APP,
        "billing/api.py": BILLING_API,
        "billing/reports.py": BILLING_REPORTS,
        "billing/search.py": BILLING_SEARCH,
        "billing/ledger.py": '''"""Invoice storage (synthetic)."""

from billing.money import *  # noqa: F403  (synthetic filler)


def load_invoice(invoice_id):
    return {"id": invoice_id, "total": 0}


def format_total(invoice):
    return f"{invoice}"
''',
    })
    return tree


def line_of(tree: Tree, file: str, needle: str) -> int:
    """1-based line of the first line containing ``needle`` in ``tree[file]``."""
    for number, text in enumerate(tree[file].splitlines(), start=1):
        if needle in text:
            return number
    raise KeyError(f"{needle!r} not in {file}")


def pr_diff(tree: Tree, changes: list[tuple[str, str, int]]) -> str:
    """A unified diff that adds ``count`` lines starting at the line holding ``needle``.

    The added lines are the tree's own lines, so the diff describes the tree: the
    pull request introduced them (synthetic history).
    """
    out: list[str] = []
    for file, needle, count in changes:
        start = line_of(tree, file, needle)
        lines = tree[file].splitlines()[start - 1:start - 1 + count]
        out += [f"diff --git a/{file} b/{file}", f"--- a/{file}", f"+++ b/{file}",
                f"@@ -{start - 1},0 +{start},{len(lines)} @@"]
        out += [f"+{text}" for text in lines]
    return "\n".join(out) + "\n"


def write_tree(folder: Path, tree: Tree) -> None:
    root = folder / "tree"
    if root.exists():
        shutil.rmtree(root)
    for rel, text in sorted(tree.items()):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


def starlette_meta(pr: int, commit: str, title: str) -> dict[str, Any]:
    return {"repo": STARLETTE_REPO, "pr": str(pr), "commit": commit, "branch": f"pr-{pr}", "title": title, "framework": "starlette"}


def billing_meta(pr: int, commit: str, title: str) -> dict[str, Any]:
    return {"repo": BILLING_REPO, "pr": str(pr), "commit": commit, "branch": f"pr-{pr}", "title": title, "framework": ""}


def archive_meta(pr: int, commit: str, title: str) -> dict[str, Any]:
    return {"repo": ARCHIVE_REPO, "pr": str(pr), "commit": commit, "branch": f"pr-{pr}", "title": title, "framework": ""}


STAR_TREE = starlette_tree()
ARCHIVE_TREE = archive_tree()
BILLING_TREE = billing_tree()
STATIC_FILE = "starlette/staticfiles.py"
RESPONSES_FILE = "starlette/responses.py"


def ws(file: str) -> str:
    return f"/workspace/{file}"


STARLETTE_STACK = [
    frame("/workspace/test_exploit.py", "test_static_files_traversal", "test_static_files_traversal", 18, False),
    frame("/usr/local/lib/python3.11/site-packages/httpx/_client.py", "get", "Client.get", 1045),
    frame("<thread boundary>", "<thread boundary>", "<thread boundary>", 0),
    frame(ws("app/routing.py"), "__call__", "Router.__call__", line_of(STAR_TREE, "starlette/routing.py", "await route.endpoint"), True),
    frame(ws(STATIC_FILE), "get_response", "StaticFiles.get_response", line_of(STAR_TREE, STATIC_FILE, "self.lookup_path(path)"), True),
    frame(ws(STATIC_FILE), "lookup_path", "StaticFiles.lookup_path", line_of(STAR_TREE, STATIC_FILE, "os.stat(full_path)"), True),
    frame(ws(RESPONSES_FILE), "__call__", "FileResponse.__call__", line_of(STAR_TREE, RESPONSES_FILE, 'open(self.path, "rb")'), True),
]

ARCHIVE_STACK = [
    frame("/workspace/test_exploit.py", "test_member_escapes_destination", "test_member_escapes_destination", 21, False),
    frame(ws("archive.py"), "handle_request", "App.handle_request", line_of(ARCHIVE_TREE, "archive.py", "written = extract_all("), True),
    frame(ws("archive.py"), "extract_all", "extract_all", line_of(ARCHIVE_TREE, "archive.py", "written.append(_write_member("), True),
    frame(ws("archive.py"), "_write_member", "_write_member", line_of(ARCHIVE_TREE, "archive.py", 'open(target, "wb")'), True),
]

PDF_STACK = [
    frame("/workspace/test_exploit.py", "test_template_reaches_shell", "test_template_reaches_shell", 14, False),
    frame(ws("billing/api.py"), "invoice_pdf", "invoice_pdf", line_of(BILLING_TREE, "billing/api.py", "return export_report(request)"), True),
    frame(ws("billing/reports.py"), "export_report", "export_report", line_of(BILLING_TREE, "billing/reports.py", "return render_pdf("), True),
    frame(ws("billing/reports.py"), "render_pdf", "render_pdf", line_of(BILLING_TREE, "billing/reports.py", "subprocess.run("), True),
]

SEARCH_STACK = [
    frame("/workspace/test_exploit.py", "test_search_term_breaks_query", "test_search_term_breaks_query", 16, False),
    frame(ws("billing/api.py"), "invoice_search", "invoice_search", line_of(BILLING_TREE, "billing/api.py", 'return search_invoices(request["q"])'), True),
    frame(ws("billing/search.py"), "search_invoices", "search_invoices", line_of(BILLING_TREE, "billing/search.py", "conn.execute("), True),
]

S_STATIC = suspicion(
    "S1", "path_traversal", STATIC_FILE, line_of(STAR_TREE, STATIC_FILE, "os.path.commonprefix"), "StaticFiles.get_response",
    "lookup_path joins the request path onto the directory and checks the prefix with os.path.commonprefix, "
    "so a sibling directory sharing the prefix (static vs static_secret) is served.",
)
S_HEADERS = suspicion("S2", "header_injection", RESPONSES_FILE, line_of(STAR_TREE, RESPONSES_FILE, "raw.append("), "Response.init_headers", "A filename with CRLF reaches Content-Disposition unescaped.")
S_RANGE = suspicion("S3", "path_traversal", STATIC_FILE, line_of(STAR_TREE, STATIC_FILE, "os.path.normpath"), "StaticFiles.get_path", "URL-encoded %2e%2e segments survive normalisation.")
S_ZIP = suspicion(
    "Z1", "archive_extraction_path_traversal", "archive.py", line_of(ARCHIVE_TREE, "archive.py", "target = os.path.join(destination, member)"), "App.handle_request",
    "extract_all joins member names onto the destination without containment, so '../' or absolute names write outside it.",
)
S_ZIP_SIZE = suspicion("Z2", "resource_exhaustion", "archive.py", line_of(ARCHIVE_TREE, "archive.py", "total = sum("), "App.handle_request", "No cap on the total uncompressed size (zip bomb).")
S_PDF = suspicion(
    "B1", "command_injection", "billing/reports.py", line_of(BILLING_TREE, "billing/reports.py", "subprocess.run("), "invoice_pdf",
    "render_pdf formats the template name into a shell command line, so a name with ';' runs a second command.",
)
S_SEARCH = suspicion(
    "B2", "sql_injection", "billing/search.py", line_of(BILLING_TREE, "billing/search.py", "conn.execute("), "invoice_search",
    "search_invoices formats the search term into the SQL statement instead of binding it as a parameter.",
)
S_DUNNING = suspicion("B3", "path_traversal", "billing/reports.py", line_of(BILLING_TREE, "billing/reports.py", 'output = f"/tmp/'), "invoice_pdf", "The invoice id is used in an output path without validation.")

#: Which part of the tree each pull request touched (file, first changed line's text, line count).
STAR_DIFFS = {
    41: [(STATIC_FILE, "def lookup_path", 12), ("app/main.py", 'Mount("/static"', 1)],
    44: [(STATIC_FILE, "def get_directories", 2)],
    46: [("starlette/routing.py", "class Router:", 10)],
    48: [(STATIC_FILE, "async def get_response", 5)],
    50: [("app/main.py", 'Route("/exports/{name}"', 1), ("app/views.py", "async def export_rows", 3)],
    52: [("app/views.py", "async def homepage", 3)],
    55: [("app/views.py", "async def show_avatar", 4), (STATIC_FILE, "def lookup_path", 3)],
}
ARCHIVE_DIFFS = {
    7: [("archive.py", "def extract_all", 9), ("archive.py", "def _write_member", 5)],
    9: [("archive.py", "def _write_member", 3)],
}
BILLING_DIFFS = {
    12: [("billing/reports.py", "def render_pdf", 6), ("billing/api.py", '@api.get("/invoices/{invoice_id}/pdf")', 3)],
    15: [("billing/dunning.py", "def ", 6)],
    17: [("billing/search.py", "def search_invoices", 5), ("billing/api.py", '@api.get("/invoices/search")', 3)],
}
DOCS_DIFF = (
    "diff --git a/docs/limits.md b/docs/limits.md\n--- a/docs/limits.md\n+++ b/docs/limits.md\n"
    "@@ -3,0 +4,2 @@\n+Uploads are limited to 50 MB per archive.\n+Larger imports must be split.\n"
)


def build(out: Path) -> list[dict[str, Any]]:
    index: list[dict[str, Any]] = []
    day = timedelta(days=1)

    # 1. Starlette, vulnerable release: proven (canary_read), two discarded.
    meta = starlette_meta(41, "3f1c9b7e2a4d", "Serve uploads from /static")
    w = RunWriter("synthetic-01-starlette-proven", "syn01starlette", START)
    opening(w, meta)
    w.emit("suspicion_raised", 22, role="adversary", tokens=(9800, 1600), suspicion=S_STATIC)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_HEADERS)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_RANGE)
    proven_chain(
        w, S_STATIC, canary="/tmp/exhibit_a_oracle/outside/canary.txt", mode="rb", stack=STARLETTE_STACK,
        reason="canary read through StaticFiles.get_response from staged app code",
        bypasses=[("encoded dot segments", False), ("sibling prefix with trailing slash", False)],
    )
    discarded(w, S_HEADERS, "discarded_unproven", "the exploit passed: no CRLF reached the response headers", runs=1)
    discarded(w, S_RANGE, "invalid_test", "no usable exploit test: the test imported a module that does not exist")
    index.append(w.write(out, meta, "high", tree=STAR_TREE, diff=pr_diff(STAR_TREE, STAR_DIFFS[41])))

    # 2. Starlette, fixed release: nothing could be proven.
    meta = starlette_meta(44, "1797de46c0aa", "Bump starlette to 0.27.0")
    w = RunWriter("synthetic-02-starlette-fixed", "syn02starfixed", START + 2 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 19, role="adversary", tokens=(9400, 1200), suspicion=S_STATIC)
    discarded(w, S_STATIC, "discarded_unproven", "no canary read observed: the exploit request got a 404", runs=1)
    index.append(w.write(out, meta, "high", tree=STAR_TREE, diff=pr_diff(STAR_TREE, STAR_DIFFS[44])))

    # 3. Archive extraction: proven (canary_write).
    meta = archive_meta(7, "a0c4e1d9b3f2", "Accept tar uploads for bulk import")
    w = RunWriter("synthetic-03-archive-proven", "syn03archive", START + 3 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 17, role="adversary", tokens=(6900, 1100), suspicion=S_ZIP)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_ZIP_SIZE)
    proven_chain(
        w, S_ZIP, canary="/tmp/exhibit_a_oracle/outside/canary.txt", mode="wb", stack=ARCHIVE_STACK,
        reason="canary created outside the destination by App.handle_request",
        bypasses=[("absolute member name", False), ("symlink member then write", False)],
    )
    discarded(w, S_ZIP_SIZE, "discarded_unproven", "no oracle for resource exhaustion in this class set", runs=1)
    index.append(w.write(out, meta, "medium", tree=ARCHIVE_TREE, diff=pr_diff(ARCHIVE_TREE, ARCHIVE_DIFFS[7])))

    # 4. Archive extraction, incomplete fix: proven, a defender variant bypasses the fix.
    meta = archive_meta(9, "c71e0b55d8a3", "Reject '..' in archive member names")
    w = RunWriter("synthetic-04-archive-incomplete-fix", "syn04archfix", START + 5 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 15, role="adversary", tokens=(7100, 1000), suspicion=S_ZIP)
    proven_chain(
        w, S_ZIP, canary="/tmp/exhibit_a_oracle/outside/canary.txt", mode="xb", stack=ARCHIVE_STACK,
        reason="canary created outside the destination by App.handle_request",
        bypasses=[("dot-dot member name", False), ("absolute member name", True)],
    )
    index.append(w.write(out, meta, "medium", tree=ARCHIVE_TREE, diff=pr_diff(ARCHIVE_TREE, ARCHIVE_DIFFS[9])))

    # 5. Baseline failed: aborted, nothing could be proven.
    meta = starlette_meta(46, "9be2207d41c0", "Refactor middleware stack")
    w = RunWriter("synthetic-05-aborted-baseline", "syn05aborted", START + 6 * day)
    opening(w, meta, baseline_ok=False)
    index.append(w.write(out, meta, "medium", engine_exit=1, tree=STAR_TREE, diff=pr_diff(STAR_TREE, STAR_DIFFS[46])))

    # 6. Risk gate: docs-only change, exploits skipped.
    meta = archive_meta(11, "5d3a9f0e7b21", "Docs: clarify upload limits")
    w = RunWriter("synthetic-06-skipped-docs", "syn06skipped", START + 7 * day)
    w.emit("pr_opened", 0, repo=meta["repo"], pr=meta["pr"], commit=meta["commit"], branch=meta["branch"], synthetic=True, title=meta["title"])
    index.append(w.write(out, meta, "low", skipped="documentation and tests only", tree=ARCHIVE_TREE, diff=DOCS_DIFF))

    # 7. Flaky and env_failure verdicts: nothing could be proven.
    meta = starlette_meta(48, "e8b14c02f6d9", "Cache static file stats")
    w = RunWriter("synthetic-07-flaky-env", "syn07flaky", START + 9 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 21, role="adversary", tokens=(10200, 1500), suspicion=S_STATIC)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_HEADERS)
    discarded(w, S_STATIC, "flaky", "unstable across runs: run 2 saw no canary read", runs=2)
    discarded(w, S_HEADERS, "env_failure", "run 1 could not execute: sandbox image build timed out", runs=1)
    index.append(w.write(out, meta, "high", tree=STAR_TREE, diff=pr_diff(STAR_TREE, STAR_DIFFS[48])))

    # 8-10. More history for the trends chart.
    for k, (pr, commit, title, proven) in enumerate(
        [
            (50, "0f9d2c6b8e14", "Add /exports static mount", True),
            (52, "7a2e5c9d1b06", "Tighten CORS settings", False),
            (55, "b4e81f3a6c29", "Serve avatars from user dirs", True),
        ]
    ):
        meta = starlette_meta(pr, commit, title)
        w = RunWriter(f"synthetic-{8 + k:02d}-starlette-pr{pr}", f"syn{8 + k:02d}pr{pr}", START + (11 + 2 * k) * day)
        opening(w, meta)
        w.emit("suspicion_raised", 18, role="adversary", tokens=(9100, 1300), suspicion=S_STATIC)
        w.emit("suspicion_raised", 0, role="adversary", suspicion=S_RANGE)
        if proven:
            proven_chain(
                w, S_STATIC, canary="/tmp/exhibit_a_oracle/outside/canary.txt", mode="rb", stack=STARLETTE_STACK,
                reason="canary read through StaticFiles.get_response from staged app code",
                bypasses=[("encoded dot segments", False)],
            )
        else:
            discarded(w, S_STATIC, "discarded_unproven", "the exploit passed: the request was confined", runs=1)
        discarded(w, S_RANGE, "invalid_test" if k != 1 else "discarded_unproven", "the exploit failed before reaching the app (wrong reason)", runs=1)
        index.append(w.write(out, meta, "high", tree=STAR_TREE, diff=pr_diff(STAR_TREE, STAR_DIFFS[pr])))

    # 11-13. A third repository: command injection and SQL injection (canary_exec, canary_sql).
    meta = billing_meta(12, "4c2a91f0d3e7", "Render invoices to PDF")
    w = RunWriter("synthetic-11-billing-pdf-exec", "syn11billpdf", START + 4 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 16, role="adversary", tokens=(8200, 1400), suspicion=S_PDF)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_DUNNING)
    proven_chain(
        w, S_PDF, canary="", mode="", stack=PDF_STACK, effect="canary_exec",
        reason="canary command executed by render_pdf, reached from the invoice_pdf route",
        bypasses=[("template with $(...)", False), ("template with backticks", False)],
    )
    discarded(w, S_DUNNING, "discarded_unproven", "the exploit passed: the output path stayed under /tmp", runs=1)
    index.append(w.write(out, meta, "high", tree=BILLING_TREE, diff=pr_diff(BILLING_TREE, BILLING_DIFFS[12])))

    meta = billing_meta(15, "8e0b7d21c4a6", "Add dunning reminders")
    w = RunWriter("synthetic-12-billing-dunning", "syn12billdun", START + 10 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 14, role="adversary", tokens=(7400, 1100), suspicion=S_DUNNING)
    discarded(w, S_DUNNING, "discarded_unproven", "no canary write observed: the reminder job wrote only under its spool", runs=1)
    index.append(w.write(out, meta, "medium", tree=BILLING_TREE, diff=pr_diff(BILLING_TREE, BILLING_DIFFS[15])))

    meta = billing_meta(17, "d97f3b0a51c8", "Invoice search by customer")
    w = RunWriter("synthetic-13-billing-search-sql", "syn13billsql", START + 16 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 18, role="adversary", tokens=(8800, 1500), suspicion=S_SEARCH)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_PDF)
    proven_chain(
        w, S_SEARCH, canary="", mode="", stack=SEARCH_STACK, effect="canary_sql",
        reason="canary row read by a statement built in search_invoices, reached from the invoice_search route",
        bypasses=[("term with UNION", False), ("term with comment", False)],
    )
    discarded(w, S_PDF, "flaky", "unstable across runs: run 2 saw no canary command", runs=2)
    index.append(w.write(out, meta, "high", tree=BILLING_TREE, diff=pr_diff(BILLING_TREE, BILLING_DIFFS[17])))
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write SYNTHETIC run folders for the dashboard.")
    parser.add_argument("out", help="Directory to create (must be empty or absent unless --force).")
    parser.add_argument("--force", action="store_true", help="Rewrite the synthetic folders in a non-empty directory.")
    args = parser.parse_args(argv)
    out = Path(args.out)
    if out.exists() and any(out.iterdir()) and not args.force:
        print(f"make_sample_runs: {out} is not empty (use --force)", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    index = build(out)
    (out / "runs.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in index), encoding="utf-8")
    (out / "README.txt").write_text(
        "SYNTHETIC SAMPLE RUNS. Generated by scripts/make_sample_runs.py.\n"
        "These are not results of real Exhibit A runs; they only exercise the dashboard.\n",
        encoding="utf-8",
    )
    print(f"make_sample_runs: wrote {len(index)} synthetic runs to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
