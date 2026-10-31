"""The catalog of sinks and entry points the reach search starts and ends at.

It is data, small on purpose, and every entry names the vulnerability class it stands for.
A sink is an external call (or a function handed to another call) whose dotted name the
graph resolved: ``builtins.open``, ``os.path.realpath``, ``subprocess.run``,
``pathlib.Path.read_text``. An entry point is a repository function an attacker's input
reaches first: an ASGI/WSGI callable, a route handler, a CLI main, or a name declared by
the case (``case.json`` ``run.entry_points``), which always wins over detection.

Three families can be proven by the oracle today (SPEC section 7): path traversal through
a read (``canary_read``) and through a write (``canary_write``), and code or command execution
(``canary_exec``). The other sinks are listed so a reach report can say what a path leads to;
their ``effect`` is None, so the loop never pretends it can prove them.
"""

from __future__ import annotations

from dataclasses import dataclass

from exhibit_a.schemas.graph import CodeGraph, EntryPoint, GraphEdge, GraphNode, SinkHit

from .build import MAIN_GUARD

READ, WRITE, EXEC = "canary_read", "canary_write", "canary_exec"


@dataclass(frozen=True)
class SinkRule:
    """Calls to any of ``names`` (exact dotted names, or ``prefix.*`` for a whole module)."""

    names: tuple[str, ...]
    category: str  # filesystem | archive | process | dynamic_code | deserialization | outbound_request
    vuln_class: str
    effect: str | None
    access: str  # read | write | probe | exec | code | network
    note: str
    #: Where an open-like call takes its mode or flags: (position, keyword). A mode with
    #: w/a/x/+ (or os.O_WRONLY/O_RDWR/O_CREAT/O_APPEND/O_TRUNC flags) makes it a write.
    mode_arg: tuple[int, str] | None = None
    #: Where a loader takes its safety argument, and the markers that make the call safe
    #: (yaml.load with a SafeLoader is not a sink).
    safe_arg: tuple[int, str, tuple[str, ...]] | None = None


#: Write-side class and effect for open-like sinks called with a write mode.
WRITE_CLASS = ("path_traversal_write", WRITE)

SINKS: tuple[SinkRule, ...] = (
    SinkRule(("builtins.open", "io.open", "codecs.open", "os.open", "anyio.open_file",
              "aiofiles.open", "pathlib.Path.open"),
             "filesystem", "path_traversal", READ, "read",
             "file open; a write mode makes it a file write", mode_arg=(1, "mode")),
    SinkRule(("pathlib.Path.read_text", "pathlib.Path.read_bytes", "os.stat", "os.lstat",
              "os.listdir", "os.scandir", "os.path.realpath", "os.path.getsize"),
             "filesystem", "path_traversal", READ, "probe",
             "reads or resolves a path on disk"),
    SinkRule(("starlette.responses.FileResponse", "flask.send_file", "flask.send_from_directory",
              "django.http.FileResponse"),
             "filesystem", "path_traversal", READ, "read", "framework file response"),
    SinkRule(("pathlib.Path.write_text", "pathlib.Path.write_bytes", "shutil.copy",
              "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.move", "os.rename",
              "os.replace", "os.link", "os.symlink"),
             "filesystem", "path_traversal_write", WRITE, "write", "writes or moves a file"),
    SinkRule(("zipfile.ZipFile.extract", "zipfile.ZipFile.extractall", "tarfile.open.extract",
              "tarfile.open.extractall", "tarfile.TarFile.extract", "tarfile.TarFile.extractall",
              "shutil.unpack_archive"),
             "archive", "archive_extraction_path_traversal", WRITE, "write",
             "archive extraction; member names decide where files land"),
    SinkRule(("subprocess.run", "subprocess.call", "subprocess.check_call",
              "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
              "subprocess.getstatusoutput", "os.system", "os.popen", "os.execv", "os.execve",
              "os.execvp", "os.execl", "os.spawnv", "os.spawnl", "asyncio.create_subprocess_shell",
              "asyncio.create_subprocess_exec"),
             "process", "command_injection", EXEC, "exec", "runs a process"),
    SinkRule(("builtins.eval", "builtins.exec"),
             "dynamic_code", "code_injection", EXEC, "code", "runs code"),
    SinkRule(("builtins.compile", "builtins.__import__", "importlib.import_module"),
             "dynamic_code", "code_injection", None, "code", "builds or loads code"),
    SinkRule(("pickle.loads", "pickle.load", "pickle.Unpickler", "shelve.open",
              "dill.loads", "yaml.unsafe_load", "yaml.full_load"),
             "deserialization", "insecure_deserialization", EXEC, "code", "unsafe deserialisation"),
    SinkRule(("marshal.loads",), "deserialization", "insecure_deserialization", None, "code",
             "unmarshals code objects without running them"),
    SinkRule(("yaml.load",), "deserialization", "insecure_deserialization", EXEC, "code",
             "yaml.load without a SafeLoader",
             safe_arg=(1, "Loader", ("SafeLoader", "CSafeLoader", "BaseLoader"))),
    SinkRule(("urllib.request.urlopen", "urllib.request.urlretrieve", "http.client.HTTPConnection",
              "http.client.HTTPSConnection", "requests.*", "httpx.*", "aiohttp.ClientSession.get",
              "aiohttp.ClientSession.post", "aiohttp.ClientSession.request"),
             "outbound_request", "ssrf", None, "network",
             "outbound request (SSRF is not a v1 class: the sandbox has no network)"),
)

#: Method names that are sinks whatever the receiver, used only when nothing resolved the
#: receiver; such a hit is weak and counts as one unresolved hop.
WEAK_METHOD_SINKS: dict[str, tuple[str, str, str | None, str]] = {
    "extractall": ("archive", "archive_extraction_path_traversal", WRITE, "write"),
    "read_text": ("filesystem", "path_traversal", READ, "read"),
    "read_bytes": ("filesystem", "path_traversal", READ, "read"),
    "write_text": ("filesystem", "path_traversal_write", WRITE, "write"),
    "write_bytes": ("filesystem", "path_traversal_write", WRITE, "write"),
}

_EXACT = {name: rule for rule in SINKS for name in rule.names if not name.endswith(".*")}
_PREFIX = tuple((name[:-1], rule) for rule in SINKS for name in rule.names if name.endswith(".*"))
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")
#: What a ``requests.*`` / ``httpx.*`` call must end with to be a request.
_REQUEST_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request",
                            "stream", "send", "urlopen"})
_CLIENTS = frozenset({"Client", "AsyncClient", "Session"})


def match_sink(name: str) -> SinkRule | None:
    """The sink rule for an external dotted name, or None."""
    rule = _EXACT.get(name)
    if rule is not None:
        return rule
    for prefix, rule in _PREFIX:
        if name.startswith(prefix):
            rest = name[len(prefix):].split(".")
            if rest[-1] in _REQUEST_VERBS and (len(rest) == 1 or (len(rest) == 2 and rest[0] in _CLIENTS)):
                return rule
    return None


def _arg(edge: GraphEdge, spec: tuple[int, str]) -> str | None:
    position, keyword = spec
    if keyword in edge.kwargs:
        return edge.kwargs[keyword]
    if len(edge.args) > position:
        return edge.args[position]
    return None


def _is_write(rule: SinkRule, edge: GraphEdge) -> bool:
    if rule.mode_arg is None:
        return False
    position, keyword = rule.mode_arg
    if edge.dst == "os.open":
        value = _arg(edge, (1, "flags")) or ""
        return any(flag in value for flag in _WRITE_FLAGS)
    if edge.dst == "pathlib.Path.open":
        position = 0
    value = _arg(edge, (position, keyword))
    if value is None or len(value) < 2 or value[0] not in "'\"" or value[-1] != value[0]:
        return False  # default or computed mode: read
    return any(ch in value[1:-1] for ch in "wax+")


def sink_hits(graph: CodeGraph) -> dict[str, list[SinkHit]]:
    """Every sink call in the graph, by the repository function that makes it."""
    hits: dict[str, list[SinkHit]] = {}
    for edge in graph.edges:
        hit = _edge_hit(edge)
        if hit is not None:
            hits.setdefault(edge.src, []).append(hit)
    for found in hits.values():
        found.sort(key=lambda h: (h.line, h.target))
    return hits


def _edge_hit(edge: GraphEdge) -> SinkHit | None:
    joined = any("os.path.join(" in a for a in edge.args) if edge.args else False
    if edge.kind == "external":
        rule = match_sink(edge.dst)
        if rule is None:
            return None
        if rule.safe_arg is not None and not edge.ref:
            position, keyword, markers = rule.safe_arg
            value = _arg(edge, (position, keyword)) or ""
            if any(marker in value for marker in markers):
                return None
        vuln_class, effect, access = rule.vuln_class, rule.effect, rule.access
        if not edge.ref and _is_write(rule, edge):
            (vuln_class, effect), access = WRITE_CLASS, "write"
        return SinkHit(node=edge.src, target=edge.dst, line=edge.line, category=rule.category,
                       vuln_class=vuln_class, effect=effect, access=access, joined_path=joined)
    if edge.kind == "unresolved" and "." in edge.text:
        method = edge.text.rsplit(".", 1)[1]
        weak = WEAK_METHOD_SINKS.get(method)
        if weak is not None:
            category, vuln_class, effect, access = weak
            return SinkHit(node=edge.src, target=edge.text, line=edge.line, category=category,
                           vuln_class=vuln_class, effect=effect, access=access, weak=True)
    return None


# -- entry points ----------------------------------------------------------------------------

#: Decorators that register a route handler (Starlette/FastAPI/Flask/Sanic/Quart/aiohttp/DRF).
ROUTE_DECORATORS = frozenset({
    "route", "get", "post", "put", "patch", "delete", "head", "options", "websocket",
    "api_route", "websocket_route", "api_view", "view",
})
#: Calls that take a handler as an argument in a route table (Starlette Route/Mount,
#: Django path/re_path/url, Flask add_url_rule, FastAPI/Starlette add_route variants).
ROUTE_TABLE_CALLS = frozenset({
    "Route", "WebSocketRoute", "Mount", "Host", "path", "re_path", "url", "add_url_rule",
    "add_route", "add_api_route", "add_websocket_route", "add_api_websocket_route", "Rule",
})
#: Decorators that make a CLI command (click, typer).
CLI_DECORATORS = frozenset({"command"})
HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
#: Method names that conventionally receive a whole request: http.server handlers
#: (do_GET ...), and the request dispatch method of hand-written apps and frameworks.
REQUEST_HANDLER_METHODS = frozenset({
    "handle_request", "dispatch_request", "do_GET", "do_POST", "do_PUT", "do_PATCH",
    "do_DELETE", "do_HEAD",
})


def _params(node: GraphNode) -> list[str]:
    params = list(node.params)
    if node.kind == "method" and params:
        params = params[1:]
    return params


def _last(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]


def find_entries(graph: CodeGraph, declared: list[str] | tuple[str, ...] = ()) -> tuple[list[EntryPoint], list[str]]:
    """Entry points of the graph, and the declared names that matched no node.

    Declared names (``case.json`` ``run.entry_points``) always win: when any are given,
    they are the only entry points, matched against node qualnames (``App.handle_request``)
    or full ids (``archive:App.handle_request``).
    """
    by_id = {node.id: node for node in graph.nodes}
    if declared:
        entries: list[EntryPoint] = []
        missing: list[str] = []
        for name in declared:
            found = [n for n in graph.nodes if n.kind in ("function", "method")
                     and (n.name == name or n.id == name)]
            if not found:
                missing.append(name)
            entries.extend(EntryPoint(node=n.id, kind="declared", oracle_name=n.name,
                                      detail="case.json entry_points") for n in found)
        return _dedupe(entries), missing

    found: dict[str, EntryPoint] = {}

    def add(node: GraphNode, kind: str, detail: str) -> None:
        if node.kind in ("function", "method") and node.id not in found:
            found[node.id] = EntryPoint(node=node.id, kind=kind, oracle_name=node.name, detail=detail)

    for node in graph.nodes:
        if node.kind not in ("function", "method"):
            continue
        params = _params(node)
        short = node.name.rsplit(".", 1)[-1]
        if (node.kind == "method" and short == "__call__") or node.kind == "function":
            if params[:3] == ["scope", "receive", "send"] and len(params) == 3:
                add(node, "asgi", "ASGI callable (scope, receive, send)")
            elif params[:2] == ["environ", "start_response"] and len(params) == 2:
                add(node, "wsgi", "WSGI callable (environ, start_response)")
        for deco in node.decorators:
            name = _last(deco.callee)
            if not deco.call:
                continue
            if name in ROUTE_DECORATORS and ("." in deco.callee or (deco.path or "").startswith("/")):
                add(node, "route_decorator", f"@{deco.callee}({deco.path!r})" if deco.path else f"@{deco.callee}")
            elif name in CLI_DECORATORS and "." in deco.callee:
                add(node, "cli_main", f"@{deco.callee}")
        if node.module.rsplit(".", 1)[-1] == "views" and params[:1] == ["request"]:
            if node.kind == "function" or short in HTTP_METHODS:
                add(node, "django_view", "view taking a request")
        if node.kind == "method" and short in REQUEST_HANDLER_METHODS:
            add(node, "request_handler", f"method named {short}")
        if node.kind == "function" and node.name == "main":
            add(node, "cli_main", "module-level main()")
    for edge in graph.edges:
        target = by_id.get(edge.dst)
        if target is None:
            continue
        if edge.kind == "ref" and _last(edge.via) in ROUTE_TABLE_CALLS:
            if target.kind == "class":
                for method in graph.nodes:
                    if method.kind == "method" and method.id.startswith(target.id + ".") and \
                            method.name[len(target.name) + 1:] in HTTP_METHODS | {"__call__"}:
                        add(method, "route_table", f"{edge.via}(..., {target.name})")
            else:
                add(target, "route_table", f"{edge.via}(..., {edge.text})")
        elif edge.via == MAIN_GUARD and edge.kind != "ref":
            add(target, "cli_main", "called under if __name__ == '__main__'")
    return sorted(found.values(), key=lambda e: e.node), []


def _dedupe(entries: list[EntryPoint]) -> list[EntryPoint]:
    seen: dict[str, EntryPoint] = {}
    for entry in entries:
        seen.setdefault(entry.node, entry)
    return sorted(seen.values(), key=lambda e: e.node)
