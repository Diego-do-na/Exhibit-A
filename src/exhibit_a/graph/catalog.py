"""The catalog of sinks and entry points the reach search starts and ends at.

It is data, small on purpose, and every entry names the vulnerability class it stands for.
A sink is an external call (or a function handed to another call) whose dotted name the
graph resolved: ``builtins.open``, ``os.path.realpath``, ``subprocess.run``,
``pathlib.Path.read_text``. An entry point is a repository function an attacker's input
reaches first: an ASGI/WSGI callable, a route handler, a CLI main, or a name declared by
the case (``case.json`` ``run.entry_points``), which always wins over detection.

Eight families can be proven by the oracle today: path traversal through a read
(``canary_read``) and through a write (``canary_write``), code or command execution
(``canary_exec``), SQL injection (``canary_sql``), server-side request forgery
(``canary_connect``), algorithmic complexity (``canary_dos``: ReDoS, quadratic
parsing), open redirect (``canary_redirect``) and broken access control
(``canary_access``: no sink call, only the observed response). A sliced PR run
that omits ``--effect`` therefore cannot derive IDOR: there is nothing reachable
to prove. The other sinks are listed so a reach report can say what a path leads
to; their ``effect`` is None, so the loop never pretends it can prove them.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from exhibit_a.schemas.graph import CodeGraph, EntryPoint, GraphEdge, GraphNode, SinkHit

from .build import MAIN_GUARD, SQL_RUN_METHODS

READ, WRITE, EXEC, SQL, CONNECT, DOS, REDIRECT, ACCESS = (
    "canary_read", "canary_write", "canary_exec", "canary_sql", "canary_connect", "canary_dos",
    "canary_redirect", "canary_access",
)


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
    #: Where a query-running call takes its statement: (position, keyword names). The call is a
    #: sink only when that argument is not a constant string (``dynamic_query``): a constant
    #: statement, however it is run, cannot carry input.
    query_arg: tuple[int, tuple[str, ...]] | None = None
    #: Where a connection-opening call takes its target: (position, keyword names). The call
    #: is a sink only when that argument is not a constant (``dynamic_address``): a fixed
    #: target cannot carry input.
    target_arg: tuple[int, tuple[str, ...]] | None = None
    #: Where a code, template, XML, YAML or upload-path call takes its payload: (position,
    #: keyword names). The call is a sink only when that argument is not a constant
    #: (``dynamic_source``): a literal cannot carry input.
    source_arg: tuple[int, tuple[str, ...]] | None = None
    #: How XML entity resolution is decided for this rule. ``always``: any non-constant
    #: source is a sink (minidom, sax). ``lxml``: a sink unless ``resolve_entities`` is
    #: False and no custom resolver is set. ``etree``: a sink only when a parser argument
    #: is supplied (the stdlib parser does not resolve entities on its own).
    xml_mode: str | None = None
    #: Where a regex call takes its pattern: (position, keyword names). The call is a
    #: sink when that argument is not a constant, or is a constant with nested
    #: quantifiers (a known-catastrophic pattern). A linear constant pattern is not.
    pattern_arg: tuple[int, tuple[str, ...]] | None = None


#: Write-side class and effect for open-like sinks called with a write mode.
WRITE_CLASS = ("path_traversal_write", WRITE)

#: Calls that run a raw SQL statement. The graph names the result of ``sqlite3.connect(...)`` by
#: that call, so ``conn.execute`` and ``conn.cursor().execute`` resolve to the first two forms; the
#: type names cover an annotated ``conn: sqlite3.Connection`` or ``cur: sqlite3.Cursor``.
SQL_QUERY_CALLS: tuple[str, ...] = (
    *(f"sqlite3.connect.{m}" for m in ("execute", "executemany", "executescript")),
    *(f"sqlite3.connect.cursor.{m}" for m in ("execute", "executemany", "executescript")),
    *(f"sqlite3.{t}.{m}" for t in ("Connection", "Cursor") for m in ("execute", "executemany", "executescript")),
    "sqlalchemy.text", "sqlalchemy.create_engine.execute", "sqlalchemy.create_engine.connect.execute",
    "sqlalchemy.create_engine.connect.exec_driver_sql", "sqlalchemy.engine.Connection.execute",
    "sqlalchemy.engine.Connection.exec_driver_sql", "sqlalchemy.engine.Engine.execute",
    "sqlalchemy.orm.Session.execute",
    "pandas.read_sql", "pandas.read_sql_query",
)

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
    SinkRule(("werkzeug.datastructures.FileStorage.save",
              "starlette.datastructures.UploadFile.write"),
             "filesystem", "unrestricted_file_upload", WRITE, "write",
             "saves an uploaded file; a constant destination cannot carry a name",
             source_arg=(0, ("dst", "path", "location", "filename"))),
    SinkRule(("xml.dom.minidom.parse", "xml.dom.minidom.parseString",
              "xml.sax.parse", "xml.sax.parseString", "xml.sax.make_parser.parse"),
             "xml", "xml_external_entity", READ, "read",
             "XML parse that may resolve external entities; a constant source cannot carry input",
             source_arg=(0, ("source", "string", "filename", "stream")), xml_mode="always"),
    SinkRule(("lxml.etree.parse", "lxml.etree.fromstring", "lxml.etree.XML"),
             "xml", "xml_external_entity", READ, "read",
             "lxml parse; resolve_entities or a custom resolver makes it a sink",
             source_arg=(0, ("source", "text", "tag")), xml_mode="lxml"),
    SinkRule(("lxml.etree.XMLParser",),
             "xml", "xml_external_entity", READ, "read",
             "lxml XMLParser; resolve_entities or a custom resolver makes it a sink",
             xml_mode="lxml"),
    SinkRule(("xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
              "xml.etree.ElementTree.XML"),
             "xml", "xml_external_entity", READ, "read",
             "ElementTree parse; only a caller-supplied XMLParser may enable entities",
             source_arg=(0, ("source", "text", "tag")), xml_mode="etree"),
    SinkRule(("jinja2.Template", "jinja2.Environment.from_string"),
             "template", "server_side_template_injection", EXEC, "code",
             "compiles a template; a constant source cannot carry input",
             source_arg=(0, ("source", "sourcecode", "src"))),
    SinkRule(("subprocess.run", "subprocess.call", "subprocess.check_call",
              "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
              "subprocess.getstatusoutput", "os.system", "os.popen", "os.execv", "os.execve",
              "os.execvp", "os.execl", "os.spawnv", "os.spawnl", "asyncio.create_subprocess_shell",
              "asyncio.create_subprocess_exec"),
             "process", "command_injection", EXEC, "exec", "runs a process"),
    SinkRule(("builtins.eval", "builtins.exec"),
             "dynamic_code", "code_injection", EXEC, "code",
             "runs code; a constant argument cannot carry input",
             source_arg=(0, ("source", "code", "object"))),
    SinkRule(("builtins.compile",),
             "dynamic_code", "code_injection", None, "code",
             "compiles code; a constant argument cannot carry input",
             source_arg=(0, ("source", "code"))),
    SinkRule(("builtins.__import__", "importlib.import_module"),
             "dynamic_code", "code_injection", None, "code", "loads a module"),
    SinkRule(("pickle.loads", "pickle.load", "pickle.Unpickler", "shelve.open",
              "dill.loads", "yaml.unsafe_load", "yaml.full_load"),
             "deserialization", "insecure_deserialization", EXEC, "code",
             "unsafe deserialisation; a constant argument cannot carry input",
             source_arg=(0, ("stream", "data"))),
    SinkRule(("marshal.loads",), "deserialization", "insecure_deserialization", None, "code",
             "unmarshals code objects without running them"),
    SinkRule(("yaml.load",), "deserialization", "insecure_deserialization", EXEC, "code",
             "yaml.load without a SafeLoader; a constant argument cannot carry input",
             safe_arg=(1, "Loader", ("SafeLoader", "CSafeLoader", "BaseLoader")),
             source_arg=(0, ("stream", "data"))),
    SinkRule(SQL_QUERY_CALLS, "database", "sql_injection", SQL, "query",
             "runs SQL; a statement that is not a constant string can carry input", query_arg=(0, ("sql", "query", "statement"))),
    SinkRule(("urllib.request.urlopen", "urllib.request.urlretrieve", "http.client.HTTPConnection",
              "http.client.HTTPSConnection", "requests.*", "httpx.*", "aiohttp.ClientSession.get",
              "aiohttp.ClientSession.post", "aiohttp.ClientSession.request"),
             "outbound_request", "ssrf", CONNECT, "network",
             "outbound request the loopback canary listener observes"),
    SinkRule(("socket.create_connection",),
             "outbound_request", "ssrf", CONNECT, "network",
             "opens a connection; only a non-constant target can carry input",
             target_arg=(0, ("address", "host", "port"))),
    SinkRule(("flask.redirect", "werkzeug.utils.redirect"),
             "redirect", "open_redirect", REDIRECT, "redirect",
             "redirect to a caller-supplied URL; a constant target cannot carry input",
             target_arg=(0, ("location", "url"))),
    SinkRule(("django.shortcuts.redirect", "django.http.HttpResponseRedirect",
              "django.http.HttpResponsePermanentRedirect", "django.http.HttpResponseFound"),
             "redirect", "open_redirect", REDIRECT, "redirect",
             "redirect to a caller-supplied URL; a constant target cannot carry input",
             target_arg=(0, ("to", "redirect_to", "url"))),
    SinkRule(("starlette.responses.RedirectResponse", "fastapi.responses.RedirectResponse"),
             "redirect", "open_redirect", REDIRECT, "redirect",
             "redirect to a caller-supplied URL; a constant target cannot carry input",
             target_arg=(0, ("url",))),
    SinkRule(("re.match", "re.search", "re.fullmatch", "re.sub", "re.findall", "re.compile"),
             "regex", "regex_denial_of_service", DOS, "cpu",
             "regex on attacker input; a non-constant or nested-quantifier pattern is ReDoS",
             pattern_arg=(0, ("pattern",))),
    # PATTERN = re.compile(...); PATTERN.match(name) resolves to re.compile.match.
    SinkRule(("re.compile.match", "re.compile.search", "re.compile.fullmatch",
              "re.compile.findall", "re.compile.finditer"),
             "regex", "regex_denial_of_service", DOS, "cpu",
             "compiled regex on attacker input; the pattern was compiled earlier"),
    SinkRule(("json.loads", "json.load", "json.JSONDecoder.decode"),
             "parsing", "algorithmic_complexity", DOS, "cpu",
             "JSON parse of attacker input; unbounded nesting is quadratic or worse",
             source_arg=(0, ("s", "fp", "document", "text"))),
    SinkRule(("xml.etree.ElementTree.iterparse", "xml.parsers.expat.ParserCreate"),
             "parsing", "algorithmic_complexity", DOS, "cpu",
             "XML parse of attacker input; unbounded nesting is quadratic or worse"),
)

_SQL_RULE = next(rule for rule in SINKS if rule.query_arg is not None)

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


def _constant_text(text: str) -> bool:
    """Whether the source text of an argument is a string whose value is fixed by the code alone.

    Literals (also joined by implicit concatenation or ``+``) and f-strings without a replacement
    field are constants. Anything that does not parse, such as text cut at the graph's cap, is not.
    """
    try:
        node = ast.parse(text.strip(), mode="eval").body
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False

    def fixed(n: ast.AST) -> bool:
        if isinstance(n, ast.Constant):
            return isinstance(n.value, str)
        if isinstance(n, ast.JoinedStr):
            return all(isinstance(v, ast.Constant) for v in n.values)
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            return fixed(n.left) and fixed(n.right)
        return False

    return fixed(node)


def _dynamic_payload(edge: GraphEdge, spec: tuple[int, tuple[str, ...]]) -> bool:
    """Whether a call may carry input: the named argument is not a constant.

    A call with no such argument kept by the graph (``*args``, ``**kwargs``) counts as
    dynamic, because it cannot be shown to be constant.
    """
    position, keywords = spec
    value = edge.args[position] if len(edge.args) > position else next(
        (edge.kwargs[k] for k in keywords if k in edge.kwargs), None)
    if value is None:
        return bool(edge.args or edge.kwargs)
    return not _constant_text(value)


def _dynamic_query(rule: SinkRule, edge: GraphEdge) -> bool:
    """Whether a query-running call may carry input: its statement is not a constant string."""
    assert rule.query_arg is not None
    return _dynamic_payload(edge, rule.query_arg)


def _false_literal(value: str | None) -> bool:
    """Whether the source text of an argument names False."""
    if value is None:
        return False
    return value.replace(" ", "") in ("False", "false", "0")


def _xml_entities_on(rule: SinkRule, edge: GraphEdge) -> bool:
    """Whether an XML parse or parser call may resolve external entities."""
    mode = rule.xml_mode
    if mode is None or mode == "always":
        return True
    if edge.kwargs.get("resolver"):
        return True
    if mode == "lxml":
        if edge.dst.endswith("XMLParser"):
            return not _false_literal(edge.kwargs.get("resolve_entities"))
        parser = edge.kwargs.get("parser")
        if parser is None and len(edge.args) > 1:
            parser = edge.args[1]
        if parser:
            compact = parser.replace(" ", "")
            if "resolver=" in compact:
                return True
            if "resolve_entities=False" in compact:
                return False
        return True
    if mode == "etree":
        return "parser" in edge.kwargs or len(edge.args) > 1
    return True


def _constant_string(text: str) -> str | None:
    """The string value of a constant argument, or None if it is not a fixed string."""
    try:
        node = ast.parse(text.strip(), mode="eval").body
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and all(isinstance(v, ast.Constant) for v in node.values):
        return "".join("" if v.value is None else str(v.value) for v in node.values)
    return None


def _matching_paren(pattern: str, start: int) -> int | None:
    """Index of the ``)`` that closes the group at ``start``, or None."""
    depth = 0
    i = start
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _has_quantifier(text: str) -> bool:
    """Whether ``text`` contains a regex quantifier ``*``, ``+`` or ``{n,}``."""
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "\\" and i + 1 < n:
            i += 2
            continue
        if text[i] in "*+":
            return True
        if text[i] == "{":
            return True
        i += 1
    return False


def _catastrophic_regex(pattern: str) -> bool:
    """Whether ``pattern`` has nested quantifiers, the usual ReDoS shape.

    ``(a+)+``, ``(a*)*``, ``(?:a+)+`` and the same with a trailing ``$`` count.
    A linear pattern such as ``^[a-z]+$`` does not.
    """
    i = 0
    n = len(pattern)
    while i < n:
        if pattern[i] == "\\" and i + 1 < n:
            i += 2
            continue
        if pattern[i] == "(":
            end = _matching_paren(pattern, i)
            if end is None:
                return False
            inner = pattern[i + 1:end]
            rest = pattern[end + 1:]
            quantified = bool(rest) and (rest[0] in "*+" or rest[0] == "{")
            if quantified and _has_quantifier(inner):
                return True
            if _catastrophic_regex(inner):
                return True
            i = end + 1
            continue
        i += 1
    return False


def _regex_is_dos(rule: SinkRule, edge: GraphEdge) -> bool:
    """Whether a regex call may carry a ReDoS pattern: non-constant or nested quantifiers."""
    assert rule.pattern_arg is not None
    position, keywords = rule.pattern_arg
    value = edge.args[position] if len(edge.args) > position else next(
        (edge.kwargs[k] for k in keywords if k in edge.kwargs), None)
    if value is None:
        return bool(edge.args or edge.kwargs)
    constant = _constant_string(value)
    if constant is None:
        return True
    return _catastrophic_regex(constant)


def _dynamic_address(rule: SinkRule, edge: GraphEdge) -> bool:
    """Whether a connection-opening call may carry input: its target is not a constant.

    A call with no target argument kept by the graph (``*args``, ``**kwargs``) counts as
    dynamic, because it cannot be shown to be constant. Anything ``ast.literal_eval``
    accepts (a literal address, however spelled) is a fixed target and not a sink.
    """
    assert rule.target_arg is not None
    position, keywords = rule.target_arg
    value = edge.args[position] if len(edge.args) > position else next(
        (edge.kwargs[k] for k in keywords if k in edge.kwargs), None)
    if value is None:
        return bool(edge.args or edge.kwargs)
    try:
        ast.literal_eval(value)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return True
    return False


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
        if rule.query_arg is not None and (edge.ref or not _dynamic_query(rule, edge)):
            return None
        if rule.source_arg is not None and (edge.ref or not _dynamic_payload(edge, rule.source_arg)):
            return None
        if rule.target_arg is not None and (edge.ref or not _dynamic_address(rule, edge)):
            return None
        if rule.pattern_arg is not None and (edge.ref or not _regex_is_dos(rule, edge)):
            return None
        if rule.xml_mode is not None and not edge.ref and not _xml_entities_on(rule, edge):
            return None
        vuln_class, effect, access = rule.vuln_class, rule.effect, rule.access
        if not edge.ref and _is_write(rule, edge):
            (vuln_class, effect), access = WRITE_CLASS, "write"
        return SinkHit(node=edge.src, target=edge.dst, line=edge.line, category=rule.category,
                       vuln_class=vuln_class, effect=effect, access=access, joined_path=joined)
    if edge.kind == "unresolved" and "." in edge.text:
        method = edge.text.rsplit(".", 1)[1]
        if method in SQL_RUN_METHODS:
            # The receiver's type is unknown, so this is a weak hit, but a statement that is a
            # constant string still carries nothing.
            if _dynamic_query(_SQL_RULE, edge):
                return SinkHit(node=edge.src, target=edge.text, line=edge.line, category=_SQL_RULE.category,
                               vuln_class=_SQL_RULE.vuln_class, effect=SQL, access=_SQL_RULE.access, weak=True)
            return None
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
