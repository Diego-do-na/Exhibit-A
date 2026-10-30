"""Static call graph of a Python repository, built with the standard-library ``ast`` only.

Repository code is untrusted input. It is read as bytes and parsed; it is never imported,
compiled to bytecode or executed. Files are found with ``os.walk`` without following
symlinks, symlinked files are skipped, every file is opened with ``O_NOFOLLOW`` and must be
a regular file, vendored and hidden directories are skipped, and the file count, the size
of each file and the total size are capped.

Nodes are modules, classes, functions and methods, named ``module:qualname`` where the
qualname is the one CPython gives the code object (``Class.method``,
``outer.<locals>.inner``), so a graph node names the same thing as an oracle frame.

Edges are the calls the builder can resolve without guessing: names bound by imports
(absolute, relative, aliased, re-exported by a package), functions and classes of the same
or an enclosing scope, ``self.m()`` / ``cls.m()`` / ``super().m()`` through the class's
in-repository bases, module attributes (``mod.f()``), constructors (``Class()`` goes to
``Class.__init__``), methods on a value whose class is known (``x = Class(); x.m()``,
``self.attr = Class()`` then ``self.attr.m()``, ``Class().m()``, a parameter annotated with
a class), and functions handed to another call as an argument (callbacks, thread pools,
route tables). Calls that leave the repository are ``external`` edges to a dotted name
(``os.path.join``, ``pathlib.Path.read_text``). Every other call is recorded as an
``unresolved`` edge with its text: dynamic dispatch, ``getattr``, values of unknown type,
monkeypatching and framework magic are not guessed.
"""

from __future__ import annotations

import ast
import builtins
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from exhibit_a.schemas.graph import (
    CodeGraph,
    Decorator,
    GraphEdge,
    GraphNode,
    GraphStats,
    SkippedFile,
)

#: Directory names never descended into (dependencies, caches, VCS metadata). Every other
#: directory whose name starts with a dot is skipped as well.
SKIP_DIRS = frozenset({
    "node_modules", "site-packages", "dist-packages", "venv", ".venv", "__pycache__",
})
MAX_FILES = 5_000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 50_000_000
MAX_TEXT = 120
MAX_ARGS = 3
MAX_ARG_TEXT = 80
_MAX_REEXPORT_DEPTH = 8
_MAX_MRO_DEPTH = 16
_BUILTINS = frozenset(dir(builtins))
MODULE_QUALNAME = "<module>"
#: ``via`` marker of the calls made under ``if __name__ == "__main__":``.
MAIN_GUARD = "__main__"

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _text(node: ast.AST | None, limit: int = MAX_TEXT) -> str:
    if node is None:
        return ""
    try:
        text = ast.unparse(node)
    except (RecursionError, ValueError, AttributeError):
        return "<expr>"
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _chain(expr: ast.AST) -> list[str] | None:
    """``a.b.c`` as ``["a", "b", "c"]``; None when the base is not a plain name."""
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if not isinstance(expr, ast.Name):
        return None
    parts.append(expr.id)
    parts.reverse()
    return parts


def _child_blocks(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Statement lists nested in a compound statement (not in nested defs)."""
    blocks: list[list[ast.stmt]] = []
    for name in ("body", "orelse", "finalbody"):
        block = getattr(stmt, name, None)
        if isinstance(block, list):
            blocks.append(block)
    for handler in getattr(stmt, "handlers", []) or []:
        blocks.append(handler.body)
    for case in getattr(stmt, "cases", []) or []:
        blocks.append(case.body)
    return blocks


def _scope_statements(body: list[ast.stmt]) -> list[ast.stmt]:
    """Every statement of a scope body, compound ones included, nested defs not entered."""
    out: list[ast.stmt] = []
    stack = [list(body)]
    while stack:
        block = stack.pop()
        for stmt in block:
            out.append(stmt)
            if not isinstance(stmt, _DEFS):
                stack.extend(_child_blocks(stmt))
    return out


def _scope_expressions(stmts: list[ast.stmt]) -> list[ast.AST]:
    """Every AST node evaluated in this scope: nested def bodies are excluded, but their
    decorators, defaults and bases (evaluated here) are included; lambdas are included."""
    out: list[ast.AST] = []
    stack: list[ast.AST] = []
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.extend(stmt.decorator_list)
            stack.extend(d for d in stmt.args.defaults if d is not None)
            stack.extend(d for d in stmt.args.kw_defaults if d is not None)
        elif isinstance(stmt, ast.ClassDef):
            stack.extend(stmt.decorator_list)
            stack.extend(stmt.bases)
            stack.extend(k.value for k in stmt.keywords)
        else:
            for name, value in ast.iter_fields(stmt):
                if name in ("body", "orelse", "finalbody", "handlers", "cases"):
                    continue  # statement blocks are visited as their own statements
                if isinstance(value, ast.AST):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(v for v in value if isinstance(v, ast.AST))
            for handler in getattr(stmt, "handlers", []) or []:
                if handler.type is not None:
                    stack.append(handler.type)
            for case in getattr(stmt, "cases", []) or []:
                stack.append(case.pattern)
                if case.guard is not None:
                    stack.append(case.guard)
    while stack:
        node = stack.pop()
        out.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return out


def _is_main_guard(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.If) or not isinstance(stmt.test, ast.Compare):
        return False
    test = stmt.test
    if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
        return False
    sides = [test.left, test.comparators[0]]
    names = [s for s in sides if isinstance(s, ast.Name) and s.id == "__name__"]
    consts = [s for s in sides if isinstance(s, ast.Constant) and s.value == "__main__"]
    return bool(names and consts)


# -- discovery ------------------------------------------------------------------------------

def _read_regular(path: str, cap: int) -> tuple[bytes | None, str]:
    if os.path.islink(path):
        return None, "symlink"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return None, f"cannot open: {exc.strerror or exc}"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "not a regular file"
        if info.st_size > cap:
            return None, "file too large"
        chunks = []
        remaining = cap + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 16))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    except OSError as exc:
        return None, f"cannot read: {exc.strerror or exc}"
    finally:
        os.close(fd)
    if len(data) > cap:
        return None, "file too large"
    return data, ""


def discover(
    root: str | Path,
    *,
    max_files: int = MAX_FILES,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> tuple[list[tuple[str, bytes]], list[SkippedFile], bool]:
    """Python files under ``root`` as ``(relative posix path, bytes)``, deterministic order."""
    base = os.path.realpath(root)
    if not os.path.isdir(base):
        raise ValueError(f"not a directory: {root}")
    found: list[tuple[str, bytes]] = []
    skipped: list[SkippedFile] = []
    total = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = [
            d for d in sorted(dirnames)
            if d not in SKIP_DIRS and not d.startswith(".") and not d.endswith(".egg-info")
            and not os.path.islink(os.path.join(dirpath, d))
        ]
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            if len(found) >= max_files:
                truncated = True
                break
            data, why = _read_regular(full, max_file_bytes)
            if data is None:
                skipped.append(SkippedFile(file=rel, reason=why))
                continue
            if total + len(data) > max_total_bytes:
                truncated = True
                skipped.append(SkippedFile(file=rel, reason="total size cap"))
                break
            total += len(data)
            found.append((rel, data))
        if truncated:
            break
    return found, skipped, truncated


def module_names(rels: list[str]) -> dict[str, str]:
    """Import name of every file: its path from the top of its package chain.

    ``src/pkg/mod.py`` (``src`` holds no ``__init__.py``) is ``pkg.mod``. When two files
    would get the same name, both fall back to their full dotted path.
    """
    init_dirs = {rel.rsplit("/", 1)[0] if "/" in rel else "" for rel in rels
                 if rel.rsplit("/", 1)[-1] == "__init__.py"}

    def parts_of(rel: str) -> tuple[list[str], list[str]]:
        parts = rel[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
            return parts, parts
        return parts, parts[:-1]

    names: dict[str, str] = {}
    for rel in rels:
        parts, dirs = parts_of(rel)
        start = len(dirs)
        while start > 0 and "/".join(dirs[:start]) in init_dirs:
            start -= 1
        names[rel] = ".".join(parts[start:]) or "__init__"
    by_name: dict[str, list[str]] = {}
    for rel, name in names.items():
        by_name.setdefault(name, []).append(rel)
    taken = {name for name, rels_ in by_name.items() if len(rels_) == 1}
    for name, group in sorted(by_name.items()):
        if len(group) == 1:
            continue
        for rel in sorted(group):
            full = ".".join(parts_of(rel)[0]) or "__init__"
            if full in taken:
                full = rel  # last resort: unique, and never a valid import name
            names[rel] = full
            taken.add(full)
    return names


# -- model ----------------------------------------------------------------------------------

Type = tuple[str, str]  # ("class", class node id) or ("ext", dotted name)


@dataclass(frozen=True)
class _Res:
    kind: str  # node | external | module | none
    value: str = ""
    edge: str = ""
    cls: str = ""  # constructors: the class being built (value may be an inherited __init__)


_NONE = _Res("none")


@dataclass
class _Module:
    name: str
    rel: str
    tree: ast.Module
    lines: int
    scope: _Scope | None = None


@dataclass
class _Class:
    id: str
    node: ast.ClassDef
    scope: _Scope  # the class body scope; its parent is where the bases are evaluated
    methods: dict[str, str] = field(default_factory=dict)
    bases: list[str] = field(default_factory=list)
    attr_types: dict[str, Type | None] = field(default_factory=dict)


@dataclass
class _Scope:
    id: str
    kind: str  # module | class | function
    module: _Module
    parent: _Scope | None
    body: list[ast.stmt]
    defs: dict[str, str] = field(default_factory=dict)
    imports: dict[str, str] = field(default_factory=dict)
    star: list[str] = field(default_factory=list)
    locals: set[str] = field(default_factory=set)
    var_types: dict[str, Type | None] = field(default_factory=dict)
    cls: _Class | None = None  # the class of a method, or the class of a class scope
    self_name: str | None = None
    self_is_class: bool = False  # classmethods: the first parameter is the class itself
    fn: ast.AST | None = None


class _Builder:
    def __init__(self, files: list[tuple[str, bytes]]) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.classes: dict[str, _Class] = {}
        self.scopes: list[_Scope] = []
        self.modules: dict[str, _Module] = {}
        self.skipped: list[SkippedFile] = []
        self.edges: dict[tuple, GraphEdge] = {}
        self.method_cache: dict[tuple[str, str], str | None] = {}
        names = module_names([rel for rel, _ in files])
        for rel, data in files:
            try:
                tree = ast.parse(data, filename=rel)
            except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
                self.skipped.append(SkippedFile(file=rel, reason=f"parse error: {type(exc).__name__}"))
                continue
            self.modules[names[rel]] = _Module(names[rel], rel, tree, max(1, data.count(b"\n") + 1))

    # -- definitions --------------------------------------------------------------------

    def define(self) -> None:
        for name in sorted(self.modules):
            module = self.modules[name]
            mid = f"{name}:{MODULE_QUALNAME}"
            self.nodes[mid] = GraphNode(
                id=mid, kind="module", module=name, name=MODULE_QUALNAME, file=module.rel,
                line=1, start=1, end=module.lines,
            )
            scope = _Scope(mid, "module", module, None, module.tree.body)
            module.scope = scope
            self.scopes.append(scope)
            self._define_scope(scope, "")

    def _define_scope(self, scope: _Scope, prefix: str) -> None:
        pending = [(scope, prefix)]
        while pending:
            sc, pre = pending.pop()
            for stmt in _scope_statements(sc.body):
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    child = self._def_function(sc, pre, stmt)
                    pending.append((child, f"{child.id.split(':', 1)[1]}.<locals>."))
                elif isinstance(stmt, ast.ClassDef):
                    child = self._def_class(sc, pre, stmt)
                    pending.append((child, f"{child.id.split(':', 1)[1]}."))
                elif isinstance(stmt, ast.Import):
                    for alias in stmt.names:
                        if alias.asname:
                            sc.imports[alias.asname] = alias.name
                        else:
                            top = alias.name.split(".", 1)[0]
                            sc.imports[top] = top
                elif isinstance(stmt, ast.ImportFrom):
                    base = self._import_base(sc.module, stmt.module, stmt.level)
                    for alias in stmt.names:
                        if alias.name == "*":
                            if base:
                                sc.star.append(base)
                            continue
                        bound = alias.asname or alias.name
                        sc.imports[bound] = f"{base}.{alias.name}" if base else ""
                if sc.kind != "class":
                    sc.locals.update(_bound_names(stmt))

    def _import_base(self, module: _Module, name: str | None, level: int) -> str:
        if not level:
            return name or ""
        parts = module.name.split(".")
        package = parts if module.rel.endswith("__init__.py") else parts[:-1]
        if level - 1 > len(package):
            return ""
        package = package[: len(package) - (level - 1)]
        return ".".join([*package, *([name] if name else [])])

    def _add_node(self, node: GraphNode) -> GraphNode:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        # The same qualname defined twice (if/else branches, property setters): one node
        # whose span covers both definitions.
        merged = existing.model_copy(update={
            "start": min(existing.start, node.start), "end": max(existing.end, node.end),
        })
        self.nodes[node.id] = merged
        return merged

    def _def_function(self, sc: _Scope, pre: str, stmt: ast.FunctionDef | ast.AsyncFunctionDef) -> _Scope:
        qual = f"{pre}{stmt.name}"
        nid = f"{sc.module.name}:{qual}"
        args = stmt.args
        params = [a.arg for a in [*args.posonlyargs, *args.args]]
        if args.vararg:
            params.append(f"*{args.vararg.arg}")
        params.extend(a.arg for a in args.kwonlyargs)
        if args.kwarg:
            params.append(f"**{args.kwarg.arg}")
        decorators = [_decorator(d) for d in stmt.decorator_list]
        start = min([stmt.lineno, *(d.lineno for d in stmt.decorator_list)])
        self._add_node(GraphNode(
            id=nid, kind="method" if sc.kind == "class" else "function", module=sc.module.name,
            name=qual, file=sc.module.rel, line=stmt.lineno, start=start,
            end=stmt.end_lineno or stmt.lineno, is_async=isinstance(stmt, ast.AsyncFunctionDef),
            params=params, decorators=decorators,
        ))
        if sc.kind == "class":
            sc.defs.setdefault(stmt.name, nid)
        else:
            sc.defs[stmt.name] = nid
        child = _Scope(nid, "function", sc.module, sc, stmt.body, fn=stmt)
        positional = [a.arg for a in [*args.posonlyargs, *args.args]]
        child.locals.update(params_names(args))
        if sc.kind == "class" and sc.cls is not None:
            sc.cls.methods.setdefault(stmt.name, nid)
            child.cls = sc.cls
            if positional and not any(d.callee in ("staticmethod",) for d in decorators):
                child.self_name = positional[0]
                child.self_is_class = any(d.callee == "classmethod" for d in decorators)
        self.scopes.append(child)
        return child

    def _def_class(self, sc: _Scope, pre: str, stmt: ast.ClassDef) -> _Scope:
        qual = f"{pre}{stmt.name}"
        nid = f"{sc.module.name}:{qual}"
        start = min([stmt.lineno, *(d.lineno for d in stmt.decorator_list)])
        self._add_node(GraphNode(
            id=nid, kind="class", module=sc.module.name, name=qual, file=sc.module.rel,
            line=stmt.lineno, start=start, end=stmt.end_lineno or stmt.lineno,
            decorators=[_decorator(d) for d in stmt.decorator_list],
            bases=[_text(b) for b in stmt.bases],
        ))
        sc.defs[stmt.name] = nid
        child = _Scope(nid, "class", sc.module, sc, stmt.body)
        info = self.classes.get(nid)
        if info is None:
            info = _Class(nid, stmt, child)
            self.classes[nid] = info
        child.cls = info
        self.scopes.append(child)
        return child

    # -- name resolution ----------------------------------------------------------------

    def _lookup(self, scope: _Scope, name: str) -> tuple[str, object] | None:
        sc: _Scope | None = scope
        first = True
        while sc is not None:
            if sc.kind == "class" and not first:
                sc = sc.parent  # class bodies are not visible from their methods
                continue
            first = False
            if name in sc.var_types:
                t = sc.var_types[name]
                return ("type", t) if t is not None else None
            if name in sc.defs:
                return "def", sc.defs[name]
            if name in sc.imports:
                target = sc.imports[name]
                return ("import", target) if target else None
            if name in sc.locals:
                return None  # a local of unknown type shadows anything outside
            if sc.kind == "module":
                for star in sc.star:
                    res = self._resolve_dotted([*star.split("."), name], 1)
                    if res.kind == "node":
                        return "def", res.value
                break
            sc = sc.parent
        if name in _BUILTINS:
            return "builtin", name
        return None

    def _module_of(self, parts: list[str]) -> tuple[_Module | None, list[str]]:
        for i in range(len(parts), 0, -1):
            module = self.modules.get(".".join(parts[:i]))
            if module is not None:
                return module, parts[i:]
        return None, parts

    def _resolve_dotted(self, parts: list[str], depth: int = 0) -> _Res:
        module, rest = self._module_of(parts)
        if module is None:
            return _Res("external", ".".join(parts), "external")
        if not rest:
            return _Res("module", module.name)
        sc = module.scope
        assert sc is not None
        name = rest[0]
        if name in sc.defs:
            return self._member(sc.defs[name], rest[1:], "attr")
        if name in sc.imports and sc.imports[name] and depth < _MAX_REEXPORT_DEPTH:
            return self._resolve_dotted([*sc.imports[name].split("."), *rest[1:]], depth + 1)
        t = sc.var_types.get(name)
        if t is not None:
            return self._on_type(t, rest[1:])
        if depth < _MAX_REEXPORT_DEPTH:
            for star in sc.star:
                res = self._resolve_dotted([*star.split("."), *rest], depth + 1)
                if res.kind == "node":
                    return res
        return _NONE

    def _member(self, nid: str, rest: list[str], edge: str) -> _Res:
        node = self.nodes[nid]
        if not rest:
            if node.kind == "class":
                return self._ctor(nid)
            return _Res("node", nid, edge)
        if node.kind == "class" and len(rest) == 1:
            method = self._method(nid, rest[0])
            return _Res("node", method, "attr") if method else _NONE
        return _NONE

    def _ctor(self, class_id: str) -> _Res:
        init = self._method(class_id, "__init__")
        return _Res("node", init or class_id, "ctor", class_id)

    def _mro(self, class_id: str) -> list[str]:
        order: list[str] = []
        stack = [(class_id, 0)]
        while stack:
            cid, depth = stack.pop(0)
            if cid in order or depth > _MAX_MRO_DEPTH:
                continue
            order.append(cid)
            info = self.classes.get(cid)
            if info is not None:
                stack.extend((b, depth + 1) for b in info.bases)
        return order

    def _method(self, class_id: str, name: str, skip_self: bool = False) -> str | None:
        key = (class_id + ("!" if skip_self else ""), name)
        if key in self.method_cache:
            return self.method_cache[key]
        found = None
        for cid in self._mro(class_id)[1 if skip_self else 0:]:
            info = self.classes.get(cid)
            if info is not None and name in info.methods:
                found = info.methods[name]
                break
        self.method_cache[key] = found
        return found

    def _attr_type(self, class_id: str, attr: str) -> Type | None:
        for cid in self._mro(class_id):
            info = self.classes.get(cid)
            if info is not None and attr in info.attr_types:
                return info.attr_types[attr]
        return None

    def _on_type(self, t: Type, attrs: list[str]) -> _Res:
        kind, value = t
        if kind == "ext":
            return _Res("external", ".".join([value, *attrs]) if attrs else value, "external")
        if not attrs:
            method = self._method(value, "__call__")
            return _Res("node", method, "instance") if method else _NONE
        if len(attrs) == 1:
            method = self._method(value, attrs[0])
            if method:
                return _Res("node", method, "instance")
        inner = self._attr_type(value, attrs[0])
        if inner is not None:
            return self._on_type(inner, attrs[1:])
        return _NONE

    def resolve(self, scope: _Scope, func: ast.AST, *, reference: bool = False) -> _Res:
        """What ``func`` names in ``scope``: a node, an external name, or nothing."""
        res = self._resolve(scope, func, reference)
        if reference and res.edge == "ctor":
            return _Res("node", res.cls, "ref")
        return res

    def _self_scope(self, scope: _Scope, head: str) -> _Scope | None:
        """The method whose ``self`` (or ``cls``) ``head`` names, closures included."""
        sc: _Scope | None = scope
        while sc is not None and sc.kind == "function":
            if sc.self_name == head and sc.cls is not None:
                return sc
            if head in sc.locals:
                return None
            sc = sc.parent
        return None

    def _resolve(self, scope: _Scope, func: ast.AST, reference: bool) -> _Res:
        chain = _chain(func)
        if chain is not None:
            head, attrs = chain[0], chain[1:]
            owner = self._self_scope(scope, head)
            if owner is not None and owner.cls is not None:
                cls_id = owner.cls.id
                if not attrs:
                    if reference:
                        return _NONE
                    if owner.self_is_class:
                        return self._ctor(cls_id)
                    return self._on_type(("class", cls_id), [])
                if len(attrs) == 1:
                    method = self._method(cls_id, attrs[0])
                    if method:
                        return _Res("node", method, "method")
                t = self._attr_type(cls_id, attrs[0])
                if t is not None and not (reference and len(attrs) == 1):
                    return self._on_type(t, attrs[1:])
                return _NONE
            found = self._lookup(scope, head)
            if found is None:
                return _NONE
            kind, value = found
            if kind == "type":
                if reference and not attrs:
                    return _NONE  # an instance, not a function
                res = self._on_type(value, attrs)  # type: ignore[arg-type]
                return res
            if kind == "def":
                node = self.nodes[value]  # type: ignore[index]
                if reference and not attrs:
                    return _Res("node", node.id, "ref")
                return self._member(node.id, attrs, "call" if not attrs else "attr")
            if kind == "import":
                res = self._resolve_dotted([*str(value).split("."), *attrs])
                if res.kind == "node" and res.edge == "attr" and not attrs:
                    return _Res("node", res.value, "call")
                return res
            if kind == "builtin":
                return _Res("external", ".".join(["builtins", *chain]), "external")
            return _NONE
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call):
            inner = func.value
            if isinstance(inner.func, ast.Name) and inner.func.id == "super" and scope.cls is not None:
                method = self._method(scope.cls.id, func.attr, skip_self=True)
                return _Res("node", method, "method") if method else _NONE
            t = self.type_of_call(scope, inner)
            if t is not None:
                return self._on_type(t, [func.attr])
        return _NONE

    def type_of_call(self, scope: _Scope, call: ast.Call) -> Type | None:
        res = self.resolve(scope, call.func)
        if res.kind == "node" and res.edge == "ctor":
            return ("class", res.cls)
        if res.kind == "external":
            return ("ext", res.value)
        return None

    def type_of_annotation(self, scope: _Scope, annotation: ast.AST | None) -> Type | None:
        if annotation is None or _chain(annotation) is None:
            return None
        res = self.resolve(scope, annotation, reference=True)
        if res.kind == "node" and self.nodes[res.value].kind == "class":
            return ("class", res.value)
        if res.kind == "external" and not res.value.startswith("builtins."):
            return ("ext", res.value)
        return None

    # -- types ----------------------------------------------------------------------------

    def infer_types(self) -> None:
        for info in sorted(self.classes.values(), key=lambda c: c.id):
            outer = info.scope.parent
            assert outer is not None
            for base in info.node.bases:
                if _chain(base) is None:
                    continue
                res = self.resolve(outer, base, reference=True)
                if res.kind == "node" and self.nodes[res.value].kind == "class" and res.value != info.id:
                    info.bases.append(res.value)
        self.method_cache.clear()
        for sc in self.scopes:
            if sc.kind in ("module", "function"):
                self._infer_scope_types(sc)
        for info in sorted(self.classes.values(), key=lambda c: c.id):
            self._infer_attr_types(info)
        self.method_cache.clear()

    def _infer_scope_types(self, sc: _Scope) -> None:
        seen: dict[str, set[Type | None]] = {}
        if isinstance(sc.fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = sc.fn.args
            for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
                if arg.annotation is not None and arg.arg != sc.self_name:
                    seen.setdefault(arg.arg, set()).add(self.type_of_annotation(sc.parent or sc, arg.annotation))
        for stmt in _scope_statements(sc.body):
            try:
                assigned = self._assigned_types(sc, stmt)
            except RecursionError:
                assigned = [(name, None) for name in _bound_names(stmt)]
            for name, t in assigned:
                seen.setdefault(name, set()).add(t)
        for name, types in seen.items():
            if name in sc.defs or name in sc.imports:
                continue
            sc.var_types[name] = next(iter(types)) if len(types) == 1 else None

    def _assigned_types(self, sc: _Scope, stmt: ast.stmt) -> list[tuple[str, Type | None]]:
        out: list[tuple[str, Type | None]] = []
        if isinstance(stmt, ast.Assign):
            t = self.type_of_call(sc, stmt.value) if isinstance(stmt.value, ast.Call) else None
            for target in stmt.targets:
                for name in _target_names(target):
                    out.append((name, t if isinstance(target, ast.Name) else None))
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            t = self.type_of_annotation(sc, stmt.annotation)
            if t is None and isinstance(stmt.value, ast.Call):
                t = self.type_of_call(sc, stmt.value)
            out.append((stmt.target.id, t))
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is None:
                    continue
                t = None
                if isinstance(item.optional_vars, ast.Name) and isinstance(item.context_expr, ast.Call):
                    t = self.type_of_call(sc, item.context_expr)
                for name in _target_names(item.optional_vars):
                    out.append((name, t))
        else:
            for name in _bound_names(stmt):
                out.append((name, None))
        return out

    def _infer_attr_types(self, info: _Class) -> None:
        seen: dict[str, set[Type | None]] = {}
        for stmt in info.node.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                seen.setdefault(stmt.target.id, set()).add(self.type_of_annotation(info.scope, stmt.annotation))
        for sc in self.scopes:
            if sc.kind != "function" or sc.cls is not info or sc.parent is not info.scope or not sc.self_name:
                continue
            for stmt in _scope_statements(sc.body):
                targets: list[ast.AST] = []
                value: ast.AST | None = None
                annotation: ast.AST | None = None
                if isinstance(stmt, ast.Assign):
                    targets, value = stmt.targets, stmt.value
                elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                    targets, value = [stmt.target], stmt.value
                    annotation = getattr(stmt, "annotation", None)
                for target in targets:
                    if (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                            and target.value.id == sc.self_name):
                        t = self.type_of_annotation(sc, annotation) if annotation is not None else None
                        if t is None and isinstance(value, ast.Call) and isinstance(stmt, ast.Assign | ast.AnnAssign):
                            t = self.type_of_call(sc, value)
                        seen.setdefault(target.attr, set()).add(t)
        for name, types in seen.items():
            info.attr_types[name] = next(iter(types)) if len(types) == 1 else None

    # -- edges ----------------------------------------------------------------------------

    def _edge(self, edge: GraphEdge) -> None:
        key = (edge.src, edge.dst, edge.kind, edge.text, edge.via, edge.ref,
               tuple(edge.args), tuple(sorted(edge.kwargs.items())))
        old = self.edges.get(key)
        if old is None or edge.line < old.line:
            self.edges[key] = edge

    def link(self) -> None:
        for sc in self.scopes:
            stmts = _scope_statements(sc.body)
            guarded: set[int] = set()
            if sc.kind == "module":
                for stmt in sc.body:
                    if _is_main_guard(stmt):
                        for inner in _scope_statements(stmt.body):
                            guarded.update(id(n) for n in _scope_expressions([inner]))
            for expr in _scope_expressions(stmts):
                if isinstance(expr, ast.Call):
                    try:
                        self._link_call(sc, expr, MAIN_GUARD if id(expr) in guarded else "")
                    except RecursionError:
                        self._edge(GraphEdge(src=sc.id, dst="", kind="unresolved", line=expr.lineno,
                                             text="<too deep>"))

    def _link_call(self, sc: _Scope, call: ast.Call, via: str) -> None:
        res = self.resolve(sc, call.func)
        text = _text(call.func)
        line = call.lineno
        if res.kind == "node":
            self._edge(GraphEdge(src=sc.id, dst=res.value, kind=res.edge, line=line, text=text, via=via))  # type: ignore[arg-type]
        elif res.kind == "external":
            self._edge(GraphEdge(
                src=sc.id, dst=res.value, kind="external", line=line, text=text, via=via,
                args=[_text(a, MAX_ARG_TEXT) for a in call.args[:MAX_ARGS]],
                kwargs={k.arg: _text(k.value, MAX_ARG_TEXT) for k in call.keywords if k.arg}
                if len(call.keywords) <= 16 else {},
            ))
        else:
            self._edge(GraphEdge(src=sc.id, dst="", kind="unresolved", line=line, text=text, via=via))
        for arg in [*call.args, *(k.value for k in call.keywords)]:
            if isinstance(arg, ast.Starred):
                arg = arg.value
            if _chain(arg) is None:
                continue
            ref = self.resolve(sc, arg, reference=True)
            if ref.kind == "node" and self.nodes[ref.value].kind in ("function", "method", "class"):
                self._edge(GraphEdge(src=sc.id, dst=ref.value, kind="ref", line=arg.lineno,
                                     text=_text(arg), via=text))
            elif ref.kind == "external" and _worth_a_ref(arg, ref.value):
                self._edge(GraphEdge(src=sc.id, dst=ref.value, kind="external", line=arg.lineno,
                                     text=_text(arg), via=text, ref=True))

    def result(self, skipped: list[SkippedFile], truncated: bool) -> CodeGraph:
        nodes = sorted(self.nodes.values(), key=lambda n: n.id)
        edges = sorted(self.edges.values(), key=lambda e: (e.src, e.line, e.kind, e.dst, e.text, e.via, e.ref))
        resolved = sum(1 for e in edges if e.kind not in ("external", "unresolved"))
        external = sum(1 for e in edges if e.kind == "external")
        return CodeGraph(
            files=sorted(m.rel for m in self.modules.values()),
            nodes=nodes,
            edges=edges,
            skipped=sorted([*skipped, *self.skipped], key=lambda s: s.file),
            truncated=truncated,
            stats=GraphStats(
                files=len(self.modules), nodes=len(nodes), edges=len(edges), resolved=resolved,
                external=external, unresolved=len(edges) - resolved - external,
            ),
        )


def _worth_a_ref(arg: ast.AST, dotted: str) -> bool:
    """An external name handed to a call that could stand for a function: not a bare module
    alias (``getattr(os, n)``) and not a builtin class (``isinstance(x, tuple)``)."""
    if dotted.startswith("builtins."):
        return not isinstance(getattr(builtins, dotted.split(".", 1)[1], None), type)
    return isinstance(arg, ast.Attribute)


def params_names(args: ast.arguments) -> set[str]:
    names = {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _target_names(elt)]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _bound_names(stmt: ast.stmt) -> list[str]:
    """Names a statement binds in its own scope (not defs, not imports)."""
    names: list[str] = []
    if isinstance(stmt, ast.Assign):
        for target in stmt.targets:
            names.extend(_target_names(target))
    elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        names.extend(_target_names(stmt.target))
    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
        names.extend(_target_names(stmt.target))
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            if item.optional_vars is not None:
                names.extend(_target_names(item.optional_vars))
    elif isinstance(stmt, ast.Try) or (hasattr(ast, "TryStar") and isinstance(stmt, getattr(ast, "TryStar"))):
        names.extend(h.name for h in stmt.handlers if h.name)
    for node in ast.walk(stmt) if not isinstance(stmt, _DEFS) else ():
        if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            names.append(node.target.id)
    return names


def _decorator(expr: ast.expr) -> Decorator:
    if isinstance(expr, ast.Call):
        path = None
        if expr.args and isinstance(expr.args[0], ast.Constant) and isinstance(expr.args[0].value, str):
            path = expr.args[0].value[:MAX_TEXT]
        return Decorator(callee=_text(expr.func), call=True, path=path)
    return Decorator(callee=_text(expr), call=False)


def build_graph(
    root: str | Path,
    *,
    max_files: int = MAX_FILES,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> CodeGraph:
    """Build the call graph of every Python file under ``root`` (parsed, never executed)."""
    files, skipped, truncated = discover(
        root, max_files=max_files, max_file_bytes=max_file_bytes, max_total_bytes=max_total_bytes
    )
    builder = _Builder(files)
    builder.define()
    builder.infer_types()
    builder.link()
    return builder.result(skipped, truncated)
