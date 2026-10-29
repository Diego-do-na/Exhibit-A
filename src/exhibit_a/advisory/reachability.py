"""Static, best-effort reachability HINT for an advisory.

It answers two narrow questions by reading the project's Python source with `ast`
(never importing or executing it):

1. Does any project file import the vulnerable package?
2. Does any project file mention a symbol the advisory names as affected?

This is a hint, not reachability. Known false positives: an import that is never called
on the vulnerable path, a local name that merely shares the symbol's name, dead code,
test-only imports. Known false negatives: dynamic imports (``importlib``,
``__import__``), a distribution whose import name differs from its project name and is
not in `import_names`, access through re-exports or another dependency, code generated
at runtime, and non-Python entry points (templates, C extensions, config).
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path

from ..schemas.advisory import ReachabilityHint

_SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__",
              "site-packages", "build", "dist", ".tox", ".nox", ".mypy_cache"}
MAX_FILES = 5_000
MAX_FILE_BYTES = 1_000_000

NOTES = [
    "hint only: an import or a name match does not show the vulnerable code is reachable",
    "false positives: unused imports, dead code, unrelated names that collide",
    "false negatives: dynamic imports, re-exports, import name differing from project name",
]


@dataclass
class _FileFacts:
    imports: list[tuple[str, int]]  # dotted module names imported, with line
    names: list[tuple[str, int]]  # identifiers and attribute names used, with line


def default_import_names(package: str) -> list[str]:
    """Guess the import name of a normalized project name (``foo-bar`` -> ``foo_bar``)."""
    return [package.replace("-", "_")]


def _facts(tree: ast.AST) -> _FileFacts:
    imports: list[tuple[str, int]] = []
    names: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imports.append((node.module, node.lineno))
            for alias in node.names:
                imports.append((f"{node.module}.{alias.name}", node.lineno))
                names.append((alias.name, node.lineno))
        elif isinstance(node, ast.Name):
            names.append((node.id, node.lineno))
        elif isinstance(node, ast.Attribute):
            names.append((node.attr, node.lineno))
    return _FileFacts(imports, names)


def _python_files(root: Path, truncated: list[bool]):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in _SKIP_DIRS and not d.startswith("."))
        for filename in sorted(filenames):
            if filename.endswith(".py"):
                count += 1
                if count > MAX_FILES:
                    truncated.append(True)
                    return
                yield Path(dirpath) / filename


def reachability_hint(root: str | os.PathLike, package: str, symbols: list[str] | tuple[str, ...],
                      import_names: list[str] | None = None) -> ReachabilityHint:
    """Scan `root` for imports of `package` and mentions of `symbols` (dotted names)."""
    root = Path(root)
    modules = import_names or default_import_names(package)
    import_sites: list[str] = []
    symbol_hits: dict[str, list[str]] = {}
    scanned = skipped = 0
    notes = list(NOTES)
    truncated: list[bool] = []
    for path in _python_files(root, truncated):
        rel = path.relative_to(root).as_posix()
        try:
            if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                skipped += 1
                continue
            tree = ast.parse(path.read_bytes(), filename=rel)
        except (OSError, SyntaxError, ValueError):
            skipped += 1
            continue
        scanned += 1
        facts = _facts(tree)
        imported_here = False
        for module, line in facts.imports:
            if any(module == m or module.startswith(m + ".") for m in modules):
                import_sites.append(f"{rel}:{line}")
                imported_here = True
        if not imported_here:
            continue  # a bare name match in a file that never imports the package is noise
        for symbol in symbols:
            leaf = symbol.rsplit(".", 1)[-1]
            sites = [f"{rel}:{line}" for name, line in facts.names if name == leaf]
            sites += [f"{rel}:{line}" for module, line in facts.imports
                      if module == symbol or module.startswith(symbol + ".")]
            if sites:
                symbol_hits.setdefault(symbol, []).extend(sites)
    if truncated:
        notes.append(f"stopped after {MAX_FILES} files; result is partial")
    if not symbols:
        notes.append("advisory lists no affected symbols; only the package import was checked")
    return ReachabilityHint(
        package_imported=bool(import_sites),
        import_sites=sorted(set(import_sites)),
        symbols_listed=list(symbols),
        symbols_referenced=sorted(symbol_hits),
        symbol_sites=sorted({s for sites in symbol_hits.values() for s in sites}),
        files_scanned=scanned,
        files_skipped=skipped,
        notes=notes,
    )
