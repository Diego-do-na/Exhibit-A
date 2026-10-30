"""Every markdown link and every cited docs path resolves to a real file.

After the A-20 docs restructure (docs grouped into oracle/, ci/, bench/,
security/, design/ and reference/), any stale relative link or stale
``docs/...`` citation means a moved document lost its readers. This test walks
every ``*.md`` file in the repository, extracts

- relative markdown links ``[text](target)`` pointing at ``.md`` files, and
- every ``docs/...`` path cited anywhere in markdown (backticked or bare),

and requires each one to resolve to an existing file.

``docs/common.md`` is exempt: it is the append-only shared log and its
historical entries name the paths documents had when those lines were
written; rewriting history there is forbidden, so old citations stay.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Skip generated/vendored trees that are not part of the deliverable docs.
SKIPPED_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".hg"}

# The append-only log keeps historical paths; see the module docstring.
EXEMPT_FILES = {"docs/common.md"}

INLINE_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
# docs/<name>.md with an optional ../ prefix and optional :line[,line] suffix.
DOCS_PATH_RE = re.compile(r"((?:\.\./)*docs/[A-Za-z0-9_.\-/]+\.md)(:\d[\d,]*)?")


def _iter_markdown_files() -> list[pathlib.Path]:
    files = []
    for path in sorted(ROOT.rglob("*.md")):
        if any(part in SKIPPED_DIRS for part in path.parts):
            continue
        files.append(path)
    assert files, "no markdown files found"
    return files


def _resolve(from_file: pathlib.Path, cited: str) -> pathlib.Path:
    cited = cited.split("#", 1)[0].strip()
    candidate = pathlib.Path(cited)
    if candidate.is_absolute():
        return ROOT / cited.lstrip("/")
    if cited.startswith("docs/"):
        return ROOT / cited
    return (from_file.parent / cited).resolve()


def _link_targets(text: str) -> list[str]:
    targets = []
    for match in INLINE_LINK_RE.finditer(text):
        target = match.group(1).strip().strip("<>")
        if not target or target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = target.split("#", 1)[0].strip()
        if target.endswith(".md"):
            targets.append(target)
    return targets


def _docs_citations(text: str) -> list[str]:
    return [match.group(1) for match in DOCS_PATH_RE.finditer(text)]


def _check_file(path: pathlib.Path) -> list[str]:
    broken = []
    rel = path.relative_to(ROOT).as_posix()
    if rel in EXEMPT_FILES:
        return broken
    text = path.read_text(encoding="utf-8")
    for target in _link_targets(text):
        if not _resolve(path, target).is_file():
            broken.append(f"{rel}: link target does not exist: {target}")
    for cited in _docs_citations(text):
        if not _resolve(path, cited).is_file():
            broken.append(f"{rel}: cited docs path does not exist: {cited}")
    return broken


def test_every_markdown_link_and_docs_citation_resolves():
    broken = []
    for path in _iter_markdown_files():
        broken.extend(_check_file(path))
    assert not broken, "broken doc links:\n" + "\n".join(broken)


def test_docs_index_covers_every_document():
    index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    missing = []
    for path in _iter_markdown_files():
        rel = path.relative_to(ROOT).as_posix()
        if not rel.startswith("docs/") or rel in EXEMPT_FILES:
            continue
        # The index links relative to docs/ (e.g. "oracle/foo.md"), so
        # accept either the repo-root or the docs-relative spelling.
        within_docs = rel[len("docs/"):]
        if rel not in index and within_docs not in index:
            missing.append(rel)
    assert not missing, "docs not listed in docs/README.md:\n" + "\n".join(missing)
