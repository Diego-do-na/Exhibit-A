"""Pull requests and authors for the dashboard, always from the chosen source.

GitHub sources list PRs with ``gh pr list --state all`` (cached). Author kind
is derived, never guessed: a ``[bot]`` suffix or GitHub ``is_bot``, Co-authored-by
trailers, and an optional ``.exhibit-a/authors.yml``. Anything else is
``unclassified``. Local sources have no GitHub PR list, so the page shows the
command that produces one. Run models, costs and tokens come from recorded
ledgers and are attached by pull-request number when a run recorded one.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, RootModel, ValidationError

KIND_BOT = "bot"
KIND_HUMAN = "human"
KIND_UNCLASSIFIED = "unclassified"
KINDS = (KIND_BOT, KIND_HUMAN, KIND_UNCLASSIFIED)

#: Deterministic palette; a login always maps to the same chip colour.
AUTHOR_PALETTE = (
    "#0f2557",
    "#2c4fc4",
    "#6a8fd8",
    "#9aa3e0",
    "#4b3fa0",
    "#b7834f",
    "#d9b98f",
    "#7f97b8",
    "#c3cbd8",
    "#4a5873",
)

PR_LIST_COMMAND = "gh pr list --state all"
AUTHORS_YML = ".exhibit-a/authors.yml"
MAX_PRS = 100
# Nested ``commits`` / ``files`` connections on ``gh pr list --json`` blow the
# GitHub GraphQL node cap on repos with many PRs. The list stays shallow; a
# follow-up query (``PR_ENRICH_QUERY``) loads a bounded page of each.
PR_JSON_FIELDS = (
    "number,title,author,createdAt,updatedAt,additions,deletions,"
    "changedFiles,url,state,mergedAt,headRefName,baseRefName"
)
PR_ENRICH_QUERY = (
    "query($owner: String!, $name: String!) {"
    " repository(owner: $owner, name: $name) {"
    "  pullRequests(first: 100, orderBy: {field: UPDATED_AT, direction: DESC}) {"
    "   nodes {"
    "    number"
    "    commits(first: 8) { nodes { commit { messageHeadline messageBody } } }"
    "    files(first: 20) { nodes { path additions deletions } }"
    "   }"
    "  }"
    " }"
    "}"
)

_COAUTHOR_RE = re.compile(
    r"^Co-authored-by:\s*(.+?)\s*<([^>]+)>\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_NOREPLY_RE = re.compile(
    r"^(?:\d+\+)?([^@]+?)@users\.noreply\.github\.com$",
    re.IGNORECASE,
)
_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}\Z")


# -- gh JSON (untrusted) -----------------------------------------------------------------


class _GhAuthor(BaseModel):
    model_config = ConfigDict(extra="ignore")

    login: str = Field(default="", max_length=100)
    is_bot: bool = False
    name: str | None = Field(default=None, max_length=200)


class _GhCommitAuthor(BaseModel):
    model_config = ConfigDict(extra="ignore")

    login: str = Field(default="", max_length=100)
    name: str | None = Field(default=None, max_length=200)
    email: str | None = Field(default=None, max_length=200)


class _GhCommit(BaseModel):
    model_config = ConfigDict(extra="ignore")

    messageHeadline: str = Field(default="", max_length=500)
    messageBody: str = Field(default="", max_length=8000)
    authors: list[_GhCommitAuthor] = Field(default_factory=list, max_length=20)


class _GhFile(BaseModel):
    model_config = ConfigDict(extra="ignore")

    path: str = Field(default="", max_length=400)
    additions: int = Field(default=0, ge=0)
    deletions: int = Field(default=0, ge=0)


class _GhPull(BaseModel):
    model_config = ConfigDict(extra="ignore")

    number: int = Field(ge=1)
    title: str = Field(default="", max_length=500)
    author: _GhAuthor | None = None
    createdAt: str = Field(default="", max_length=64)
    updatedAt: str = Field(default="", max_length=64)
    additions: int = Field(default=0, ge=0)
    deletions: int = Field(default=0, ge=0)
    changedFiles: int = Field(default=0, ge=0)
    commits: list[_GhCommit] = Field(default_factory=list, max_length=50)
    url: str = Field(default="", max_length=500)
    state: str = Field(default="", max_length=32)
    mergedAt: str | None = Field(default=None, max_length=64)
    headRefName: str = Field(default="", max_length=255)
    baseRefName: str = Field(default="", max_length=255)
    files: list[_GhFile] = Field(default_factory=list, max_length=30)


class _GhPullList(RootModel[list[_GhPull]]):
    root: list[_GhPull] = Field(default_factory=list, max_length=200)


# -- classification ----------------------------------------------------------------------


def parse_authors_yml(text: str) -> dict[str, str]:
    """Parse a tiny ``login: human|bot`` mapping. Unknown lines are ignored."""
    mapping: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        login = key.strip().strip("'\"")
        kind = val.strip().strip("'\"").lower()
        if login and kind in (KIND_BOT, KIND_HUMAN):
            mapping[login] = kind
    return mapping


def author_color(login: str) -> str:
    """Stable colour for a login; the same name always gets the same chip."""
    acc = 0
    for char in login or "":
        acc = (acc * 33 + ord(char)) & 0xFFFFFFFF
    return AUTHOR_PALETTE[acc % len(AUTHOR_PALETTE)]


def classify_author(
    login: str,
    *,
    is_bot: bool = False,
    mapping: dict[str, str] | None = None,
) -> str:
    """Return ``bot``, ``human`` or ``unclassified``. Never guesses human."""
    name = (login or "").strip()
    if not name:
        return KIND_UNCLASSIFIED
    table = mapping or {}
    mapped = table.get(name) or table.get(name.lower())
    if mapped in (KIND_BOT, KIND_HUMAN):
        return mapped
    if is_bot or name.lower().endswith("[bot]"):
        return KIND_BOT
    return KIND_UNCLASSIFIED


def parse_coauthors(message: str) -> list[tuple[str, bool]]:
    """``(login, is_bot)`` pairs from Co-authored-by trailers in a commit body."""
    found: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for match in _COAUTHOR_RE.finditer(message or ""):
        name = match.group(1).strip()
        email = match.group(2).strip()
        login = name
        noreply = _NOREPLY_RE.match(email)
        if noreply:
            login = noreply.group(1)
        bot = "[bot]" in name.lower() or "[bot]" in email.lower() or "[bot]" in login.lower()
        if bot and not login.lower().endswith("[bot]"):
            login = f"{login}[bot]"
        key = login.lower()
        if not login or key in seen:
            continue
        seen.add(key)
        found.append((login, bot))
    return found


def _pr_url(repo: str, number: int) -> str:
    if _REPO_RE.match(repo) and number >= 1:
        return f"https://github.com/{repo}/pull/{number}"
    return ""


def _area(files: Sequence[_GhFile]) -> str:
    for item in files:
        path = (item.path or "").strip().lstrip("/")
        if path:
            return path.split("/")[0] if "/" in path else path
    return ""


def parse_pr_list(raw: bytes, *, repo: str = "", mapping: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Validate ``gh pr list --json`` bytes into dashboard pull-request rows."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("pull request list is not valid UTF-8") from exc
    try:
        parsed = _GhPullList.model_validate_json(text)
    except ValidationError as exc:
        raise ValueError("pull request list does not match the expected schema") from exc
    table = mapping or {}
    rows: list[dict[str, Any]] = []
    for item in parsed.root[:MAX_PRS]:
        author = item.author or _GhAuthor()
        login = (author.login or "").strip()
        kind = classify_author(login, is_bot=author.is_bot, mapping=table)
        coauthors: list[dict[str, str]] = []
        seen_co = {login.lower()} if login else set()
        for commit in item.commits:
            body = "\n".join(part for part in (commit.messageHeadline, commit.messageBody) if part)
            for name, is_bot in parse_coauthors(body):
                if name.lower() in seen_co:
                    continue
                seen_co.add(name.lower())
                coauthors.append({
                    "login": name[:100],
                    "kind": classify_author(name, is_bot=is_bot, mapping=table),
                    "color": author_color(name),
                })
        state = (item.state or "").upper()
        if item.mergedAt and state not in {"MERGED", "CLOSED"}:
            state = "MERGED"
        files = [f.path for f in item.files if f.path][:20]
        rows.append({
            "number": item.number,
            "id": str(item.number),
            "title": item.title,
            "author": login,
            "author_kind": kind,
            "author_color": author_color(login) if login else AUTHOR_PALETTE[-1],
            "created_at": item.createdAt,
            "updated_at": item.updatedAt,
            "merged_at": item.mergedAt or "",
            "state": state,
            "additions": item.additions,
            "deletions": item.deletions,
            "changed_files": item.changedFiles or len(files),
            "commits": len(item.commits),
            "head": item.headRefName,
            "base": item.baseRefName,
            "url": _pr_url(repo, item.number),
            "coauthors": coauthors,
            "area": _area(item.files),
            "files": files,
            "models": [],
            "cost_usd": None,
            "tokens_in": None,
            "tokens_out": None,
            "proven": 0,
            "run_id": "",
            "runs": [],
        })
    return rows


def enrich_pr_rows(
    rows: list[dict[str, Any]],
    payload: Any,
    *,
    mapping: dict[str, str] | None = None,
) -> None:
    """Fill Co-authored-by trailers and file paths from a bounded GraphQL page."""
    nodes = (
        ((payload or {}).get("data") or {}).get("repository") or {}
    ).get("pullRequests", {})
    if isinstance(nodes, dict):
        nodes = nodes.get("nodes")
    if not isinstance(nodes, list):
        return
    by_num = {int(row["number"]): row for row in rows}
    table = mapping or {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        number = node.get("number")
        row = by_num.get(number) if isinstance(number, int) else None
        if row is None:
            continue
        commits = ((node.get("commits") or {}).get("nodes") or [])
        if isinstance(commits, list) and commits:
            row["commits"] = len(commits)
            seen = {str(row.get("author") or "").lower()} if row.get("author") else set()
            seen.discard("")
            coauthors: list[dict[str, str]] = list(row.get("coauthors") or [])
            for extra in coauthors:
                seen.add(str(extra.get("login") or "").lower())
            for item in commits:
                commit = (item or {}).get("commit") if isinstance(item, dict) else {}
                if not isinstance(commit, dict):
                    continue
                body = "\n".join(
                    part for part in (commit.get("messageHeadline"), commit.get("messageBody")) if part
                )
                for name, is_bot in parse_coauthors(body):
                    if name.lower() in seen:
                        continue
                    seen.add(name.lower())
                    coauthors.append({
                        "login": name[:100],
                        "kind": classify_author(name, is_bot=is_bot, mapping=table),
                        "color": author_color(name),
                    })
            row["coauthors"] = coauthors
        files = ((node.get("files") or {}).get("nodes") or [])
        if isinstance(files, list) and files:
            paths = [
                str(item.get("path") or "")[:400]
                for item in files
                if isinstance(item, dict) and item.get("path")
            ][:20]
            if paths:
                row["files"] = paths
                row["area"] = paths[0].split("/")[0] if "/" in paths[0] else paths[0]
                if not row.get("changed_files"):
                    row["changed_files"] = len(paths)


def attach_run_metrics(prs: list[dict[str, Any]], run_rows: Iterable[dict[str, Any]]) -> None:
    """Fill models, cost, tokens, proven and the per-run history from recorded runs.

    A pull request can have several runs (vulnerable head, then fixed head).
    ``runs`` keeps every matched run newest-first so the PR page can show the
    detection alongside the fix instead of only the latest head.
    """
    by_pr: dict[str, list[dict[str, Any]]] = {}
    for row in run_rows:
        number = str(row.get("pr") or "").lstrip("#")
        if number.isdigit():
            by_pr.setdefault(number, []).append(row)
    for pr in prs:
        matched = by_pr.get(str(pr["number"]), [])
        if not matched:
            continue
        models: list[str] = []
        cost = 0.0
        tokens_in = tokens_out = 0
        proven = 0
        have_cost = have_tokens = False
        run_id = ""
        for row in matched:
            run_id = run_id or str(row.get("run_id") or "")
            proven += int(row.get("proven") or 0)
            if row.get("cost_usd") is not None:
                cost += float(row["cost_usd"])
                have_cost = True
            tin, tout = row.get("tokens_in"), row.get("tokens_out")
            if tin is not None or tout is not None:
                tokens_in += int(tin or 0)
                tokens_out += int(tout or 0)
                have_tokens = True
            for name in row.get("models") or []:
                if name and name not in models:
                    models.append(name)
        pr["models"] = models[:20]
        pr["cost_usd"] = round(cost, 8) if have_cost else None
        pr["tokens_in"] = tokens_in if have_tokens else None
        pr["tokens_out"] = tokens_out if have_tokens else None
        pr["proven"] = proven
        pr["run_id"] = run_id
        history = [
            {
                "run_id": str(row.get("run_id") or ""),
                "proven": int(row.get("proven") or 0),
                "status": str(row.get("status") or ""),
                "headline": str(row.get("headline") or ""),
                "started_at": str(row.get("started_at") or ""),
                "commit": str(row.get("commit") or ""),
            }
            for row in matched
            if str(row.get("run_id") or "")
        ]
        history.sort(key=lambda h: (h["started_at"], h["run_id"]), reverse=True)
        pr["runs"] = history


def build_author_rows(prs: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate authors (PR author + Co-authored-by) for the authors panel."""
    cells: dict[str, dict[str, Any]] = {}
    for pr in prs:
        entries = [(pr.get("author") or "", pr.get("author_kind") or KIND_UNCLASSIFIED)]
        for extra in pr.get("coauthors") or []:
            entries.append((extra.get("login") or "", extra.get("kind") or KIND_UNCLASSIFIED))
        seen: set[str] = set()
        for login, kind in entries:
            if not login or login.lower() in seen:
                continue
            seen.add(login.lower())
            cell = cells.get(login.lower())
            if cell is None:
                cell = {
                    "login": login,
                    "kind": kind,
                    "color": author_color(login),
                    "prs": 0,
                    "additions": 0,
                    "deletions": 0,
                    "areas": {},
                }
                cells[login.lower()] = cell
            cell["prs"] += 1
            cell["additions"] += int(pr.get("additions") or 0)
            cell["deletions"] += int(pr.get("deletions") or 0)
            area = pr.get("area") or ""
            if area:
                areas = cell["areas"]
                areas[area] = areas.get(area, 0) + 1
    rows = []
    for cell in cells.values():
        top = sorted(cell["areas"].items(), key=lambda kv: (-kv[1], kv[0]))
        rows.append({
            "login": cell["login"],
            "kind": cell["kind"],
            "color": cell["color"],
            "prs": cell["prs"],
            "additions": cell["additions"],
            "deletions": cell["deletions"],
            "area": top[0][0] if top else "",
            "area_count": top[0][1] if top else 0,
        })
    rows.sort(key=lambda r: (-r["prs"], r["login"].lower()))
    return rows


def build_pr_index(
    raw_prs: Sequence[dict[str, Any]],
    *,
    source_label: str,
    available: bool,
    empty_reason: str = "",
    run_rows: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """JSON for ``GET /api/prs``: PRs, authors, and the command that produces them."""
    prs = [dict(item) for item in raw_prs]
    if run_rows is not None:
        attach_run_metrics(prs, run_rows)
    authors = build_author_rows(prs)
    return {
        "source": source_label,
        "available": bool(available and prs),
        "command": PR_LIST_COMMAND,
        "empty_reason": "" if prs else (
            empty_reason
            or f"No pull requests yet. List them with `{PR_LIST_COMMAND}` "
            "after launching with --source github:owner/repo."
        ),
        "pull_requests": prs,
        "authors": authors,
    }
