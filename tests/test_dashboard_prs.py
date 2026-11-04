"""Dashboard pull requests and authors come only from the chosen source."""

from __future__ import annotations

import json
from pathlib import Path

from exhibit_a.dashboard.prs import (
    KIND_BOT,
    KIND_HUMAN,
    KIND_UNCLASSIFIED,
    PR_LIST_COMMAND,
    attach_run_metrics,
    author_color,
    build_pr_index,
    classify_author,
    parse_authors_yml,
    parse_coauthors,
    parse_pr_list,
)
from exhibit_a.dashboard.sources import GhError, GitHubSource, LocalRunsSource
from test_dashboard_sources import artifact, fake_github, gh_listing, write_run, event_line
from test_dashboard_support import api, make_state


def gh_pr(
    number,
    title,
    login,
    *,
    is_bot=False,
    body="",
    additions=1,
    deletions=0,
    files=None,
    state="OPEN",
    merged_at=None,
):
    return {
        "number": number,
        "title": title,
        "author": {"login": login, "is_bot": is_bot, "name": login},
        "createdAt": "2026-11-03T12:00:00Z",
        "updatedAt": "2026-11-03T12:30:00Z",
        "additions": additions,
        "deletions": deletions,
        "changedFiles": len(files or []),
        "commits": [{
            "messageHeadline": title,
            "messageBody": body,
            "authors": [{"login": login, "name": login, "email": f"{login}@users.noreply.github.com"}],
        }],
        "url": f"https://evil.example/pull/{number}",
        "state": state,
        "mergedAt": merged_at,
        "headRefName": f"pr-{number}",
        "baseRefName": "main",
        "files": [{"path": p, "additions": 1, "deletions": 0} for p in (files or [])],
    }


def test_authors_yml_maps_human_and_bot_and_ignores_junk():
    text = """
# optional overlay
diego: human
claude: bot
dependabot[bot]: bot
empty:
unknown: maybe
"""
    mapping = parse_authors_yml(text)
    assert mapping == {"diego": "human", "claude": "bot", "dependabot[bot]": "bot"}


def test_classify_author_never_guesses_human():
    assert classify_author("dependabot[bot]") == KIND_BOT
    assert classify_author("copilot", is_bot=True) == KIND_BOT
    assert classify_author("diego") == KIND_UNCLASSIFIED
    assert classify_author("diego", mapping={"diego": "human"}) == KIND_HUMAN
    assert classify_author("claude", mapping={"claude": "bot"}) == KIND_BOT
    assert classify_author("") == KIND_UNCLASSIFIED


def test_coauthored_by_trailers_extract_bot_and_human_logins():
    body = (
        "Fix the sink.\n\n"
        "Co-authored-by: claude[bot] <claude[bot]@users.noreply.github.com>\n"
        "Co-authored-by: Diego <123+diego@users.noreply.github.com>\n"
    )
    pairs = parse_coauthors(body)
    logins = {name: bot for name, bot in pairs}
    assert logins["claude[bot]"] is True
    assert logins["diego"] is False


def test_parse_pr_list_drops_untrusted_url_and_classifies():
    raw = json.dumps([
        gh_pr(15, "traversal in memos.py", "diego", files=["memos.py"],
              body="Co-authored-by: claude[bot] <claude[bot]@users.noreply.github.com>\n"),
        gh_pr(16, "SSRF in pings.py", "dependabot[bot]", is_bot=True, files=["pings.py"]),
    ]).encode()
    rows = parse_pr_list(raw, repo="acme/app", mapping={"diego": "human"})
    assert [r["number"] for r in rows] == [15, 16]
    assert rows[0]["url"] == "https://github.com/acme/app/pull/15"
    assert rows[0]["author_kind"] == KIND_HUMAN
    assert rows[0]["coauthors"][0]["login"] == "claude[bot]"
    assert rows[0]["coauthors"][0]["kind"] == KIND_BOT
    assert rows[0]["area"] == "memos.py"
    assert rows[1]["author_kind"] == KIND_BOT
    assert rows[1]["author_color"] == author_color("dependabot[bot]")


def test_github_lists_pull_requests_from_gh_pr_list_and_caches(tmp_path):
    listing = json.dumps([
        gh_pr(15, "traversal in memos.py UNIQUE-A", "diego", files=["memos.py"]),
    ]).encode()
    gh = fake_github({
        "pr list acme/app": listing,
        "repos/acme/app/contents/.exhibit-a/authors.yml": b"diego: human\n",
    })
    source = GitHubSource("acme/app", gh=gh)
    rows = source.list_pull_requests()
    assert rows[0]["title"] == "traversal in memos.py UNIQUE-A"
    assert rows[0]["author_kind"] == KIND_HUMAN
    assert any(call[0][:2] == ["pr", "list"] for call in gh.calls)
    before = len(gh.calls)
    source.list_pull_requests()
    assert len(gh.calls) == before  # listing cached


def test_two_github_sources_do_not_cross_pull_request_strings():
    gh_a = fake_github({
        "pr list acme/app": json.dumps([gh_pr(15, "UNIQUE-TRAVERSAL-MEMOS", "diego")]).encode(),
        "repos/acme/app/contents/.exhibit-a/authors.yml": GhError("HTTP 404"),
    })
    gh_b = fake_github({
        "repos/other/lib/actions/artifacts": gh_listing(artifact(21, 601)),
        "pr list other/lib": json.dumps([gh_pr(17, "UNIQUE-INNOCUOUS-REFACTOR", "alice")]).encode(),
        "repos/other/lib/contents/.exhibit-a/authors.yml": GhError("HTTP 404"),
    })
    # fake_github() seeds acme/app artifacts; other/lib needs its own listing.
    a = GitHubSource("acme/app", gh=gh_a)
    b = GitHubSource("other/lib", gh=gh_b)
    titles_a = [p["title"] for p in a.list_pull_requests()]
    titles_b = [p["title"] for p in b.list_pull_requests()]
    assert titles_a == ["UNIQUE-TRAVERSAL-MEMOS"]
    assert titles_b == ["UNIQUE-INNOCUOUS-REFACTOR"]
    body_a = json.dumps(build_pr_index(a.list_pull_requests(), source_label=a.label, available=True))
    body_b = json.dumps(build_pr_index(b.list_pull_requests(), source_label=b.label, available=True))
    assert "UNIQUE-TRAVERSAL-MEMOS" in body_a and "UNIQUE-TRAVERSAL-MEMOS" not in body_b
    assert "UNIQUE-INNOCUOUS-REFACTOR" in body_b and "UNIQUE-INNOCUOUS-REFACTOR" not in body_a
    assert "acme/app" in body_a and "other/lib" not in body_a


def test_local_source_has_no_github_prs_and_names_the_command(tmp_path):
    write_run(tmp_path, "run-a", event_line() + "\n")
    source = LocalRunsSource(tmp_path)
    assert source.list_pull_requests() == []
    state = make_state(source)
    status, _, body = api(state, "/api/prs")
    assert status == 200
    assert body["available"] is False
    assert body["pull_requests"] == []
    assert PR_LIST_COMMAND in body["empty_reason"]
    assert body["command"] == PR_LIST_COMMAND


def test_api_prs_attaches_ledger_cost_and_model(tmp_path):
    from exhibit_a.dashboard.model import run_row

    ledger = "\n".join([
        json.dumps({
            "ts": "2026-11-03T14:00:00Z", "run_id": "r1", "type": "scan_done",
            "payload": {},
        }),
        json.dumps({
            "ts": "2026-11-03T14:00:01Z", "run_id": "r1", "type": "suspicion_raised",
            "role": "adversary", "model": "muse-wonder-1.0",
            "tokens_in": 10, "tokens_out": 4, "cost_usd": 0.05,
            "payload": {"suspicion": {"id": "S1", "class": "path_traversal"}},
        }),
    ]) + "\n"
    write_run(tmp_path, "r1", ledger, {"schema_version": "1", "status": "completed", "pr": "15"})
    source = LocalRunsSource(tmp_path)
    # Stamp the PR number the way an index would.
    (tmp_path / "runs.jsonl").write_text(json.dumps({
        "run_id": "r1", "dir": "r1", "pr": "15",
    }) + "\n")
    data = source.load_run("r1")
    row = run_row(data)
    prs = parse_pr_list(json.dumps([gh_pr(15, "traversal", "diego")]).encode(), repo="acme/app")
    attach_run_metrics(prs, [row])
    assert prs[0]["models"] == ["muse-wonder-1.0"]
    assert prs[0]["cost_usd"] == 0.05
    assert prs[0]["tokens_in"] == 10
    assert prs[0]["run_id"] == "r1"


def test_two_local_sources_do_not_cross_run_strings(tmp_path):
    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"
    write_run(a_dir, "run-a", event_line(run_id="UNIQUE-SRC-A") + "\n")
    write_run(b_dir, "run-b", event_line(run_id="UNIQUE-SRC-B") + "\n")
    status_a, _, body_a = api(make_state(LocalRunsSource(a_dir)), "/api/runs")
    status_b, _, body_b = api(make_state(LocalRunsSource(b_dir)), "/api/runs")
    assert status_a == 200 and status_b == 200
    text_a = json.dumps(body_a)
    text_b = json.dumps(body_b)
    assert "UNIQUE-SRC-A" in text_a and "UNIQUE-SRC-A" not in text_b
    assert "UNIQUE-SRC-B" in text_b and "UNIQUE-SRC-B" not in text_a
    prs_a = api(make_state(LocalRunsSource(a_dir)), "/api/prs")[2]
    prs_b = api(make_state(LocalRunsSource(b_dir)), "/api/prs")[2]
    assert prs_a["source"] != prs_b["source"]
    assert "UNIQUE-SRC-A" not in json.dumps(prs_b)
    assert "UNIQUE-SRC-B" not in json.dumps(prs_a)


def test_dashboard_static_files_carry_no_bundled_snapshot():
    """Point 4 of T153: another --source must never see Exhibit-A's numbers."""
    root = Path(__file__).resolve().parent.parent / "web" / "dashboard"
    banned = (
        "12603", "9,030", "8,260", "29.9k", "19pkgs", "120mods", "317imports",
        "131046", "Diego-do-na/Exhibit-A · main",
    )
    blobs = []
    for path in list(root.glob("*.html")) + list((root / "views").glob("*.js")):
        blobs.append(path.read_text(encoding="utf-8"))
    text = "\n".join(blobs)
    for token in banned:
        assert token not in text, token
    graph_js = (root / "views" / "graph.js").read_text(encoding="utf-8")
    assert "fetch('/api/graph'" in graph_js
    prs_js = (root / "views" / "prs.js").read_text(encoding="utf-8")
    assert "fetch('/api/prs'" in prs_js
    assert "unclassified" in prs_js


def test_api_graph_is_empty_until_the_checkout_builder_lands(tmp_path):
    write_run(tmp_path, "run-a", event_line() + "\n")
    status, _, body = api(make_state(LocalRunsSource(tmp_path)), "/api/graph")
    assert status == 200
    assert body["available"] is False
    assert body["command"] == "exhibit-a scan --graph"
    assert body["packages"] == []
    assert "oracle" not in json.dumps(body)
    assert "29.9k" not in json.dumps(body)
