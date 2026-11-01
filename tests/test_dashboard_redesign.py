"""Dashboard redesign (FE-REDESIGN): self-hosted fonts, fluid type scale, home view,
liquid-glass backdrop and the interactive code graph.

These tests pin the behaviour the redesign added; the older dashboard tests keep
covering the API contracts, CSP and XSS guarantees.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from test_dashboard_support import WEB_DIR, local_state, make_samples, request

CSS = (WEB_DIR / "style.css").read_text(encoding="utf-8")
JS = (WEB_DIR / "app.js").read_text(encoding="utf-8")
HTML = (WEB_DIR / "index.html").read_text(encoding="utf-8")


@pytest.fixture()
def state(tmp_path: Path):
    return local_state(make_samples(tmp_path))


# -- A: fonts and type scale ---------------------------------------------------------


def test_fonts_are_self_hosted_with_swap_and_served_as_woff2(state):
    faces = re.findall(r"@font-face\s*{([^}]*)}", CSS)
    families = {re.search(r'font-family:\s*"([^"]+)"', face).group(1) for face in faces}
    assert {"Lora", "IBM Plex Sans", "JetBrains Mono"} <= families
    for face in faces:
        assert "font-display: swap" in face
        url = re.search(r'url\("([^"]+)"\)', face).group(1)
        assert url.startswith("fonts/") and url.endswith(".woff2")  # same origin, never a CDN
        assert (WEB_DIR / url).is_file(), url
        status, headers, body = request(state, "/" + url)
        assert status == 200 and headers["content-type"] == ["font/woff2"]
        assert body[:4] == b"wOF2"
        assert headers["content-security-policy"][0].find("font-src 'self'") >= 0
    for licence in ("lora", "ibm-plex-sans", "jetbrains-mono"):
        assert (WEB_DIR / "fonts" / f"LICENSE-{licence}.txt").is_file()


@pytest.mark.parametrize("target", [
    "/fonts/../app.js", "/fonts/missing.woff2", "/fonts/LICENSE-lora.txt", "/fonts/Lora.woff2",
    "/fonts/x.woff2.js", "/fonts//lora-latin-700-normal.woff2", "/fonts/%2e%2e/style.css",
])
def test_only_existing_lowercase_woff2_fonts_are_served(state, target):
    status, _, _ = request(state, target)
    assert status == 404


def test_type_scale_is_fluid_and_rem_based():
    root = re.search(r"\nhtml\s*{([^}]*)}", CSS).group(1)
    assert "clamp(" in root and "vw" in root  # 1280-1920 px keep the 1728 px proportions
    assert "--sidebar-w: 16.25rem" in CSS  # 260 px at 1728 px wide
    assert "--panel-pad: 2.5rem" in CSS and "--workspace-pad: 1.25rem" in CSS
    sizes = re.findall(r"--type-size-\d+:\s*([^;]+);", CSS)
    assert sizes and all(value.strip().endswith("rem") for value in sizes)


def test_theme_never_follows_the_operating_system():
    assert "prefers-color-scheme" not in CSS
    assert "matchMedia(\"(prefers-color-scheme" not in JS
    init = JS[JS.index("function initTheme"):JS.index("function toggleTheme")]
    assert '"light"' in init and "localStorage.getItem" in init


def test_runs_table_is_fixed_layout_with_truncated_titles():
    assert re.search(r"table\.runs\s*{[^}]*table-layout:\s*fixed", CSS)
    run_title = re.search(r"\.run-title\s*{([^}]*)}", CSS).group(1)
    assert "text-overflow: ellipsis" in run_title and "white-space: nowrap" in run_title
    assert re.search(r"\.page-title\s*{[^}]*text-overflow:\s*ellipsis", CSS)


def test_no_invented_numbers_in_finding_detail():
    detail = JS[JS.index("async function renderFindingDetail"):JS.index("// Live run / replay")]
    for invented in ('"403"', '"200"', "|| 403", "|| 200", '"HIGH"', '"1 → 0"', "EA_FIXTURE"):
        assert invented not in detail
    assert "BYPASSED" in detail  # a defeated fix is never shown as PASS


# -- B: repositories and the home view -------------------------------------------------

from exhibit_a.dashboard.model import UNKNOWN_REPO_ID, repo_id  # noqa: E402
from test_dashboard_support import api  # noqa: E402

STARLETTE = "example-org/starlette-app (synthetic)"
ARCHIVE = "example-org/archive-service (synthetic)"
BILLING = "example-org/billing-api (synthetic)"


def test_repo_ids_are_stable_url_safe_and_distinct():
    assert repo_id(STARLETTE) == repo_id(STARLETTE)
    assert re.fullmatch(r"[a-z0-9][a-z0-9-]{0,80}", repo_id(STARLETTE))
    assert repo_id("a/b") != repo_id("a-b")  # same slug, different digest
    assert repo_id("") == UNKNOWN_REPO_ID
    assert re.fullmatch(r"[a-z0-9][a-z0-9-]{0,80}", repo_id('<script>alert("x")</script>/../..'))


def test_repos_endpoint_summarises_every_repository_from_run_data(state):
    status, headers, data = api(state, "/api/repos")
    assert status == 200 and headers["content-type"] == ["application/json; charset=utf-8"]
    repos = {repo["name"]: repo for repo in data["repos"]}
    assert set(repos) == {STARLETTE, ARCHIVE, BILLING}
    assert data["runs_considered"] == data["runs_total"] == 13
    _, _, runs = api(state, "/api/runs?per_page=100")
    for name, repo in repos.items():
        rows = [row for row in runs["runs"] if row["repo"] == name]
        assert repo["runs"] == len(rows)
        assert repo["proven"] == sum(row["proven"] for row in rows)
        assert [p["proven"] for p in repo["trend"]] == [r["proven"] for r in sorted(rows, key=lambda r: r["started_at"])]
        assert repo["last_run"]["run_id"] == max(rows, key=lambda r: r["started_at"])["run_id"]
        assert all(row["repo_id"] == repo["id"] for row in rows)
    assert repos[BILLING]["severity_mix"]["critical"] == 2  # canary_exec + canary_sql
    assert repos[STARLETTE]["severity_mix"]["high"] == 3
    # most recently active first
    starts = [repo["last_run"]["started_at"] for repo in data["repos"]]
    assert starts == sorted(starts, reverse=True)


def test_repo_detail_metrics_are_counts_of_recorded_runs(state):
    _, _, index = api(state, "/api/repos")
    ids = {repo["name"]: repo["id"] for repo in index["repos"]}

    status, _, starlette = api(state, f"/api/repos/{ids[STARLETTE]}")
    assert status == 200
    m = starlette["metrics"]
    # S1 is proven in three runs of the same code: three findings, one root cause.
    assert (m["runs"], m["proven"], m["root_causes"], m["fixes_verified"]) == (7, 3, 1, 3)
    assert [pr["pr"] for pr in starlette["pull_requests"]] == ["55", "52", "50", "48", "46", "44", "41"]
    assert starlette["top_findings"][0]["occurrences"] == 3
    assert starlette["top_findings"][0]["run_id"] == "synthetic-10-starlette-pr55"  # newest occurrence

    _, _, archive = api(state, f"/api/repos/{ids[ARCHIVE]}")
    # Run 04's fix was defeated by a bypass variant: it is never counted as verified.
    assert archive["metrics"]["fixes_bypassed"] == 1 and archive["metrics"]["fixes_verified"] == 1
    assert archive["top_findings"][0]["fix_status"] == "bypassed"

    _, _, billing = api(state, f"/api/repos/{ids[BILLING]}")
    assert {f["effect"] for f in billing["top_findings"]} == {"canary_exec", "canary_sql"}
    assert all(f["severity"] == "critical" for f in billing["top_findings"])
    assert billing["metrics"]["cost_usd"] == pytest.approx(
        sum(pr["cost_usd"] for pr in billing["pull_requests"]))


@pytest.mark.parametrize("target", ["/api/repos/unknown-000000", "/api/repos/UPPER", "/api/repos/..", "/api/repos/a/b"])
def test_repo_detail_refuses_unknown_or_malformed_ids(state, target):
    status, _, _ = api(state, target)
    assert status == 404


def test_repo_endpoints_need_the_session(state):
    for target in ("/api/repos", f"/api/repos/{repo_id(STARLETTE)}"):
        status, _, _ = request(state, target)
        assert status == 401


def test_home_is_the_default_route_and_sidebar_starts_with_it():
    nav = re.findall(r'data-nav="([a-z]+)"', HTML)
    assert nav[0] == "home"
    assert 'href="#/" class="nav-item" data-nav="home"' in HTML
    router = JS[JS.index("async function route()"):JS.index("// -- Bootstrap")]
    assert "await renderHome(null);" in router.split("} else {")[-1]  # unknown hashes land on home
    assert "renderHome(parts[1])" in router


def test_static_export_answers_the_repository_endpoints(tmp_path):
    from exhibit_a.dashboard.export import export_dashboard
    from exhibit_a.dashboard.sources import LocalRunsSource

    out = tmp_path / "export"
    export_dashboard(LocalRunsSource(make_samples(tmp_path)), out, run_id="synthetic-01-starlette-proven")
    script = (out / "static.js").read_text(encoding="utf-8")
    assert 'parts[1] === "repos"' in script and repo_id(STARLETTE) in script
