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
    assert {"Lora", "IBM Plex Sans", "JetBrains Mono", "Inter", "Geist", "Manrope"} <= families
    for face in faces:
        assert "font-display: swap" in face
        url = re.search(r'url\("([^"]+)"\)', face).group(1)
        assert url.startswith("fonts/") and url.endswith(".woff2")  # same origin, never a CDN
        assert (WEB_DIR / url).is_file(), url
        status, headers, body = request(state, "/" + url)
        assert status == 200 and headers["content-type"] == ["font/woff2"]
        assert body[:4] == b"wOF2"
        assert headers["content-security-policy"][0].find("font-src 'self'") >= 0
    for licence in ("lora", "ibm-plex-sans", "jetbrains-mono", "inter", "geist", "manrope"):
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


def test_two_level_navigation_and_siem_topbar_are_present():
    assert 'id="repo-switcher-card"' in HTML and 'id="repo-select"' in HTML
    assert 'id="repo-nav"' in HTML and 'id="pr-nav"' in HTML
    assert 'id="nav-back-repo"' in HTML and 'id="pr-context-card"' in HTML
    assert 'id="run-context-card"' not in HTML  # no Current run widget at repository level
    assert 'id="window-selector"' in HTML
    for window_key in ("7d", "30d", "90d", "total"):
        assert f'data-window="{window_key}"' in HTML
    for meta_id in ("meta-window", "meta-last-update", "meta-source"):
        assert f'id="{meta_id}"' in HTML
    assert "function setSidebarLevel" in JS and "function filterRunsByWindow" in JS


def test_static_export_answers_the_repository_endpoints(tmp_path):
    from exhibit_a.dashboard.export import export_dashboard
    from exhibit_a.dashboard.sources import LocalRunsSource

    out = tmp_path / "export"
    export_dashboard(LocalRunsSource(make_samples(tmp_path)), out, run_id="synthetic-01-starlette-proven")
    script = (out / "static.js").read_text(encoding="utf-8")
    assert 'parts[1] === "repos"' in script and repo_id(STARLETTE) in script


# -- C: dynamic backdrop and liquid glass ----------------------------------------------


def test_backdrop_is_decorative_and_moves_only_with_transforms():
    assert re.search(r'<div class="backdrop" id="backdrop" aria-hidden="true">', HTML)
    assert HTML.count('class="field field-') >= 4
    assert re.search(r"\.backdrop\s*{[^}]*contain:\s*strict", CSS)
    assert re.search(r"\.field\s*{[^}]*will-change:\s*transform", CSS)
    init = JS[JS.index("const DRIFT = ["):JS.index("async function boot")]
    # app.js only ever sets transform on the fields, stepped a few times a second
    assert re.findall(r'style\.setProperty\("([a-z-]+)"', init) == ["transform"]
    assert "const DRIFT_STEP_MS = 200;" in init and "setInterval(step, DRIFT_STEP_MS)" in init
    assert "@keyframes drift" not in CSS  # no display-rate animation under the glass


def test_backdrop_respects_reduced_motion_and_pauses_when_hidden():
    init = JS[JS.index("function initBackdrop"):JS.index("async function boot")]
    assert '"(prefers-reduced-motion: reduce)"' in init
    assert "visibilitychange" in init and "document.hidden" in init and "clearInterval(timer)" in init
    assert 'removeProperty("transform")' in init  # reduced motion: the static picture


def test_graph_route_keeps_the_canvas_out_of_a_blurred_layer():
    block = CSS[CSS.index(".route-graph .data-workspace"):]
    block = block[:block.index("}")]
    assert "backdrop-filter: none" in block and "var(--panel-solid)" in block
    graph = JS[JS.index("async function renderDependencies"):]
    assert 'document.body.classList.add("route-graph")' in graph
    assert 'document.body.classList.remove("route-graph")' in graph


def test_liquid_glass_uses_the_token_blur_and_has_a_solid_fallback():
    assert "backdrop-filter: blur(var(--effect-background-blur))" in CSS
    assert "-webkit-backdrop-filter: blur(var(--effect-background-blur))" in CSS
    fallback = CSS[CSS.index("@supports not ((backdrop-filter"):]
    fallback = fallback[:fallback.index("\n}\n")]
    for surface in (".sidebar", ".data-workspace", ".action-btn"):
        assert surface in fallback
    assert "var(--panel-solid)" in fallback and "var(--sidebar-solid)" in fallback
    assert "--glass-specular" in CSS  # the highlight along the top edge


def test_a_stale_render_cannot_paint_over_a_newer_route():
    # Regression: opening "/" then "#/runs" quickly let the slower home render finish last
    # and replace the runs table. Each navigation now aborts the previous one's requests.
    api_fn = JS[JS.index("async function api(path)"):JS.index("function renderError")]
    assert "signal: state.routeAbort.signal" in api_fn
    router = JS[JS.index("async function route()"):JS.index("// -- Bootstrap")]
    assert router.index("state.routeAbort.abort();") < router.index("new AbortController()")
    assert "if (isAbort(error) || signal.aborted) return;" in router


# -- D: the code graph -------------------------------------------------------------------

import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

from exhibit_a.dashboard.model import build_code_graph  # noqa: E402
from exhibit_a.dashboard.sources import LocalRunsSource, MAX_DIFF_BYTES  # noqa: E402


def test_codegraph_describes_the_whole_tree(state):
    status, headers, graph = api(state, "/api/runs/synthetic-01-starlette-proven/codegraph")
    assert status == 200 and headers["content-type"] == ["application/json; charset=utf-8"]
    assert graph["available"] and graph["changed_source"] == "diff"
    ids = {n["id"] for n in graph["nodes"]}
    kinds = {n["kind"] for n in graph["nodes"]}
    assert {"file", "function", "method", "sink"} <= kinds
    assert all(e["source"] in ids and e["target"] in ids for e in graph["edges"])
    assert {e["kind"] for e in graph["edges"]} == {"defines", "call", "sink"}
    by_id = {n["id"]: n for n in graph["nodes"]}
    # entry points: the ASGI callable and the route table handlers
    assert by_id["starlette.staticfiles:StaticFiles.__call__"]["entry_kind"] == "asgi"
    assert by_id["app.views:show_avatar"]["entry"]
    # the PR diff changed lookup_path; S1 sits on it and is proven along an observed path
    lookup = by_id["starlette.staticfiles:StaticFiles.lookup_path"]
    assert lookup["changed"] and lookup["in_pr"] and lookup["proven"] and lookup["severity"] == "high"
    assert [f["id"] for f in lookup["findings"]] == ["S1"]
    assert by_id["sink:os.stat"]["sink"] and by_id["sink:os.stat"]["effect"] == "canary_read"
    assert graph["proven_paths"] and all(p["nodes"][-1] == p["sink"] for p in graph["proven_paths"])
    proven_edges = [e for e in graph["edges"] if e["proven"]]
    assert proven_edges and all(by_id[e["source"]]["proven"] and by_id[e["target"]]["proven"] for e in proven_edges)
    # discarded suspicions are placed too, never as proven
    assert by_id["starlette.responses:Response.init_headers"]["findings"][0]["verdict"] == "discarded_unproven"
    assert by_id["starlette.responses:Response.init_headers"]["severity"] == ""


def test_codegraph_scales_to_the_large_sample(state):
    started = time.perf_counter()
    status, _, graph = api(state, "/api/runs/synthetic-04-archive-incomplete-fix/codegraph")
    assert status == 200 and len(graph["nodes"]) >= 450 and not graph["truncated"]
    assert time.perf_counter() - started < 5  # parsed with ast, cached afterwards
    assert graph["stats"]["functions"] >= 400 and graph["stats"]["entries"] >= 20


def test_codegraph_changes_come_only_from_the_diff(tmp_path):
    runs = make_samples(tmp_path)
    source = LocalRunsSource(runs)
    docs_only = build_code_graph(source.load_run("synthetic-06-skipped-docs"))
    assert docs_only["available"] and docs_only["stats"]["changed"] == 0
    assert not any(n["changed"] for n in docs_only["nodes"] if n["kind"] != "file")
    folder = runs / "synthetic-03-archive-proven"
    (folder / "pr.diff").unlink()
    no_diff = build_code_graph(LocalRunsSource(runs).load_run("synthetic-03-archive-proven"))
    assert no_diff["changed_source"] == "none" and no_diff["stats"]["changed"] == 0
    assert no_diff["proven_paths"]  # the oracle's paths do not depend on the diff


def test_pr_diff_is_read_without_following_symlinks_or_oversize(tmp_path):
    runs = make_samples(tmp_path)
    folder = runs / "synthetic-01-starlette-proven"
    secret = tmp_path / "secret.diff"
    secret.write_text("+++ b/starlette/staticfiles.py\n@@ -1,0 +1,1 @@\n+x\n")
    (folder / "pr.diff").unlink()
    (folder / "pr.diff").symlink_to(secret)
    assert LocalRunsSource(runs).load_run("synthetic-01-starlette-proven").diff == ""
    (folder / "pr.diff").unlink()
    (folder / "pr.diff").write_bytes(b"+" * (MAX_DIFF_BYTES + 1))
    data = LocalRunsSource(runs).load_run("synthetic-01-starlette-proven")
    assert data.error == "" and data.diff == ""  # an oversized diff is ignored, the run still loads


def test_codegraph_needs_the_session_and_a_tree(state, tmp_path):
    status, _, _ = request(state, "/api/runs/synthetic-01-starlette-proven/codegraph")
    assert status == 401
    from test_dashboard_support import FIXTURES
    hostile = local_state(FIXTURES / "hostile")
    status, _, graph = api(hostile, "/api/runs/run-hostile/codegraph")
    assert status == 200 and graph["available"] is False and graph["nodes"] == []


def test_graph_engine_is_written_here_and_accessible():
    graph = JS[JS.index("// Code graph: a force-directed graph drawn on canvas."):JS.index("// All runs")]
    assert "function buildQuadtree" in graph and "class ForceGraph" in graph  # Barnes-Hut, no library
    for word in ("d3", "cytoscape", "sigma", "vis-network", "import(", "require("):
        assert word not in graph
    # the animation loop stops once the layout has settled and is cancelled on navigation
    assert "const moving = this.alpha > 0.004;" in graph and "if (moving || this.dirty)" in graph
    assert "fg.stop();" in graph and "observer.disconnect();" in graph
    # keyboard and screen reader paths
    for key in ('"ArrowRight"', '"ArrowLeft"', '"Enter"', '"Escape"', '"+"', '"-"', '"0"', '"/"'):
        assert key in graph
    assert 'role: "application"' in graph and '"aria-label": `Code graph of' in graph
    assert 'h("table", { class: "graph-table" }' in graph and '"aria-live": "polite"' in graph


GRAPH_BROWSER = r"""
const { chromium } = require('playwright');
(async () => {
  const [bootstrap, base] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  const report = { errors: [], dialogs: [] };
  page.on('pageerror', (e) => report.errors.push(String(e)));
  page.on('dialog', async (d) => { report.dialogs.push(d.message()); await d.dismiss(); });
  await page.goto(bootstrap);
  await page.goto(base + '#/run/synthetic-04-archive-incomplete-fix/graph');
  await page.waitForSelector('canvas.graph-canvas-el');
  await page.waitForTimeout(800);
  report.canvas = await page.evaluate(() => { const c = document.querySelector('canvas.graph-canvas-el'); return { w: c.width, h: c.height }; });
  await page.fill('.graph-search', 'extract_all');
  await page.press('.graph-search', 'Enter');
  report.panel = await page.textContent('.graph-panel');
  await page.focus('canvas.graph-canvas-el');
  await page.keyboard.press('ArrowRight');
  report.afterArrow = await page.textContent('.graph-panel h3');
  report.filtered = await page.textContent('.graph-status');
  await page.fill('.graph-search', '');
  await page.click('text=This pull request');
  await page.waitForTimeout(300);
  report.prStatus = await page.textContent('.graph-status');
  await page.click('.seg-btn:has-text("List")');
  report.prRows = await page.locator('.graph-table tbody tr').count();
  await page.click('text=Whole repository');
  report.listRows = await page.locator('.graph-table tbody tr').count();
  report.canvasHidden = await page.locator('.graph-stage').isHidden();
  await page.goto(base + '#/runs');
  await page.waitForSelector('table.runs');
  report.routeClassGone = await page.evaluate(() => !document.body.classList.contains('route-graph'));
  await browser.close();
  console.log(JSON.stringify(report));
})().catch((e) => { console.error(String(e)); process.exit(1); });
"""


def test_graph_view_works_in_a_real_browser(tmp_path):
    from test_dashboard_xss import _playwright_env
    from exhibit_a.dashboard.server import create_server

    env = _playwright_env()
    if env is None:
        pytest.skip("Node + Playwright not available: the browser-level graph check was not run")
    node, node_path = env
    srv = create_server(LocalRunsSource(make_samples(tmp_path)), port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        script = tmp_path / "graph.js"
        script.write_text(GRAPH_BROWSER)
        proc = subprocess.run([node, str(script), srv.state.bootstrap_url(), f"http://127.0.0.1:{srv.state.port}/"],
                              capture_output=True, text=True, timeout=120, env={**os.environ, "NODE_PATH": node_path})
    finally:
        srv.shutdown()
        srv.server_close()
    if proc.returncode != 0 and "Executable doesn't exist" in proc.stderr:
        pytest.skip("Chromium for Playwright is not installed: the browser-level graph check was not run")
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout.strip().splitlines()[-1])
    assert report["errors"] == [] and report["dialogs"] == []
    assert report["canvas"]["w"] > 300 and report["canvas"]["h"] > 200
    assert "extract_all" in report["panel"] and "archive.py:" in report["panel"] and "Callers" in report["panel"]
    assert report["afterArrow"]  # the keyboard moved the selection
    assert report["filtered"].startswith("1 node match")  # the search dims everything else
    assert "in this pull request" in report["prStatus"]
    assert 0 < report["prRows"] < 20  # the list follows the scope
    assert report["listRows"] >= 450 and report["canvasHidden"]
    assert report["routeClassGone"]  # leaving the graph restores the glass panel
