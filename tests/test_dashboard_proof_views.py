"""Proof-view surfaces: palette, ledger scrubber, compare, printable finding, heatmap.

Static source checks plus serving checks through the real handler. Frontend
logic is plain script under a strict CSP, so assertions read the sources.
"""

from __future__ import annotations

import re

from test_dashboard_support import WEB_DIR, local_state, make_samples, request

PAGES = ("index", "prs", "pr", "findings", "finding", "graph", "benchmark")


def read(name: str) -> str:
    return (WEB_DIR / name).read_text(encoding="utf-8")


def test_new_pages_and_scripts_are_served(tmp_path):
    state = local_state(make_samples(tmp_path))
    for target, snippet in (
        ("/finding.html", "Finding package"),
        ("/views/palette.js", "XAPalette"),
        ("/views/finding.js", "provenance"),
    ):
        status, headers, body = request(state, target)
        assert status == 200, target
        assert snippet.encode() in body, target
    status, _, _ = request(state, "/compare.html")
    assert status == 404


def test_every_page_loads_the_command_palette():
    for page in PAGES:
        html = read(f"{page}.html")
        assert 'src="views/palette.js"' in html, page
        assert html.index('src="views/palette.js"') > html.index("dc-lite.js"), page
    code = re.sub(r"/\*.*?\*/", "", read("views/palette.js"), flags=re.DOTALL)
    for banned in (".innerHTML", ".outerHTML", "insertAdjacentHTML", "eval(", "new Function"):
        assert banned not in code
    assert "metaKey" in code and "Escape" in code
    assert "/api/runs" in code and "codegraph" in code


def test_pr_page_lists_the_real_ledger_and_explains_a_clean_run():
    js = read("views/pr.js")
    assert "/api/runs/" in js and "/events?limit=" in js
    html = read("pr.html")
    assert "Scrub the ledger" not in html and 'type="range"' not in html
    assert "live.player" in html and "chronological" in js
    assert "safe" in js and "discarded" in js
    assert "why-safe" in html and "Why nothing could be proven" in html
    assert "Green is not safe" in html


def test_no_loops_inside_table_body_select_or_svg_roots():
    # The HTML parser drops <sc-for> inside <tbody> and <select>, which left
    # the scorecard table empty. Loops must use div/row markup instead.
    for page in PAGES:
        html = read(f"{page}.html")
        for match in re.finditer(r"<(?:tbody|table|select)\b[^>]*>(.*?)</(?:tbody|table|select)>", html, flags=re.DOTALL):
            assert "<sc-for" not in match.group(0), page
    assert "score" in read("views/benchmark.js")


def test_graph_text_stays_readable_in_dark_mode():
    css = read("dashboard.css")
    for selector in (".gv-label", ".gv-name", ".gv-sub", ".gv-chip", ".detail-chip"):
        assert f":root[data-theme=dark] {selector}" in css, selector


def test_network_graph_expands_detail_with_zoom():
    code = read("views/netgraph.js")
    assert "detail" in code and "view.k" in code
    assert "expand each file into its functions" in code or "expand" in code
    assert 'id="blastnet"' in read("pr.html") or "blastnet" in read("pr.html")


def test_finding_page_is_a_printable_package():
    js = read("views/finding.js")
    assert "proven" in js and "provenance" in js or "frames" in js
    html = read("finding.html")
    assert "window.print" in js and "Print this package" in html
    css = read("dashboard.css")
    assert "@media print" in css


def test_finding_page_replays_the_proof_and_shows_a_vulnerability_sheet():
    js = read("views/finding.js")
    assert "Replay the proof" in js
    assert "prefers-reduced-motion" in js
    assert "not recorded" in js
    assert "sheetFor" in js and "CWE-22" in js
    html = read("finding.html")
    assert "Replay the proof" in html and "{{replay.start}}" in html
    assert "What it is" in html and "How to fix it" in html


def test_benchmark_has_a_coverage_panel_and_derived_stats():
    assert "Coverage: what could not be proven" in read("benchmark.html")
    assert "green means nothing could be proven, never safe" in read("benchmark.html")
    js = read("views/benchmark.js")
    assert "proof rate" in js and "red-team" in js
    assert "fix rate" not in js


def test_pull_requests_map_authors_to_packages():
    assert "pkgmap" in read("views/prs.js")
    assert "Where each author merged" in read("prs.html")


def test_graph_page_has_a_heatmap_and_proven_attack_paths():
    js = read("views/graph.js")
    assert "codegraph" in js and "proven_paths" in js and "heat" in js
    html = read("graph.html")
    assert "Heatmap and attack paths" in html and 'class="heat"' in html
