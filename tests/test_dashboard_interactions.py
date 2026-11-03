"""Static checks for the dashboard's shared interactions: select options, chart zoom, graph hosts.

The pages are plain HTML + JavaScript under a strict CSP, so these tests read the sources.
"""

from __future__ import annotations

import re

from test_dashboard_support import WEB_DIR, request, local_state, make_samples

PAGES = ("index", "prs", "pr", "findings", "graph", "benchmark")


def read(name: str) -> str:
    return (WEB_DIR / name).read_text(encoding="utf-8")


def test_selects_take_options_from_data_options_not_sc_for():
    # <sc-for> inside <select> is dropped by the HTML parser, which left every select empty.
    for page in PAGES:
        html = read(f"{page}.html")
        for match in re.finditer(r"<select\b[^>]*>(.*?)</select>", html, flags=re.DOTALL):
            assert "<sc-for" not in match.group(0) and "<option" not in match.group(0)
            assert 'data-options="{{' in match.group(0)
    assert "data-options" in read("dc-lite.js")


def test_every_expand_button_opens_a_zoom_dialog_with_its_own_description():
    seen = set()
    for page in PAGES:
        html = read(f"{page}.html")
        buttons = re.findall(r"<button[^>]*Expand chart[^>]*>", html)
        for button in buttons:
            assert "data-zoom " in button or "data-zoom\n" in button or 'data-zoom data-zoom-desc' in button
            desc = re.search(r'data-zoom-desc="([^"]+)"', button)
            assert desc and len(desc.group(1)) > 60
            assert desc.group(1) not in seen  # one specific description per chart
            seen.add(desc.group(1))
    assert len(seen) == 14
    viz = read("views/viz.js")
    assert "openZoom" in viz and "aria-modal" in viz and "Escape" in viz


def test_graph_hosts_are_kept_by_the_runtime_and_pages_load_viz_first():
    assert 'id="gcanvas"' in read("graph.html") and "data-keep" in read("graph.html")
    assert 'id="blast"' in read("pr.html") and "data-keep" in read("pr.html")
    assert "data-keep" in read("dc-lite.js") and "componentDidRender" in read("dc-lite.js")
    for page in PAGES:
        html = read(f"{page}.html")
        assert html.index("views/viz.js") < html.index("dc-lite.js")


def test_viz_has_no_innerhtml_or_inline_style_attributes():
    code = re.sub(r"/\*.*?\*/", "", read("views/viz.js"), flags=re.DOTALL)
    for banned in (".innerHTML", ".outerHTML", "insertAdjacentHTML", "eval(", "new Function", "setAttribute('style'"):
        assert banned not in code


def test_pull_request_page_makes_no_claim_about_the_author_or_intent(tmp_path):
    page = read("pr.html") + read("views/pr.js")
    assert "malicious" not in page.lower()
    assert "Open" in read("views/pr.js") and "state-l" in read("pr.html")


def test_viz_is_served_with_the_view_scripts(tmp_path):
    state = local_state(make_samples(tmp_path))
    status, headers, body = request(state, "/views/viz.js")
    assert status == 200 and headers["content-type"][0].startswith("text/javascript")
    assert b"DCViz" in body


def test_night_mode_toggle_on_every_page_and_network_is_csp_safe():
    for page in PAGES:
        assert "data-theme-toggle" in read(f"{page}.html"), page
    assert 'src="views/netgraph.js"' in read("graph.html") and 'src="views/netgraph.js"' in read("pr.html")
    for name in ("views/netgraph.js", "views/viz.js"):
        code = re.sub(r"/\*.*?\*/", "", read(name), flags=re.DOTALL)
        assert "innerHTML" not in code and "eval(" not in code, name
    assert (WEB_DIR / "views/graphdata.js").is_file()


def test_every_expandable_chart_has_a_full_version():
    ids = {"index": {"vel", "don", "fun"}, "prs": {"tl", "hist", "cyh"}, "findings": {"sus", "out", "cost"},
           "benchmark": {"sys", "abl", "roles", "auth"}, "graph": {"layers"}}
    for page, want in ids.items():
        html = read(f"{page}.html")
        got = set(re.findall(r'data-zoom data-zoom-id="([a-z]+)"', html))
        assert got == want, page
        assert "views/fullchart.js" in html and html.index("views/fullchart.js") < html.index("views/viz.js")
        js = read(f"views/{page}.js")
        assert "fullSpec(id)" in js
        for zid in want:
            assert f"'{zid}'" in js, (page, zid)
    code = re.sub(r"/\*.*?\*/", "", read("views/fullchart.js"), flags=re.DOTALL)
    assert "innerHTML" not in code and "eval(" not in code
