"""Dashboard frontend security: no HTML-parsing sinks, strict CSP headers.

Restores the XSS coverage deleted in the dashboard redesign. The static
check scans every JavaScript file shipped under ``web/dashboard/``; the
header check drives the real dashboard handler (no socket, no Docker).
"""

from __future__ import annotations

import re
from pathlib import Path

from exhibit_a.dashboard.server import CSP, SECURITY_HEADERS
from test_dashboard_support import WEB_DIR, local_state, make_samples, request

BANNED = ("innerHTML", "outerHTML", "document.write")


def _js_files() -> list[Path]:
    files = sorted(WEB_DIR.rglob("*.js"))
    assert files, "no dashboard JavaScript files found"
    return files


def _strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    return re.sub(r"(?m)^\s*//.*$", "", code)


def test_dashboard_js_never_uses_html_parsing_sinks():
    for path in _js_files():
        code = _strip_comments(path.read_text(encoding="utf-8"))
        for banned in BANNED:
            assert banned not in code, f"{path.relative_to(WEB_DIR)} uses {banned}"


def test_dashboard_js_never_uses_eval_or_function_constructor():
    for path in _js_files():
        code = _strip_comments(path.read_text(encoding="utf-8"))
        assert "eval(" not in code, f"{path.relative_to(WEB_DIR)} uses eval"
        assert "new Function" not in code, f"{path.relative_to(WEB_DIR)} uses new Function"


def test_dashboard_html_has_no_inline_script_or_style_blocks():
    for path in sorted(WEB_DIR.rglob("*.html")):
        html = path.read_text(encoding="utf-8")
        for tag in re.findall(r"<script\b[^>]*>", html):
            if "src=" not in tag:
                # Only the inert text/x-dc data block may be inline; it is
                # never executed (CSP script-src 'self' also blocks it).
                assert 'type="text/x-dc"' in tag, (path.name, tag)
        assert "<style" not in html, path.name


def test_dashboard_server_sends_strict_csp_headers(tmp_path: Path):
    state = local_state(make_samples(tmp_path))
    status, headers, _ = request(state, "/index.html")
    assert status == 200
    for key, value in SECURITY_HEADERS.items():
        if key == "Cache-Control":
            continue  # static files override with ETag revalidation (no-cache)
        assert headers[key.lower()] == [value], key
    assert headers["cache-control"] == ["no-cache"]
    csp = headers["content-security-policy"][0]
    assert csp == CSP
    for directive in (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ):
        assert directive in csp
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    assert headers["x-content-type-options"] == ["nosniff"]
    assert headers["x-frame-options"] == ["DENY"]


def test_dashboard_route_exit_animation_is_defined_and_reduced_motion_safe():
    css = (WEB_DIR / "dashboard.css").read_text(encoding="utf-8")
    assert "@keyframes cardExit" in css
    assert ".anim-exit" in css and "cardExit .22s" in css
    # The exit rule must beat the .content>* entrance in specificity, or
    # cardExit never runs (the original bug: exit was invisible).
    assert "main.content>*.anim-exit" in css
    assert ".anim-enter" in css
    reduced = css.split("@media (prefers-reduced-motion:reduce)", 1)[1].split("}", 1)[0]
    assert ".anim-exit" in reduced


def test_dashboard_route_transition_waits_for_exit_and_cancels_stale_clicks():
    js = (WEB_DIR / "dc-lite.js").read_text(encoding="utf-8")
    assert "anim-exit" in js and "cardExit" in js
    assert "animationend" in js and "setTimeout(finish, EXIT_MS)" in js
    assert "routeSeq" in js and "seq !== routeSeq" in js
    assert "prefers-reduced-motion: reduce" in js


def test_zoom_dialog_exit_animation_overrides_entrance_fill():
    css = (WEB_DIR / "dashboard.css").read_text(encoding="utf-8")
    # .zm-ovl keeps fadein with fill both, so opacity:0 alone never shows;
    # the exit must be an animation on the stronger .zm-ovl.zm-out selector.
    assert ".zm-ovl.zm-out" in css and "zmFadeOut" in css
    assert ".zm-out .zm" in css and "zmExit" in css
    viz = (WEB_DIR / "views/viz.js").read_text(encoding="utf-8")
    assert "setTimeout(done, 200)" in viz


def test_pr_report_follows_the_selected_pull_request():
    prs_js = (WEB_DIR / "views/prs.js").read_text(encoding="utf-8")
    prs_html = (WEB_DIR / "prs.html").read_text(encoding="utf-8")
    pr_js = (WEB_DIR / "views/pr.js").read_text(encoding="utf-8")
    pr_html = (WEB_DIR / "pr.html").read_text(encoding="utf-8")
    assert "pr.html?pr=" in prs_js and 'href="{{sel.href}}"' in prs_html
    assert "views/prdata.js" in pr_html and "{{pr.title}}" in pr_html
    assert "prRow()" in pr_js and "window.XA_PRS" in pr_js


def test_pr_blast_graph_is_the_full_graph_with_damaged_route_in_red():
    pr_js = (WEB_DIR / "views/pr.js").read_text(encoding="utf-8")
    pr_html = (WEB_DIR / "pr.html").read_text(encoding="utf-8")
    assert "views/graphdata.js" in pr_html
    assert "window.DCGraphData" in pr_js and "vuln: hot" in pr_js
    assert "f:pam" not in pr_js  # the old pamphlet-only mini graph is gone


def test_dashboard_visual_protagonists_and_contrast_hooks():
    css = (WEB_DIR / "dashboard.css").read_text(encoding="utf-8")
    index = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert "proof-strip" in index and "Exploit fails on the vulnerable code" in index
    assert "proofIn" in css and ".proof-strip" in css
    assert (WEB_DIR / "graph.html").read_text(encoding="utf-8").count("g-hero") >= 1
    assert "hero-bar" in (WEB_DIR / "findings.html").read_text(encoding="utf-8")
    assert "5" in (WEB_DIR / "findings.html").read_text(encoding="utf-8")
    dark = css.split(":root[data-theme=dark] .proof-step b", 1)[1]
    assert "color" in dark


def test_dashboard_api_responses_also_carry_strict_csp(tmp_path: Path):
    state = local_state(make_samples(tmp_path))
    status, headers, _ = request(state, "/api/info")
    # Unauthenticated API calls are refused, but must still carry the CSP.
    assert status == 401
    assert headers["content-security-policy"] == [CSP]
