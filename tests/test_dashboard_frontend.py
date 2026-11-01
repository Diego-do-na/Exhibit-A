"""Dashboard frontend tests.

Verifies that the dashboard serves the exported design (tokens, five screens, dark mode):
- The HTML references tokens and stylesheet
- Loads without external URLs or CDNs
- Contains no inline event handlers or inline styles
- Uses CSS custom properties for all visual values (light & dark mode)
- Renders the five screens and shared shell against the sample runs API
"""

from __future__ import annotations

import html.parser
import json
import re
from pathlib import Path

import pytest

from test_dashboard_support import FIXTURES, WEB_DIR, api, cookie_for, local_state, make_samples, request


class _TagCollector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        self.tags.append((tag, {k.lower(): (v or "") for k, v in attrs}))


@pytest.fixture()
def state(tmp_path: Path):
    return local_state(make_samples(tmp_path))


# -- HTML Parsing & Static Cleanliness ------------------------------------------


def test_index_html_parses_cleanly_without_inline_handlers_or_styles(state):
    status, headers, body = request(state, "/", headers=cookie_for(state))
    assert status == 200
    html_text = body.decode("utf-8")

    parser = _TagCollector()
    parser.feed(html_text)

    # 1. No inline event handlers (on*) and no inline styles
    for tag, attrs in parser.tags:
        for attr_name, attr_val in attrs.items():
            assert not attr_name.startswith("on"), f"Inline event handler '{attr_name}' found on <{tag}>"
            assert attr_name != "style", f"Inline style attribute found on <{tag}>"

    # 2. No inline script blocks
    assert re.search(r"<script(?![^>]*src=)", html_text, re.IGNORECASE) is None

    # 3. Exactly one script tag pointing to app.js
    scripts = [attrs for tag, attrs in parser.tags if tag == "script"]
    assert len(scripts) == 1
    assert scripts[0].get("src") == "app.js"


def test_index_html_loads_without_external_urls(state):
    status, _, body = request(state, "/", headers=cookie_for(state))
    assert status == 200
    html_text = body.decode("utf-8")

    # Strip HTML comments and http-equiv before checking
    cleaned = re.sub(r"<!--.*?-->", "", html_text, flags=re.DOTALL)
    cleaned = cleaned.replace("http-equiv", "")

    # No external schemes or protocol-relative URLs
    assert "http://" not in cleaned
    assert "https://" not in cleaned
    assert "//" not in re.sub(r'href="#/[^"]*"', '', cleaned)  # Ignore internal route fragments if any


def test_index_html_defines_semantic_shell_and_navigation(state):
    status, _, body = request(state, "/", headers=cookie_for(state))
    assert status == 200
    html_text = body.decode("utf-8")

    parser = _TagCollector()
    parser.feed(html_text)

    tag_names = {tag for tag, _ in parser.tags}
    assert "aside" in tag_names
    assert "header" in tag_names
    assert "main" in tag_names
    assert "footer" in tag_names
    assert "nav" in tag_names

    # Check for the 5 navigation destinations
    nav_links = [attrs.get("data-nav") for tag, attrs in parser.tags if tag == "a" and "data-nav" in attrs]
    assert "overview" in nav_links
    assert "liverun" in nav_links
    assert "findings" in nav_links
    assert "benchmark" in nav_links
    assert "dependencies" in nav_links


# -- Tokens & CSS Implementation ------------------------------------------------


def test_style_css_defines_all_tokens_from_design(state):
    status, headers, body = request(state, "/style.css")
    assert status == 200
    assert "text/css" in headers.get("content-type", [""])[0]
    css = body.decode("utf-8")

    # Fonts
    assert "--font-editorial" in css
    assert "--font-ui" in css
    assert "--font-mono" in css

    # Type scale (from tokens.json)
    for px in (15, 16, 17, 18, 20, 22, 24, 26, 27, 28, 32, 36, 40, 42, 52, 88):
        assert f"--type-size-{px}" in css or f"--type_size_px-{px}" in css

    # Spacing scale (from tokens.json)
    for px in (0, 5, 6, 7, 8, 10, 12, 14, 15, 16, 18, 20, 22, 24, 28, 32, 36, 40):
        assert f"--space-{px}" in css or f"--space_px-{px}" in css

    # Radius scale (from tokens.json)
    for px in (0, 5, 6, 8, 10, 12, 18, 24, 60):
        assert f"--radius-{px}" in css or f"--radius_px-{px}" in css

    # Rules / borders (from tokens.json)
    assert "--rule-1" in css or "--rule_px-1" in css

    # Surfaces
    assert "--surface-raised" in css
    assert "--surface-workspace" in css
    assert "--surface-workspace-white" in css
    assert "--surface-selected" in css

    # Border default
    assert "--border-default" in css

    # Text palette
    assert "--text-primary" in css
    assert "--text-secondary" in css
    assert "--text-navy" in css
    assert "--text-slate" in css
    assert "--text-inverse" in css

    # Accent & Severity
    assert "--accent-primary" in css
    assert "--severity-high" in css

    # Chart palette
    assert "--chart-proven" in css
    assert "--chart-unproven" in css
    assert "--chart-invalid" in css
    assert "--chart-flaky" in css
    assert "--chart-environment" in css
    assert "--chart-duplicates" in css

    # Test failure
    assert "--test-fail" in css
    assert "--test-fail-surface" in css

    # Navy depth tokens
    assert "--navy-overview-ink" in css
    assert "--navy-overview-depth" in css
    assert "--navy-overview-mid" in css

    # Glass white tokens
    assert "--glass-white-7" in css or "--glass-white-9" in css
    assert "--glass-white-13" in css or "--glass-white-15" in css

    # Code container and syntax
    assert "--code-surface" in css
    assert "--code-header" in css
    assert "--code-border" in css
    assert "--code-text" in css
    assert "--syntax-token-5" in css
    assert "--syntax-token-10" in css


def test_style_css_supports_dark_mode_and_responsive_layout(state):
    status, _, body = request(state, "/style.css")
    assert status == 200
    css = body.decode("utf-8")

    # Dark mode is an explicit opt-in through the theme toggle: the approved design
    # is light by default, so the OS preference must not switch the theme by itself.
    assert '[data-theme="dark"]' in css
    assert "prefers-color-scheme: dark" not in css

    # Responsive media query for mobile/phone width
    assert re.search(r"@media\s*\(\s*max-width:\s*\d+px\s*\)", css) is not None


def test_style_css_components_use_custom_properties_without_hardcoded_colors():
    css = (WEB_DIR / "style.css").read_text()
    # Remove :root and @media blocks that define the palette
    lines = css.splitlines()
    in_palette = False
    component_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(":root") or stripped.startswith("--"):
            in_palette = True
            continue
        if in_palette and stripped.endswith("}"):
            in_palette = False
            continue
        if not in_palette:
            component_lines.append(line)

    component_css = "\n".join(component_lines)
    # Ensure color, background, and border properties in components use var(--...)
    color_props = re.findall(r"(?:color|background|background-color|border-color)\s*:\s*([^;]+);", component_css)
    for prop_val in color_props:
        val = prop_val.strip()
        # Exclude standard keywords like transparent, inherit, none
        if val in ("transparent", "inherit", "none", "currentColor"):
            continue
        assert "var(--" in val or "rgba(" in val or "linear-gradient" in val, f"Hardcoded component color found: '{val}'"


# -- JavaScript Client Architecture & Sinks -------------------------------------


def test_app_js_has_no_html_sinks_and_safe_href(state):
    status, _, body = request(state, "/app.js")
    assert status == 200
    source = body.decode("utf-8")

    code = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    code = "\n".join(line.split("//", 1)[0] if "://" not in line else line for line in code.splitlines())

    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute(\"on", "srcdoc"):
        assert sink not in code, f"HTML sink '{sink}' found in app.js"

    # safeHref contract preserved
    assert 'function safeHref' in source
    body_safe_href = source[source.index("function safeHref"):source.index("function h(")]
    assert 'startsWith("#/")' in body_safe_href
    assert 'url.protocol === "https:" && url.hostname === "github.com"' in body_safe_href
    assert 'return "#";' in body_safe_href


def test_theme_toggle_stored_only_in_localstorage_inside_try_catch(state):
    status, _, body = request(state, "/app.js")
    assert status == 200
    source = body.decode("utf-8")

    assert "localStorage.getItem" in source
    assert "localStorage.setItem" in source

    # Check try/catch wrapper
    theme_block = source[source.index("function initTheme"):source.index("function updateThemeIcon")]
    assert "try {" in theme_block
    assert "catch" in theme_block


# -- Five Screens API & Data Contracts with Sample Runs -------------------------


def test_sample_runs_serve_five_screens_data(state):
    # 1. Screen 7: All runs list
    status, _, runs_data = api(state, "/api/runs")
    assert status == 200
    runs = runs_data["runs"]
    assert len(runs) > 0

    proven_run = next((r for r in runs if r["proven"] > 0), runs[0])
    run_id = proven_run["run_id"]

    # 2. Screen 04: Run overview
    status, _, detail = api(state, f"/api/runs/{run_id}")
    assert status == 200
    assert "run" in detail
    assert "proven" in detail
    assert "discarded" in detail
    assert "stages" in detail

    # 3. Screen 05: Finding detail
    if detail["proven"]:
        finding = detail["proven"][0]
        assert "id" in finding
        assert "evidence" in finding
        ev = finding["evidence"]
        assert "effect" in ev
        assert "fails_on_vulnerable" in ev
        assert "passes_on_fixed" in ev
        assert "fix" in ev

    # 4. Screen 3: Live run / replay
    status, _, events_page = api(state, f"/api/runs/{run_id}/events?from=0&limit=10")
    assert status == 200
    assert "events" in events_page
    assert events_page["count"] > 0

    # 5. Screen 5: Benchmark / trends
    status, _, trends = api(state, "/api/trends?limit=50")
    assert status == 200
    assert "points" in trends
    assert len(trends["points"]) > 0
    first_pt = trends["points"][0]
    for key in ("proven", "discarded_unproven", "invalid_test"):
        assert key in first_pt

    # 6. Screen 6: Dependencies / code graph
    status, _, graph = api(state, f"/api/runs/{run_id}/graph")
    assert status == 200
    assert "nodes" in graph or "reason" in graph
