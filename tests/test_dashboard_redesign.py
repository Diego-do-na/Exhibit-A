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
