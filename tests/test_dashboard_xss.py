"""XSS: a hostile ledger (script tags and javascript: URLs in every text field) stays inert.

Three layers: the API serves it as JSON with nosniff, the client never uses
HTML sinks (static check of app.js), and, when Node + Playwright + Chromium
are available, a real browser renders every view of the hostile run and no
script runs, no dialog opens, and no javascript: link or injected element
appears.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading

import pytest

from exhibit_a.dashboard.server import create_server
from exhibit_a.dashboard.sources import LocalRunsSource
from test_dashboard_support import FIXTURES, WEB_DIR, api, local_state

XSS = '<script>alert("xss")</script>'
JS_URL = "javascript:alert(1)"
HOSTILE = FIXTURES / "hostile"


def test_fixture_puts_hostile_strings_in_every_text_field():
    lines = [json.loads(line) for line in (HOSTILE / "run-hostile" / "ledger.jsonl").read_text().splitlines()]
    assert all("<script>" in line["run_id"] for line in lines)
    assert all(JS_URL in line["model"] and XSS in line["role"] for line in lines)
    blob = json.dumps(lines)
    assert blob.count("<script>alert(") > 30 and blob.count(JS_URL) > 20


def test_api_serves_hostile_strings_only_as_json():
    state = local_state(HOSTILE)
    for target in ("/api/runs", "/api/runs/run-hostile", "/api/runs/run-hostile/events", "/api/trends"):
        status, headers, data = api(state, target)
        assert status == 200, target
        assert headers["content-type"] == ["application/json; charset=utf-8"]
        assert headers["x-content-type-options"] == ["nosniff"]
        assert "<script>alert(" in json.dumps(data)  # kept verbatim as data; escaping is the renderer's job
    _, _, detail = api(state, "/api/runs/run-hostile")
    assert detail["run"]["url"] == ""  # a javascript: url in the ledger never becomes the run link
    assert detail["run"]["commit"] == ""  # not a SHA, dropped
    assert detail["proven"][0]["evidence"]["fix"]["applied"] is False


def test_client_never_uses_html_sinks():
    source = (WEB_DIR / "app.js").read_text()
    code = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    code = "\n".join(line.split("//", 1)[0] if "://" not in line else line for line in code.splitlines())
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute(\"on", "srcdoc"):
        assert sink not in code, sink
    html = (WEB_DIR / "index.html").read_text()
    assert "<script src=\"app.js\"></script>" in html
    assert re.search(r"<script>|\son\w+=|style=", html) is None  # nothing inline, so CSP needs no unsafe-inline
    assert "http" not in re.sub(r"<!--.*?-->", "", html).replace("http-equiv", "")  # no CDN


def test_client_link_policy_allows_only_internal_routes_and_github():
    source = (WEB_DIR / "app.js").read_text()
    body = source[source.index("function safeHref"):source.index("function h(")]
    assert 'startsWith("#/")' in body
    assert 'url.protocol === "https:" && url.hostname === "github.com"' in body
    assert 'return "#";' in body


BROWSER_SCRIPT = r"""
const { chromium } = require('playwright');
(async () => {
  const [bootstrap, base] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await (await browser.newContext()).newPage();
  const report = { dialogs: [], errors: [], views: {} };
  page.on('dialog', async (d) => { report.dialogs.push(d.message()); await d.dismiss(); });
  page.on('pageerror', (e) => report.errors.push(String(e)));
  await page.goto(bootstrap);
  const views = [['runs', '#/runs', 'table.runs'], ['detail', '#/run/run-hostile', '.finding'],
                 ['trends', '#/trends', '.chart svg'], ['replay', '#/replay/run-hostile', 'button.primary']];
  for (const [name, hash, selector] of views) {
    await page.goto(base + hash);
    await page.waitForSelector(selector, { timeout: 10000 });
    if (name === 'replay') { await page.click('button.primary'); await page.waitForTimeout(1500); }
    if (name === 'detail') { await page.waitForSelector('.events li'); }
    report.views[name] = await page.evaluate(() => ({
      scripts: document.querySelectorAll('script').length,
      imgs: document.querySelectorAll('img, iframe, object, embed').length,
      jsLinks: [...document.querySelectorAll('[href],[src],[action]')].filter((el) =>
        /^\s*javascript:/i.test(el.getAttribute('href') || el.getAttribute('src') || el.getAttribute('action') || '')).length,
      handlers: [...document.querySelectorAll('*')].filter((el) => [...el.attributes].some((a) => a.name.startsWith('on'))).length,
      literal: document.body.innerText.includes('<script>alert("xss")</script>'),
      jsText: document.body.innerText.includes('javascript:alert(1)'),
      pwned: window.__pwned === true,
    }));
  }
  await browser.close();
  console.log(JSON.stringify(report));
})().catch((e) => { console.error(String(e)); process.exit(1); });
"""


def _playwright_env():
    node = shutil.which("node")
    npm = shutil.which("npm")
    if not node or not npm:
        return None
    root = subprocess.run([npm, "root", "-g"], capture_output=True, text=True, timeout=30).stdout.strip()
    probe = subprocess.run([node, "-e", "require('playwright')"], capture_output=True, env={"NODE_PATH": root, "PATH": ""}, timeout=30)
    return (node, root) if probe.returncode == 0 else None


def test_hostile_run_is_inert_in_a_real_browser(tmp_path):
    env = _playwright_env()
    if env is None:
        pytest.skip("Node + Playwright not available: the browser-level XSS check was not run")
    node, node_path = env
    try:
        srv = create_server(LocalRunsSource(HOSTILE), port=0)
    except PermissionError as exc:
        pytest.skip(f"cannot bind a socket here: {exc}")
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        script = tmp_path / "xss.js"
        script.write_text(BROWSER_SCRIPT)
        base = f"http://127.0.0.1:{srv.state.port}/"
        proc = subprocess.run(
            [node, str(script), srv.state.bootstrap_url(), base],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "NODE_PATH": node_path},
        )
    finally:
        srv.shutdown()
        srv.server_close()
    if proc.returncode != 0 and "Executable doesn't exist" in proc.stderr:
        pytest.skip("Chromium for Playwright is not installed: the browser-level XSS check was not run")
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout.strip().splitlines()[-1])
    assert report["dialogs"] == [] and report["errors"] == []
    assert set(report["views"]) == {"runs", "detail", "trends", "replay"}
    for name, view in report["views"].items():
        assert view["scripts"] == 1, name  # only app.js
        assert view["imgs"] == 0 and view["jsLinks"] == 0 and view["handlers"] == 0, name
        assert view["pwned"] is False
    assert report["views"]["detail"]["literal"] and report["views"]["detail"]["jsText"]  # shown as text
