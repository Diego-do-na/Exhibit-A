"""Shared helpers for the dashboard tests (no tests of its own).

Handler tests drive the real handler class over an in-memory request, like
tests/test_live.py, so they run where binding a socket is forbidden.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

from exhibit_a.dashboard.server import DashboardState, make_handler
from exhibit_a.dashboard.sources import LocalRunsSource

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web" / "dashboard"
FIXTURES = ROOT / "tests" / "fixtures" / "dashboard"
PORT = 8765
HOST = f"127.0.0.1:{PORT}"


def load_sample_script():
    spec = importlib.util.spec_from_file_location("make_sample_runs", ROOT / "scripts" / "make_sample_runs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_samples(tmp_path: Path) -> Path:
    out = tmp_path / "runs"
    assert load_sample_script().main([str(out)]) == 0
    return out


class _KeepBytes(io.BytesIO):
    def close(self):  # keep the buffer readable after handler teardown
        pass


class _FakeRequest:
    def __init__(self, raw: bytes):
        self._reader = io.BytesIO(raw)
        self.out = _KeepBytes()

    def makefile(self, mode, *args, **kwargs):
        return self._reader if "r" in mode else self.out

    def sendall(self, data: bytes):
        self.out.write(data)


def make_state(source, port: int = PORT) -> DashboardState:
    return DashboardState(source=source, web_dir=WEB_DIR, port=port)


def local_state(root: Path) -> DashboardState:
    return make_state(LocalRunsSource(root))


def request(state, target, method="GET", host=HOST, headers=None, verbose=False):
    """Send one request through the real handler; return (status, headers, body)."""
    lines = [f"{method} {target} HTTP/1.1"]
    if host is not None:
        lines.append(f"Host: {host}")
    for key, value in (headers or {}).items():
        lines.append(f"{key}: {value}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode()
    req = _FakeRequest(raw)
    make_handler(state)(req, ("127.0.0.1", 50000), SimpleNamespace(verbose=verbose))
    data = req.out.getvalue()
    head, _, body = data.partition(b"\r\n\r\n")
    status_line, *header_lines = head.decode("latin-1").split("\r\n")
    status = int(status_line.split()[1])
    parsed: dict[str, list[str]] = {}
    for line in header_lines:
        key, _, value = line.partition(":")
        parsed.setdefault(key.strip().lower(), []).append(value.strip())
    return status, parsed, body


def cookie_for(state) -> dict[str, str]:
    return {"Cookie": f"exhibit_a_dashboard={state.session}"}


def api(state, target, **kwargs):
    headers = {**cookie_for(state), **kwargs.pop("headers", {})}
    status, hdrs, body = request(state, target, headers=headers, **kwargs)
    return status, hdrs, (json.loads(body) if body and hdrs.get("content-type", [""])[0].startswith("application/json") else body)
