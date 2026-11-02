"""Static dashboard export contract tests."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from exhibit_a.dashboard import export_dashboard
from exhibit_a.dashboard import server as server_mod
from exhibit_a.dashboard.sources import LocalRunsSource, SourceError
from test_dashboard_support import make_samples


def _files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


def _digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in _files(root):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _export(tmp_path: Path, *, run_id: str | None = None) -> tuple[Path, Path]:
    runs = make_samples(tmp_path)
    output = tmp_path / "export"
    export_dashboard(LocalRunsSource(runs), output, run_id=run_id)
    return runs, output


def test_export_is_self_contained_and_uses_relative_references(tmp_path: Path):
    _, output = _export(tmp_path, run_id="synthetic-01-starlette-proven")
    names = {path.relative_to(output).as_posix() for path in _files(output)}
    assert {
        "index.html",
        "pr.html",
        "dc-lite.js",
        "dashboard.css",
        "views/index.js",
        "static.js",
        "data/info.json",
        "data/runs.json",
        "data/trends.json",
        "data/run.json",
        "runs/synthetic-01-starlette-proven/ledger.jsonl",
        "runs/synthetic-01-starlette-proven/result.json",
    } <= names

    # The self-hosted fonts ship with their SIL OFL licence texts, which cite the licence's
    # home page as text; nothing loads them. Every other exported byte must be URL-free.
    licences = {name for name in names if name.startswith("fonts/LICENSE-") and name.endswith(".txt")}
    assert {"fonts/LICENSE-lora.txt", "fonts/LICENSE-ibm-plex-sans.txt", "fonts/LICENSE-jetbrains-mono.txt"} <= licences
    assert any(name.endswith(".woff2") for name in names)
    generated = b"\n".join(path.read_bytes() for path in _files(output)
                           if path.relative_to(output).as_posix() not in licences)
    assert not re.search(rb"https?://", generated)
    assert b"file://" not in generated
    html = (output / "index.html").read_text(encoding="utf-8")
    references = re.findall(r"""(?:src|href)="([^"]+)""", html)
    assert {"dashboard.css", "dc-lite.js", "views/index.js", "prs.html"} <= set(references)
    assert all(re.fullmatch(r"[a-z]+\.html|dashboard\.css|dc-lite\.js|views/[a-z]+\.js", value) for value in references)
    assert not re.search(r"""(?:src|href)=["'](?:/|[A-Za-z]:[\\/])""", html)
    assert json.loads((output / "data/run.json").read_text(encoding="utf-8"))["ledger"].startswith("runs/")


@pytest.mark.parametrize("run_id", ["../run", "/tmp/run", r"C:\run", "run\0id", "run/../other"])
def test_export_rejects_path_traversal_run_ids(tmp_path: Path, run_id: str):
    runs = make_samples(tmp_path)
    with pytest.raises(SourceError):
        export_dashboard(LocalRunsSource(runs), tmp_path / "export", run_id=run_id)


def test_hostile_text_round_trips_as_data_not_markup(tmp_path: Path):
    runs = tmp_path / "runs"
    hostile = runs / "hostile-run"
    hostile.mkdir(parents=True)
    events = [
        {
            "ts": "2026-10-20T10:00:00+00:00",
            "run_id": "ledger-run",
            "type": "pr_opened",
            "payload": {
                "repo": "<script>alert(1)</script>",
                "title": "<img src=x onerror=alert(1)>",
                "pr": "1",
                "commit": "javascript:alert(1)",
                "branch": "<b>branch</b>",
                "synthetic": True,
            },
        },
        {
            "ts": "2026-10-20T10:00:01+00:00",
            "run_id": "ledger-run",
            "type": "suspicion_raised",
            "role": "<script>role</script>",
            "model": "hostile",
            "payload": {
                "suspicion": {
                    "id": "<b>S1</b>",
                    "class": "<script>class</script>",
                    "location": {"file": "<img src=x>", "line": 7},
                    "entry_point": "handler",
                    "hypothesis": "<script>hypothesis</script>",
                }
            },
        },
        {
            "ts": "2026-10-20T10:00:02+00:00",
            "run_id": "ledger-run",
            "type": "verdict",
            "payload": {
                "suspicion_id": "<b>S1</b>",
                "verdict": "proven",
                "reason": "<script>reason</script>",
            },
        },
    ]
    (hostile / "ledger.jsonl").write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "export"
    export_dashboard(LocalRunsSource(runs), output, run_id="hostile-run")

    data = json.loads((output / "data/run.json").read_text(encoding="utf-8"))
    assert data["detail"]["proven"][0]["id"] == "<b>S1</b>"
    assert data["events"]["events"][0]["payload"]["title"] == "<img src=x onerror=alert(1)>"
    static = (output / "static.js").read_text(encoding="utf-8")
    assert "<script>" not in static and "</script>" not in static
    assert "<img" not in static
    assert "<script>" not in (output / "index.html").read_text(encoding="utf-8")


def test_export_is_deterministic(tmp_path: Path):
    runs = make_samples(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    source = LocalRunsSource(runs)
    export_dashboard(source, first, run_id="synthetic-01-starlette-proven")
    export_dashboard(source, second, run_id="synthetic-01-starlette-proven")
    assert _digest(first) == _digest(second)
    assert [(p.relative_to(first).as_posix(), p.read_bytes()) for p in _files(first)] == [
        (p.relative_to(second).as_posix(), p.read_bytes()) for p in _files(second)
    ]


def test_open_is_off_by_default(monkeypatch, tmp_path: Path):
    runs = make_samples(tmp_path)
    opened: list[str] = []

    class FakeServer:
        state = type("State", (), {"port": 8765, "bootstrap_url": lambda self: "http://127.0.0.1:8765/auth?token=x"})()

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            pass

    monkeypatch.setattr(server_mod, "create_server", lambda *args, **kwargs: FakeServer())
    monkeypatch.setattr(server_mod.webbrowser, "open", opened.append)
    assert server_mod.main(["--source", f"local:{runs}"]) == 0
    assert opened == []
