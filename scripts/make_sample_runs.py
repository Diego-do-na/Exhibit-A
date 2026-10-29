"""Generate SYNTHETIC run folders for the local dashboard.

Every run written here is made up: realistic in shape (the same ledger event
payloads ``loop/pipeline.py`` emits, the same result.json ``ci/summary.py``
writes) but not the output of a real Exhibit A run. Each run is labelled
synthetic three times: ``synthetic: true`` in its ``pr_opened`` payload, in
the ``runs.jsonl`` index, and in the README written next to the runs.

Two cases are covered, matching the corpus:

- Starlette ``StaticFiles`` path traversal (CVE-2023-29159), effect
  ``canary_read``: proven on the vulnerable release, nothing proven on the
  fixed one.
- Archive extraction path traversal (zip-slip, analog of CVE-2007-4559),
  effect ``canary_write``: proven, plus an incomplete fix that a defender
  bypass variant defeats.

Plus the outcomes a dashboard must word carefully: an aborted baseline, a
risk-gate skip, flaky and env_failure verdicts.

Usage::

    python scripts/make_sample_runs.py runs-sample
    python -m exhibit_a.dashboard --source local:runs-sample
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from exhibit_a.ci.summary import build_result  # noqa: E402
from exhibit_a.ledger import Ledger  # noqa: E402
from exhibit_a.schemas import Event  # noqa: E402

MODEL = "synthetic-model"
STARLETTE_REPO = "example-org/starlette-app (synthetic)"
ARCHIVE_REPO = "example-org/archive-service (synthetic)"
START = datetime(2026, 10, 15, 14, 0, tzinfo=timezone.utc)
FULL_FLAGS = {"naive": False, "oracle": True, "differential": True, "defender": True}


class RunWriter:
    """Builds one synthetic run: events with a running clock, then files."""

    def __init__(self, name: str, run_id: str, start: datetime) -> None:
        self.name = name
        self.run_id = run_id
        self.clock = start
        self.events: list[Event] = []

    def emit(self, type_: str, seconds: float = 1.0, role: str = "", tokens: tuple[int, int] = (0, 0), **payload: Any) -> None:
        self.clock += timedelta(seconds=seconds)
        cost = round((tokens[0] * 0.2 + tokens[1] * 0.6) / 1_000_000, 6)
        self.events.append(
            Event(
                ts=self.clock.isoformat(),
                run_id=self.run_id,
                type=type_,
                role=role,
                model=MODEL if role else "",
                tokens_in=tokens[0],
                tokens_out=tokens[1],
                cost_usd=cost,
                latency_ms=int(seconds * 1000) if role else 0,
                payload=payload,
            )
        )

    def write(self, out: Path, meta: dict[str, Any], risk: str, engine_exit: int = 0, skipped: str = "") -> dict[str, Any]:
        folder = out / self.name
        folder.mkdir(parents=True, exist_ok=True)
        ledger_path = folder / "ledger.jsonl"
        if ledger_path.exists():
            ledger_path.unlink()  # the ledger API only appends; start each sample fresh
        ledger_path.touch()
        ledger = Ledger(ledger_path)
        for event in self.events:
            ledger.append(event)
        result = build_result(
            self.events,
            run_id=self.run_id,
            engine_exit=engine_exit,
            risk={"risk": risk, "should_run_exploits": risk != "low", "reasons": {}},
            skipped_reason=skipped,
        )
        (folder / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        stamp = (self.events[-1] if self.events else None)
        when = datetime.fromisoformat(stamp.ts) if stamp else self.clock
        os.utime(ledger_path, (when.timestamp(), when.timestamp()))
        return {"dir": self.name, "run_id": self.run_id, "started_at": self.clock_start, "synthetic": True, **meta}

    @property
    def clock_start(self) -> str:
        return self.events[0].ts if self.events else self.clock.isoformat()


def frame(file: str, function: str, qualname: str, line: int, admitted: bool | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"file": file, "function": function, "qualname": qualname, "line": line}
    if admitted is not None:
        out["admitted"] = admitted
        out["admission"] = "staged app code" if admitted else "outside the app tree"
    return out


STARLETTE_STACK = [
    frame("/workspace/test_exploit.py", "test_static_files_traversal", "test_static_files_traversal", 18, False),
    frame("/usr/local/lib/python3.11/site-packages/httpx/_client.py", "get", "Client.get", 1045),
    frame("<thread boundary>", "<thread boundary>", "<thread boundary>", 0),
    frame("/workspace/app/main.py", "app", "app", 12, True),
    frame("/workspace/starlette/staticfiles.py", "get_response", "StaticFiles.get_response", 129, True),
    frame("/workspace/starlette/staticfiles.py", "lookup_path", "StaticFiles.lookup_path", 162, True),
    frame("/workspace/starlette/responses.py", "__call__", "FileResponse.__call__", 328, True),
]

ARCHIVE_STACK = [
    frame("/workspace/test_exploit.py", "test_member_escapes_destination", "test_member_escapes_destination", 21, False),
    frame("/workspace/archive.py", "handle_request", "App.handle_request", 44, True),
    frame("/workspace/archive.py", "extract_all", "extract_all", 27, True),
    frame("/workspace/archive.py", "_write_member", "_write_member", 15, True),
]


def suspicion(sid: str, cls: str, file: str, line: int, entry: str, hypothesis: str) -> dict[str, Any]:
    return {"id": sid, "class": cls, "location": {"file": file, "line": line}, "entry_point": entry, "hypothesis": hypothesis, "source": "adversary"}


def opening(w: RunWriter, meta: dict[str, Any], baseline_ok: bool = True) -> None:
    w.emit("pr_opened", 0, repo=meta["repo"], pr=meta["pr"], commit=meta["commit"], branch=meta["branch"], synthetic=True, title=meta["title"])
    w.emit("scan_done", 2, language="python", test_cmd="pytest -q", framework=meta.get("framework", ""))
    w.emit("baseline_done", 41 if baseline_ok else 23, ok=baseline_ok, outcome="passed" if baseline_ok else "failed", flags=FULL_FLAGS)


def proven_chain(
    w: RunWriter,
    s: dict[str, Any],
    *,
    canary: str,
    mode: str,
    stack: list[dict[str, Any]],
    reason: str,
    bypasses: list[tuple[str, bool]],
    fix_holds: bool = True,
) -> None:
    sid = s["id"]
    w.emit("exploit_written", 14, role="test_writer", tokens=(5200, 900), suspicion_id=sid, test_path=f"work/{sid.lower()}/test_exploit.py")
    for n in (1, 2, 3):
        w.emit("run_started", 1, suspicion_id=sid, run=n, of=3)
        event = {"type": "canary_read", "path": canary, "mode": mode, "stack": stack, "via_symlink": False, "symlink": None, "symlink_target": None}
        w.emit("oracle_event", 9, suspicion_id=sid, run=n, event=event)
    w.emit("verdict", 1, suspicion_id=sid, verdict="proven", reason=reason)
    w.emit("fix_proposed", 19, role="fixer", tokens=(6100, 1400), suspicion_id=sid, applied=True)
    for n in (1, 2, 3):
        w.emit("run_started", 8, suspicion_id=sid, on="fixed", run=n, of=3)
    w.emit("baseline_done", 38, suspicion_id=sid, on="fixed", ok=True)
    for i, (name, bypassed) in enumerate(bypasses):
        w.emit("bypass_attempt", 12 if i == 0 else 1, role="defender" if i == 0 else "", tokens=(4800, 1100) if i == 0 else (0, 0), suspicion_id=sid, name=name)
        w.emit("bypass_result", 9, suspicion_id=sid, name=name, bypassed=bypassed)
    w.emit("packaged", 1, suspicion_id=sid, path=f"packages/{sid.lower()}", fix_verified=fix_holds)


def discarded(w: RunWriter, s: dict[str, Any], verdict: str, reason: str, runs: int = 1) -> None:
    sid = s["id"]
    if verdict != "invalid_test":
        w.emit("exploit_written", 11, role="test_writer", tokens=(4300, 700), suspicion_id=sid, test_path=f"work/{sid.lower()}/test_exploit.py")
        for n in range(1, runs + 1):
            w.emit("run_started", 1, suspicion_id=sid, run=n, of=3)
            if verdict == "flaky" and n == 1:
                event = {"type": "canary_read", "path": "/tmp/exhibit_a_oracle/outside/canary.txt", "mode": "r", "stack": STARLETTE_STACK, "via_symlink": False}
                w.emit("oracle_event", 7, suspicion_id=sid, run=n, event=event)
    w.emit("verdict", 4, suspicion_id=sid, verdict=verdict, reason=reason)


def starlette_meta(pr: int, commit: str, title: str) -> dict[str, Any]:
    return {"repo": STARLETTE_REPO, "pr": str(pr), "commit": commit, "branch": f"pr-{pr}", "title": title, "framework": "starlette"}


def archive_meta(pr: int, commit: str, title: str) -> dict[str, Any]:
    return {"repo": ARCHIVE_REPO, "pr": str(pr), "commit": commit, "branch": f"pr-{pr}", "title": title, "framework": ""}


S_STATIC = suspicion(
    "S1", "path_traversal", "starlette/staticfiles.py", 162, "StaticFiles.get_response",
    "lookup_path joins the request path onto the directory and checks the prefix with os.path.commonprefix, "
    "so a sibling directory sharing the prefix (static vs static_secret) is served.",
)
S_HEADERS = suspicion("S2", "header_injection", "starlette/responses.py", 61, "Response.init_headers", "A filename with CRLF reaches Content-Disposition unescaped.")
S_RANGE = suspicion("S3", "path_traversal", "starlette/staticfiles.py", 141, "StaticFiles.get_path", "URL-encoded %2e%2e segments survive normalisation.")
S_ZIP = suspicion(
    "Z1", "archive_extraction_path_traversal", "archive.py", 27, "App.handle_request",
    "extract_all joins member names onto the destination without containment, so '../' or absolute names write outside it.",
)
S_ZIP_SIZE = suspicion("Z2", "resource_exhaustion", "archive.py", 33, "App.handle_request", "No cap on the total uncompressed size (zip bomb).")


def build(out: Path) -> list[dict[str, Any]]:
    index: list[dict[str, Any]] = []
    day = timedelta(days=1)

    # 1. Starlette, vulnerable release: proven (canary_read), two discarded.
    meta = starlette_meta(41, "3f1c9b7e2a4d", "Serve uploads from /static")
    w = RunWriter("synthetic-01-starlette-proven", "syn01starlette", START)
    opening(w, meta)
    w.emit("suspicion_raised", 22, role="adversary", tokens=(9800, 1600), suspicion=S_STATIC)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_HEADERS)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_RANGE)
    proven_chain(
        w, S_STATIC, canary="/tmp/exhibit_a_oracle/outside/canary.txt", mode="rb", stack=STARLETTE_STACK,
        reason="canary read through StaticFiles.get_response from staged app code",
        bypasses=[("encoded dot segments", False), ("sibling prefix with trailing slash", False)],
    )
    discarded(w, S_HEADERS, "discarded_unproven", "the exploit passed: no CRLF reached the response headers", runs=1)
    discarded(w, S_RANGE, "invalid_test", "no usable exploit test: the test imported a module that does not exist")
    index.append(w.write(out, meta, "high"))

    # 2. Starlette, fixed release: nothing could be proven.
    meta = starlette_meta(44, "1797de46c0aa", "Bump starlette to 0.27.0")
    w = RunWriter("synthetic-02-starlette-fixed", "syn02starfixed", START + 2 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 19, role="adversary", tokens=(9400, 1200), suspicion=S_STATIC)
    discarded(w, S_STATIC, "discarded_unproven", "no canary read observed: the exploit request got a 404", runs=1)
    index.append(w.write(out, meta, "high"))

    # 3. Archive extraction: proven (canary_write).
    meta = archive_meta(7, "a0c4e1d9b3f2", "Accept tar uploads for bulk import")
    w = RunWriter("synthetic-03-archive-proven", "syn03archive", START + 3 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 17, role="adversary", tokens=(6900, 1100), suspicion=S_ZIP)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_ZIP_SIZE)
    proven_chain(
        w, S_ZIP, canary="/tmp/exhibit_a_oracle/outside/canary.txt", mode="wb", stack=ARCHIVE_STACK,
        reason="canary created outside the destination by App.handle_request",
        bypasses=[("absolute member name", False), ("symlink member then write", False)],
    )
    discarded(w, S_ZIP_SIZE, "discarded_unproven", "no oracle for resource exhaustion in this class set", runs=1)
    index.append(w.write(out, meta, "medium"))

    # 4. Archive extraction, incomplete fix: proven, a defender variant bypasses the fix.
    meta = archive_meta(9, "c71e0b55d8a3", "Reject '..' in archive member names")
    w = RunWriter("synthetic-04-archive-incomplete-fix", "syn04archfix", START + 5 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 15, role="adversary", tokens=(7100, 1000), suspicion=S_ZIP)
    proven_chain(
        w, S_ZIP, canary="/tmp/exhibit_a_oracle/outside/canary.txt", mode="xb", stack=ARCHIVE_STACK,
        reason="canary created outside the destination by App.handle_request",
        bypasses=[("dot-dot member name", False), ("absolute member name", True)],
    )
    index.append(w.write(out, meta, "medium"))

    # 5. Baseline failed: aborted, nothing could be proven.
    meta = starlette_meta(46, "9be2207d41c0", "Refactor middleware stack")
    w = RunWriter("synthetic-05-aborted-baseline", "syn05aborted", START + 6 * day)
    opening(w, meta, baseline_ok=False)
    index.append(w.write(out, meta, "medium", engine_exit=1))

    # 6. Risk gate: docs-only change, exploits skipped.
    meta = archive_meta(11, "5d3a9f0e7b21", "Docs: clarify upload limits")
    w = RunWriter("synthetic-06-skipped-docs", "syn06skipped", START + 7 * day)
    w.emit("pr_opened", 0, repo=meta["repo"], pr=meta["pr"], commit=meta["commit"], branch=meta["branch"], synthetic=True, title=meta["title"])
    index.append(w.write(out, meta, "low", skipped="documentation and tests only"))

    # 7. Flaky and env_failure verdicts: nothing could be proven.
    meta = starlette_meta(48, "e8b14c02f6d9", "Cache static file stats")
    w = RunWriter("synthetic-07-flaky-env", "syn07flaky", START + 9 * day)
    opening(w, meta)
    w.emit("suspicion_raised", 21, role="adversary", tokens=(10200, 1500), suspicion=S_STATIC)
    w.emit("suspicion_raised", 0, role="adversary", suspicion=S_HEADERS)
    discarded(w, S_STATIC, "flaky", "unstable across runs: run 2 saw no canary read", runs=2)
    discarded(w, S_HEADERS, "env_failure", "run 1 could not execute: sandbox image build timed out", runs=1)
    index.append(w.write(out, meta, "high"))

    # 8-10. More history for the trends chart.
    for k, (pr, commit, title, proven) in enumerate(
        [
            (50, "0f9d2c6b8e14", "Add /exports static mount", True),
            (52, "7a2e5c9d1b06", "Tighten CORS settings", False),
            (55, "b4e81f3a6c29", "Serve avatars from user dirs", True),
        ]
    ):
        meta = starlette_meta(pr, commit, title)
        w = RunWriter(f"synthetic-{8 + k:02d}-starlette-pr{pr}", f"syn{8 + k:02d}pr{pr}", START + (11 + 2 * k) * day)
        opening(w, meta)
        w.emit("suspicion_raised", 18, role="adversary", tokens=(9100, 1300), suspicion=S_STATIC)
        w.emit("suspicion_raised", 0, role="adversary", suspicion=S_RANGE)
        if proven:
            proven_chain(
                w, S_STATIC, canary="/tmp/exhibit_a_oracle/outside/canary.txt", mode="rb", stack=STARLETTE_STACK,
                reason="canary read through StaticFiles.get_response from staged app code",
                bypasses=[("encoded dot segments", False)],
            )
        else:
            discarded(w, S_STATIC, "discarded_unproven", "the exploit passed: the request was confined", runs=1)
        discarded(w, S_RANGE, "invalid_test" if k != 1 else "discarded_unproven", "the exploit failed before reaching the app (wrong reason)", runs=1)
        index.append(w.write(out, meta, "high"))
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write SYNTHETIC run folders for the dashboard.")
    parser.add_argument("out", help="Directory to create (must be empty or absent unless --force).")
    parser.add_argument("--force", action="store_true", help="Rewrite the synthetic folders in a non-empty directory.")
    args = parser.parse_args(argv)
    out = Path(args.out)
    if out.exists() and any(out.iterdir()) and not args.force:
        print(f"make_sample_runs: {out} is not empty (use --force)", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    index = build(out)
    (out / "runs.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in index), encoding="utf-8")
    (out / "README.txt").write_text(
        "SYNTHETIC SAMPLE RUNS. Generated by scripts/make_sample_runs.py.\n"
        "These are not results of real Exhibit A runs; they only exercise the dashboard.\n",
        encoding="utf-8",
    )
    print(f"make_sample_runs: wrote {len(index)} synthetic runs to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
