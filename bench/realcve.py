"""Benchmark on real CVEs: vulnerable release proven, patched release silent.

``python -m bench.realcve --list`` prints every manifest entry.

``python -m bench.realcve --offline-check`` validates the manifest and, for
every entry, stages its harness app in a temp directory and runs a probe
test against it in the sandbox (Docker) with the vulnerable and the fixed
package version installed. No model is involved.

``python -m bench.realcve --live ...`` (owner only: it spends real money and
needs Docker) runs the normal verification loop on the vulnerable and on
the fixed version of every entry whose oracle effect is implemented, then
writes ``bench/results/realcve-<date>.json`` and regenerates the table in
``docs/bench/real-cves.md``. Entries with effect ``pending`` are listed in
the table as pending and are never run: an effect the oracle cannot observe
yet is reported, never silently dropped.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REALCVE_DIR = HERE / "realcve"
MANIFEST_PATH = REALCVE_DIR / "manifest.json"
RESULTS_DIR = HERE / "results"
DOC_PATH = Path(__file__).resolve().parent.parent / "docs" / "bench" / "real-cves.md"

IMPLEMENTED_EFFECTS = ("canary_read", "canary_write", "canary_exec", "canary_sql")
PENDING_EFFECT = "pending"
EFFECTS = IMPLEMENTED_EFFECTS + (PENDING_EFFECT,)
CLASSES = (
    "path_traversal",
    "archive_extraction",
    "command_injection",
    "deserialization",
    "ssti",
    "sql_injection",
    "ssrf",
    "redos",
    "xss",
)


def _fail(message: str) -> ValueError:
    return ValueError(f"{MANIFEST_PATH}: {message}")


def load_manifest(path: str | Path = MANIFEST_PATH) -> dict:
    """Read and strictly validate the manifest; return the parsed mapping."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path}: cannot be read: {exc}") from exc
    except ValueError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise _fail("expected a mapping with an 'entries' list")
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        raise _fail("expected a non-empty 'entries' list")
    seen: set[str] = set()
    for raw in entries:
        _check_entry(raw, seen)
    return data


def _check_entry(raw: object, seen: set[str]) -> None:
    if not isinstance(raw, dict):
        raise _fail(f"entry {raw!r} is not a mapping")
    for key in ("id", "cve", "package", "vulnerable_version", "fixed_version",
                "vulnerable_api", "class", "effect", "entry_point", "harness"):
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            raise _fail(f"entry {raw.get('id')!r}: {key!r} must be a non-empty string")
    entry_id = raw["id"]
    if entry_id in seen:
        raise _fail(f"duplicate entry id {entry_id!r}")
    seen.add(entry_id)
    if raw["vulnerable_version"] == raw["fixed_version"]:
        raise _fail(f"entry {entry_id!r}: vulnerable and fixed versions are identical")
    if raw["effect"] not in EFFECTS:
        raise _fail(f"entry {entry_id!r}: unknown effect {raw['effect']!r}")
    if raw["class"] not in CLASSES:
        raise _fail(f"entry {entry_id!r}: unknown class {raw['class']!r}")
    advisories = raw.get("advisories")
    if not isinstance(advisories, list) or not advisories:
        raise _fail(f"entry {entry_id!r}: expected a non-empty 'advisories' list")
    for advisory in advisories:
        if not isinstance(advisory, dict):
            raise _fail(f"entry {entry_id!r}: advisory {advisory!r} is not a mapping")
        url = advisory.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            raise _fail(f"entry {entry_id!r}: advisory has no http(s) url")
    harness = REALCVE_DIR / raw["harness"]
    if not harness.is_file():
        raise _fail(f"entry {entry_id!r}: harness {raw['harness']!r} not found")
    if raw["effect"] == "canary_sql":
        for key in ("sql_db", "seed_sql"):
            if not isinstance(raw.get(key), str) or not raw.get(key):
                raise _fail(f"entry {entry_id!r}: {key!r} is required for canary_sql")
        seed = harness.parent / raw["seed_sql"]
        if not seed.is_file():
            raise _fail(f"entry {entry_id!r}: seed {raw['seed_sql']!r} not found")


def requirements_for(entry: dict, version: str) -> list[str]:
    """Pip requirements pinning ``entry`` at ``version`` (vulnerable or fixed)."""
    if version == "vulnerable":
        if isinstance(entry.get("requirements"), list) and entry["requirements"]:
            return [str(item) for item in entry["requirements"]]
        return [f"{entry['package']}=={entry['vulnerable_version']}"]
    if version == "fixed":
        if isinstance(entry.get("fixed_requirements"), list) and entry["fixed_requirements"]:
            return [str(item) for item in entry["fixed_requirements"]]
        return [f"{entry['package']}=={entry['fixed_version']}"]
    raise ValueError(f"unknown version label {version!r}")


def version_number(entry: dict, version: str) -> str:
    """The package version string for the ``vulnerable`` or ``fixed`` run."""
    if version == "vulnerable":
        return str(entry["vulnerable_version"])
    if version == "fixed":
        return str(entry["fixed_version"])
    raise ValueError(f"unknown version label {version!r}")


def _probe_test(entry_point: str) -> str:
    return (
        "def test_harness_entry_point_declared():\n"
        "    import app\n"
        f"    assert callable(getattr(app, {entry_point!r})), "
        f"\"app.{entry_point} must be a callable entry point\"\n"
    )


def stage_import_check(entry: dict, work: Path) -> Path:
    """Stage the harness app plus a probe test; return the test path."""
    harness = REALCVE_DIR / entry["harness"]
    shutil.copyfile(harness, work / "app.py")
    probe = work / "test_entry_probe.py"
    probe.write_text(_probe_test(entry["entry_point"]), encoding="utf-8")
    return probe


def check_import(entry: dict, version: str, timeout: float = 600.0) -> dict[str, str]:
    """Import the harness in the sandbox with one pinned version installed."""
    from exhibit_a.sandbox import run as sandbox_run

    with tempfile.TemporaryDirectory(prefix="exhibit_a_realcve_") as tmp:
        work = Path(tmp)
        probe = stage_import_check(entry, work)
        result = sandbox_run(
            str(work), str(probe), timeout,
            requirements=requirements_for(entry, version),
        )
    outcome = str(result.get("outcome", ""))
    if outcome == "passed":
        return {"id": entry["id"], "version": version, "ok": True, "detail": ""}
    detail = (result.get("stderr") or result.get("stdout") or outcome)[-2000:]
    return {"id": entry["id"], "version": version, "ok": False, "detail": detail}


def cmd_list(entries: list[dict]) -> int:
    for entry in entries:
        pending = " (pending effect)" if entry["effect"] == PENDING_EFFECT else ""
        print(
            f"{entry['id']}: {entry['package']} "
            f"{entry['vulnerable_version']} -> {entry['fixed_version']} "
            f"[{entry['class']}/{entry['effect']}] "
            f"{entry['entry_point']} in {entry['harness']}{pending}"
        )
    return 0


def cmd_offline_check(entries: list[dict]) -> int:
    """Import every harness against both versions in the sandbox; no model."""
    failures = 0
    for entry in entries:
        for version in ("vulnerable", "fixed"):
            pinned = version_number(entry, version)
            print(
                f"realcve: importing {entry['id']} "
                f"with {entry['package']}=={pinned} ...",
                flush=True,
            )
            try:
                report = check_import(entry, version)
            except Exception as exc:  # noqa: BLE001 - one broken entry must not kill the run
                report = {"id": entry["id"], "version": version, "ok": False, "detail": str(exc)}
            status = "ok" if report["ok"] else "FAIL"
            print(f"realcve:   [{status}] {entry['id']} ({version})")
            if report["detail"]:
                print(f"realcve:   {report['detail'][-500:]}")
            if not report["ok"]:
                failures += 1
    if failures:
        print(f"realcve: offline-check failed for {failures} import(s)", file=sys.stderr)
        return 1
    print(f"realcve: offline-check passed for {len(entries)} entries x 2 versions")
    return 0


def stage_live_run(entry: dict, work: Path) -> tuple[Path, str, str | None]:
    """Stage a loop clone for one entry; return (clone, source_file, sql_db).

    The clone holds the harness app, a baseline test that only checks the
    entry point exists (so it passes on both versions), and, for canary_sql,
    a database built from the harness seed file.
    """
    harness = REALCVE_DIR / entry["harness"]
    clone = work / "clone"
    clone.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(harness, clone / "app.py")
    (clone / "test_baseline.py").write_text(
        "def test_entry_point_declared():\n"
        "    import app\n"
        f"    assert callable(getattr(app, {entry['entry_point']!r}))\n",
        encoding="utf-8",
    )
    sql_db = entry.get("sql_db") if entry["effect"] == "canary_sql" else None
    if sql_db:
        seed = harness.parent / entry["seed_sql"]
        db_path = clone / sql_db
        db_path.parent.mkdir(parents=True, exist_ok=True)
        if db_path.exists():
            db_path.unlink()
        connection = sqlite3.connect(db_path)
        try:
            connection.executescript(seed.read_text(encoding="utf-8"))
            connection.commit()
        finally:
            connection.close()
    return clone, "app.py", sql_db


def build_live_roles(provider: str, model: str, profile: str, meter):  # noqa: ANN001, ANN202
    """Build one role per model backend through the provider registry."""
    from exhibit_a.models import Role
    from exhibit_a.models.config import RoleConfig, build_roles

    compact = profile == "compact"
    caps = {
        Role.ADVERSARY: 6000,
        Role.TEST_WRITER: 8000,
        Role.FIXER: 6000,
        Role.DEFENDER: 10000,
    }
    config = {}
    for role in Role:
        config[role] = RoleConfig(
            provider=provider,
            model=model,
            reasoning_effort="minimal" if compact else "",
            max_output_tokens=caps[role] if compact else 0,
        )
    by_role = build_roles(config, meter)
    from exhibit_a.loop import Roles

    return Roles(by_role[Role.ADVERSARY], by_role[Role.TEST_WRITER],
                 by_role[Role.FIXER], by_role[Role.DEFENDER])


def run_one_live(entry: dict, version: str, *, provider: str, model: str,
                 profile: str, runs: int, meter, ledger, out_dir: Path) -> dict:  # noqa: ANN001
    """Run the normal loop for one entry at one version; return its reading."""
    from exhibit_a.loop import VerificationLoop
    from exhibit_a.loop.runner import SandboxRunner

    run_id = f"realcve:{entry['id']}:{version}"
    with tempfile.TemporaryDirectory(prefix="exhibit_a_realcve_live_") as tmp:
        clone, source, sql_db = stage_live_run(entry, Path(tmp))
        requirements = requirements_for(entry, version)
        runner = SandboxRunner(requirements=tuple(requirements),
                               sql_db=sql_db if isinstance(sql_db, str) else None)
        roles = build_live_roles(provider, model, profile, meter)
        loop = VerificationLoop(
            clone, out_dir, ledger, roles, "test_baseline.py",
            run_id=run_id, runner=runner, requirements=tuple(requirements),
            judge=runner.run_exploit, effect=entry["effect"],
            prompt_profile=profile, runs=runs,
            sql_db=sql_db if isinstance(sql_db, str) else None,
        )
        result = loop.run(source)
    totals = ledger.totals(run_id)
    return {
        "version": version_number(entry, version),
        "proven": bool(result.proven),
        "aborted": result.aborted,
        "cost_usd": totals["cost_usd"],
        "tokens": totals["tokens_in"] + totals["tokens_out"],
    }


def run_live(entries: list[dict], *, provider: str, model: str, profile: str,
             runs: int, total_usd: float, out_dir: Path,
             pipeline=None) -> list[dict]:  # noqa: ANN001
    """Run every implemented-effect entry at both versions; honour the budget.

    ``pipeline`` defaults to the real loop (``run_one_live``); tests inject
    a stub. A BudgetExceeded anywhere marks that reading and everything after
    it ``stopped`` without starting another model call.
    """
    from exhibit_a.ledger import Ledger
    from exhibit_a.models import BudgetExceeded
    from exhibit_a.models.cost import CostMeter

    if profile not in ("standard", "compact"):
        raise ValueError(f"unknown profile {profile!r}")
    meter = CostMeter(total_usd)
    ledger = Ledger(out_dir / "ledger.jsonl")
    pipeline = pipeline or _default_pipeline(
        provider=provider, model=model, profile=profile, runs=runs,
        meter=meter, ledger=ledger, out_dir=out_dir,
    )
    rows: list[dict] = []
    stopped = False
    for entry in entries:
        row: dict = {
            "id": entry["id"], "cve": entry["cve"], "package": entry["package"],
            "class": entry["class"], "effect": entry["effect"],
        }
        if entry["effect"] == PENDING_EFFECT:
            row["status"] = "pending"
            rows.append(row)
            continue
        for version in ("vulnerable", "fixed"):
            if stopped:
                row[version] = {"status": "stopped"}
                continue
            try:
                meter.check()
                row[version] = pipeline(entry, version)
            except BudgetExceeded as exc:
                row[version] = {"status": "stopped", "detail": str(exc)}
                stopped = True
            except Exception as exc:  # noqa: BLE001 - one broken entry must not kill the run
                row[version] = {"status": "error", "detail": str(exc)[:500]}
        row["status"] = "stopped" if stopped else "ok"
        rows.append(row)
    return rows


def _default_pipeline(*, provider, model, profile, runs, meter, ledger, out_dir):  # noqa: ANN001, ANN202
    def pipeline(entry: dict, version: str) -> dict:
        return run_one_live(
            entry, version, provider=provider, model=model, profile=profile,
            runs=runs, meter=meter, ledger=ledger, out_dir=out_dir,
        )

    return pipeline


def write_results(rows: list[dict], *, provider: str, model: str, profile: str,
                  runs: int, out_dir: Path) -> Path:
    """Write the dated results JSON; return its path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = out_dir / f"realcve-{stamp}.json"
    payload = {
        "date": stamp,
        "provider": provider,
        "model": model,
        "profile": profile,
        "runs": runs,
        "entries": rows,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def render_table(rows: list[dict]) -> str:
    """Render the results table: one row per entry."""
    header = (
        "# Real CVEs\n\n"
        "Vulnerable release proven, patched release silent. "
        "A green result means nothing could be proven, never safe. "
        "Entries with a pending effect are listed, never silently dropped.\n\n"
        "| CVE | package | class | vulnerable: proven? | fixed: false proof? | cost (USD) | tokens |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
    )
    lines = [header]
    for row in rows:
        if row.get("effect") == PENDING_EFFECT or row.get("status") == "pending":
            lines.append(
                f"| {row['cve']} | {row['package']} | {row['class']} "
                f"| pending effect | pending effect | - | - |\n"
            )
            continue
        vuln = row.get("vulnerable", {})
        fixed = row.get("fixed", {})
        if vuln.get("status") not in (None, "ok") or fixed.get("status") not in (None, "ok"):
            proved_v = proved_f = "stopped"
        else:
            proved_v = "yes" if vuln.get("proven") else "no"
            proved_f = "PROOF (bad)" if fixed.get("proven") else "no proof"
        cost = (vuln.get("cost_usd", 0.0) or 0.0) + (fixed.get("cost_usd", 0.0) or 0.0)
        tokens = (vuln.get("tokens", 0) or 0) + (fixed.get("tokens", 0) or 0)
        lines.append(
            f"| {row['cve']} | {row['package']} | {row['class']} "
            f"| {proved_v} | {proved_f} | {cost:.4f} | {tokens} |\n"
        )
    return "".join(lines)


def cmd_live(args: argparse.Namespace, entries: list[dict]) -> int:
    rows = run_live(
        entries, provider=args.provider, model=args.model, profile=args.profile,
        runs=args.runs, total_usd=args.total_usd, out_dir=RESULTS_DIR,
    )
    results_path = write_results(
        rows, provider=args.provider, model=args.model,
        profile=args.profile, runs=args.runs, out_dir=RESULTS_DIR,
    )
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text(render_table(rows), encoding="utf-8")
    print(f"realcve: wrote {results_path} and {DOC_PATH}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench.realcve",
                                     description="Benchmark Exhibit A on real CVEs.")
    parser.add_argument("--list", action="store_true", help="list manifest entries")
    parser.add_argument("--offline-check", action="store_true",
                        help="validate the manifest and import every harness "
                             "against both versions in the sandbox (no model)")
    parser.add_argument("--live", action="store_true",
                        help="run the normal loop on both versions (owner only: "
                             "spends real money, needs Docker)")
    parser.add_argument("--provider", default="meta")
    parser.add_argument("--model", default="muse-wonder-1.0")
    parser.add_argument("--profile", default="compact", choices=["standard", "compact"])
    parser.add_argument("--total-usd", type=float, default=50.0)
    parser.add_argument("--runs", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest()
    except ValueError as exc:
        print(f"realcve: {exc}", file=sys.stderr)
        return 2
    entries = manifest["entries"]
    if args.offline_check:
        return cmd_offline_check(entries)
    if args.live:
        if args.total_usd <= 0:
            print("realcve: --total-usd must be positive", file=sys.stderr)
            return 2
        if args.runs < 1:
            print("realcve: --runs must be at least 1", file=sys.stderr)
            return 2
        return cmd_live(args, entries)
    return cmd_list(entries)


if __name__ == "__main__":
    raise SystemExit(main())
