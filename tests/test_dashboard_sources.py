"""Dashboard run sources: local folders, the fake-gh GitHub source, schema rejection, caps."""

from __future__ import annotations

import io
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from exhibit_a.dashboard import sources
from exhibit_a.dashboard.sources import (
    GhError,
    GitHubSource,
    LocalRunsSource,
    SourceError,
    parse_ledger,
    parse_result,
    parse_source,
    read_artifact_zip,
    run_gh,
)
from test_dashboard_support import FIXTURES, make_samples


def event_line(run_id="r1", type_="scan_done", **payload):
    return json.dumps({"ts": "2026-10-20T10:00:00+00:00", "run_id": run_id, "type": type_, "payload": payload})


def write_run(root: Path, name: str, ledger: str | bytes, result: dict | None = None) -> Path:
    folder = root / name
    folder.mkdir(parents=True)
    (folder / "ledger.jsonl").write_bytes(ledger.encode() if isinstance(ledger, str) else ledger)
    if result is not None:
        (folder / "result.json").write_text(json.dumps(result))
    return folder


# -- local source -----------------------------------------------------------------------


def test_local_source_lists_and_loads_sample_runs(tmp_path):
    source = LocalRunsSource(make_samples(tmp_path))
    refs = {ref.run_id: ref for ref in source.list_runs()}
    assert len(refs) == 10
    ref = refs["synthetic-01-starlette-proven"]
    assert ref.synthetic is True and ref.pr == "41" and ref.commit == "3f1c9b7e2a4d"
    data = source.load_run("synthetic-01-starlette-proven")
    assert data.error == ""
    assert data.result["status"] == "completed"
    assert data.events and all(e.run_id == "syn01starlette" for e in data.events)


def test_local_source_works_without_an_index(tmp_path):
    write_run(tmp_path, "run-a", event_line() + "\n")
    refs = LocalRunsSource(tmp_path).list_runs()
    assert [r.run_id for r in refs] == ["run-a"]
    assert refs[0].repo == ""


def test_index_lines_pointing_outside_or_malformed_are_ignored():
    source = LocalRunsSource(FIXTURES / "hostile")
    refs = source.list_runs()
    assert [r.run_id for r in refs] == ["run-hostile"]
    # The hostile index entry is applied, but the commit is not a SHA, so it is dropped.
    assert refs[0].commit == ""


def test_unknown_or_invalid_run_ids_raise_key_error(tmp_path):
    write_run(tmp_path, "run-a", event_line() + "\n")
    source = LocalRunsSource(tmp_path)
    for bad in ("missing", "../run-a", "run-a/../run-a", "", ".hidden", "a" * 200):
        with pytest.raises(KeyError):
            source.load_run(bad)


def test_symlinked_run_folder_is_not_listed_or_loaded(tmp_path):
    real = write_run(tmp_path / "elsewhere", "secret", event_line() + "\n")
    root = tmp_path / "runs"
    root.mkdir()
    os.symlink(real, root / "linked")
    source = LocalRunsSource(root)
    assert source.list_runs() == []
    with pytest.raises(KeyError):
        source.load_run("linked")


def test_symlinked_ledger_is_refused(tmp_path):
    outside = tmp_path / "outside.jsonl"
    outside.write_text(event_line() + "\n")
    folder = tmp_path / "runs" / "run-a"
    folder.mkdir(parents=True)
    os.symlink(outside, folder / "ledger.jsonl")
    data = LocalRunsSource(tmp_path / "runs").load_run("run-a")
    assert data.events == [] and "symlink" in data.error


def test_fifo_ledger_is_refused_without_blocking(tmp_path):
    folder = tmp_path / "run-a"
    folder.mkdir()
    os.mkfifo(folder / "ledger.jsonl")
    data = LocalRunsSource(tmp_path).load_run("run-a")
    assert "regular file" in data.error


def test_missing_ledger_is_an_error_not_an_empty_run(tmp_path):
    folder = tmp_path / "run-a"
    folder.mkdir()
    (folder / "result.json").write_text("{}")
    data = LocalRunsSource(tmp_path).load_run("run-a")
    assert data.error == "ledger.jsonl is missing"


def test_appended_ledger_is_reloaded(tmp_path):
    folder = write_run(tmp_path, "run-a", event_line() + "\n")
    source = LocalRunsSource(tmp_path)
    assert len(source.load_run("run-a").events) == 1
    with (folder / "ledger.jsonl").open("a") as handle:
        handle.write(event_line(type_="baseline_done", ok=True) + "\n")
    assert len(source.load_run("run-a").events) == 2


def test_result_run_id_selects_the_run_inside_a_shared_ledger(tmp_path):
    ledger = "\n".join([event_line("first"), event_line("second"), event_line("first")]) + "\n"
    write_run(tmp_path, "run-a", ledger, {"schema_version": "1", "run_id": "first", "status": "completed"})
    data = LocalRunsSource(tmp_path).load_run("run-a")
    assert [e.run_id for e in data.events] == ["first", "first"]


# -- schema rejection ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "ledger, needle",
    [
        ("{not json}\n", "line 2: not valid JSON"),
        (event_line() + "\n[1, 2]\n", "line 3: not a valid Event"),
        (json.dumps({"ts": "x", "run_id": "r", "type": "not_a_type"}) + "\n", "not a valid Event"),
        (json.dumps({"ts": "x", "run_id": "r", "type": "scan_done", "extra": 1}) + "\n", "not a valid Event"),
        (json.dumps({"ts": "x", "run_id": "r", "type": "scan_done", "tokens_in": -5}) + "\n", "not a valid Event"),
        ('{"ts": "x", "run_id": "r", "type": "scan_done", "cost_usd": NaN}\n', "not valid JSON"),
        ('{"ts": "x", "run_id": "r", "type": "scan_done", "payload": ' + "[" * 50000 + "]" * 50000 + "}\n",
         # Python 3.11 refuses the nesting ("not valid JSON"); 3.14 parses it and the run is then
         # rejected as "not a valid Event". Either way the whole ledger is rejected on line 2.
         "line 2: not"),
    ],
)
def test_malformed_ledgers_are_rejected_whole(tmp_path, ledger, needle):
    write_run(tmp_path, "run-a", event_line() + "\n" + ledger)
    data = LocalRunsSource(tmp_path).load_run("run-a")
    assert data.events == []
    assert needle in data.error


def test_invalid_utf8_is_rejected():
    with pytest.raises(SourceError, match="UTF-8"):
        parse_ledger(b"\xff\xfe" + event_line().encode())


@pytest.mark.parametrize(
    "result",
    [
        {"schema_version": "1", "status": "safe"},
        {"schema_version": "1", "status": "completed", "risk": {"risk": "none"}},
        {"schema_version": "1", "status": "completed", "engine_exit": "0; rm -rf /"},
        {"status": "completed"},
        ["not", "an", "object"],
    ],
)
def test_malformed_result_json_makes_the_run_unreadable(tmp_path, result):
    write_run(tmp_path, "run-a", event_line() + "\n", result)
    data = LocalRunsSource(tmp_path).load_run("run-a")
    assert data.events == [] and data.error == "result JSON is not valid"


def test_result_json_counts_are_not_trusted():
    parsed = parse_result(json.dumps({"schema_version": "1", "status": "completed", "proven": 99}).encode())
    assert "proven" not in parsed


# -- caps ------------------------------------------------------------------------------


def test_ledger_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(sources, "MAX_LEDGER_BYTES", 200)
    write_run(tmp_path, "run-a", (event_line() + "\n") * 5)
    assert "larger than 200 bytes" in LocalRunsSource(tmp_path).load_run("run-a").error


def test_line_size_cap(monkeypatch):
    monkeypatch.setattr(sources, "MAX_LINE_BYTES", 100)
    with pytest.raises(SourceError, match="line 1 longer than 100 bytes"):
        parse_ledger(event_line(blob="x" * 200).encode())


def test_event_count_cap(monkeypatch):
    monkeypatch.setattr(sources, "MAX_EVENTS", 3)
    with pytest.raises(SourceError, match="more than 3 events"):
        parse_ledger(((event_line() + "\n") * 4).encode())


def test_result_size_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(sources, "MAX_RESULT_BYTES", 10)
    write_run(tmp_path, "run-a", event_line() + "\n", {"schema_version": "1", "status": "completed"})
    assert "result.json: larger than 10 bytes" in LocalRunsSource(tmp_path).load_run("run-a").error


def test_run_listing_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(sources, "MAX_RUNS", 3)
    for i in range(6):
        write_run(tmp_path, f"run-{i}", event_line() + "\n")
    assert len(LocalRunsSource(tmp_path).list_runs()) == 3


# -- GitHub source with a fake gh ------------------------------------------------------------


def artifact_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in files.items():
            archive.writestr(name, body)
    return buffer.getvalue()


class FakeGh:
    """Records every argv and answers from canned responses; never runs anything."""

    def __init__(self, responses: dict[str, bytes | Exception]):
        self.responses = responses
        self.calls: list[tuple[list[str], float, int]] = []

    def __call__(self, argv, timeout, max_bytes):
        self.calls.append((list(argv), timeout, max_bytes))
        endpoint = next(a for a in argv if a.startswith("repos/"))
        answer = self.responses[endpoint]
        if isinstance(answer, Exception):
            raise answer
        return answer


SAMPLE_LEDGER = (FIXTURES / "hostile" / "run-hostile" / "ledger.jsonl").read_bytes()


def gh_listing(*artifacts):
    return json.dumps({"total_count": len(artifacts), "artifacts": list(artifacts)}).encode()


def artifact(art_id, run_id, name="exhibit-a-ledger", expired=False, size=100):
    return {
        "id": art_id, "name": name, "size_in_bytes": size, "expired": expired,
        "created_at": f"2026-10-2{art_id % 10}T10:00:00Z",
        "workflow_run": {"id": run_id, "head_branch": "feature", "head_sha": "abcdef1234567"},
    }


def fake_github(extra=None):
    responses = {
        "repos/acme/app/actions/artifacts": gh_listing(
            artifact(11, 501), artifact(12, 502), artifact(13, 501), artifact(14, 503, expired=True),
            artifact(15, 504, name="something-else"),
        ),
        "repos/acme/app/actions/runs/501": json.dumps(
            {"id": 501, "head_sha": "0123456789abc", "head_branch": "pr-branch", "pull_requests": [{"number": 7}],
             "run_started_at": "2026-10-21T09:00:00Z", "html_url": "javascript:alert(1)"}
        ).encode(),
        "repos/acme/app/actions/artifacts/13/zip": artifact_zip(
            {"ledger.jsonl": SAMPLE_LEDGER, "result.json": b'{"schema_version": "1", "status": "completed"}', "other.txt": b"x"}
        ),
    }
    responses.update(extra or {})
    return FakeGh(responses)


def test_github_lists_runs_from_one_artifacts_call():
    gh = fake_github()
    source = GitHubSource("acme/app", gh=gh)
    refs = {r.run_id: r for r in source.list_runs()}
    assert set(refs) == {"501", "502"}  # expired and differently named artifacts skipped
    assert refs["501"].url == "https://github.com/acme/app/actions/runs/501"
    assert gh.calls[0][0] == [
        "api", "--method", "GET", "repos/acme/app/actions/artifacts",
        "-f", "name=exhibit-a-ledger", "-f", "per_page=100",
    ]
    source.list_runs()
    assert len(gh.calls) == 1  # listing cached


def test_github_listing_cache_expires():
    now = [0.0]
    gh = fake_github()
    source = GitHubSource("acme/app", gh=gh, clock=lambda: now[0])
    source.list_runs()
    now[0] += sources.LIST_TTL + 1
    source.list_runs()
    assert len(gh.calls) == 2


def test_github_loads_the_newest_artifact_in_memory():
    gh = fake_github()
    data = GitHubSource("acme/app", gh=gh).load_run("501")
    assert data.error == ""
    assert data.ref.pr == "7" and data.ref.commit == "0123456789abc" and data.ref.branch == "pr-branch"
    assert data.ref.url == "https://github.com/acme/app/actions/runs/501"  # html_url from GitHub is not used
    assert len(data.events) == 14
    zip_call = gh.calls[-1]
    assert zip_call[0] == ["api", "--method", "GET", "repos/acme/app/actions/artifacts/13/zip"]
    assert zip_call[2] == sources.MAX_GH_OUTPUT


def test_github_failure_is_reported_and_not_cached():
    gh = fake_github({"repos/acme/app/actions/artifacts/13/zip": GhError("gh exited with 1: HTTP 410")})
    source = GitHubSource("acme/app", gh=gh)
    assert "HTTP 410" in source.load_run("501").error
    gh.responses["repos/acme/app/actions/artifacts/13/zip"] = artifact_zip({"ledger.jsonl": SAMPLE_LEDGER})
    assert source.load_run("501").error == ""


def test_github_rejects_unknown_and_non_numeric_ids():
    source = GitHubSource("acme/app", gh=fake_github())
    for bad in ("999", "abc", "501; rm -rf /", "1" * 30):
        with pytest.raises(KeyError):
            source.load_run(bad)


def test_github_schema_mismatch_is_an_error():
    gh = fake_github({"repos/acme/app/actions/artifacts": b'{"artifacts": [{"id": "x"}]}'})
    with pytest.raises(GhError, match="expected schema"):
        GitHubSource("acme/app", gh=gh).list_runs()


def test_github_oversized_artifact_is_not_downloaded():
    gh = fake_github({"repos/acme/app/actions/artifacts": gh_listing(artifact(13, 501, size=sources.MAX_GH_OUTPUT + 1))})
    data = GitHubSource("acme/app", gh=gh).load_run("501")
    assert "artifact larger than" in data.error
    assert not any("zip" in a for call in gh.calls for a in call[0])


@pytest.mark.parametrize(
    "repo",
    ["acme", "acme/app/extra", "acme/..", "acme/.", "-acme/app", "acme/app;rm -rf /", "acme/$(id)", "acme /app", "a" * 40 + "/x", "acme/app\n"],
)
def test_github_repo_is_validated(repo):
    with pytest.raises(SourceError, match="invalid repository"):
        GitHubSource(repo, gh=fake_github())


def test_github_artifact_name_is_validated():
    with pytest.raises(SourceError, match="invalid artifact"):
        GitHubSource("acme/app", artifact="--jq=.", gh=fake_github())


def test_artifact_zip_caps_and_ignores_nested_entries(monkeypatch):
    nested = artifact_zip({"dir/ledger.jsonl": b"x", "../ledger.jsonl": b"y"})
    assert read_artifact_zip(nested) == (None, None)
    monkeypatch.setattr(sources, "MAX_LEDGER_BYTES", 100)
    with pytest.raises(SourceError, match="larger than 100 bytes"):
        read_artifact_zip(artifact_zip({"ledger.jsonl": b"z" * 10_000}))
    with pytest.raises(SourceError, match="not a valid zip"):
        read_artifact_zip(b"PK\x03\x04garbage")


def test_artifact_zip_entry_count_cap(monkeypatch):
    monkeypatch.setattr(sources, "MAX_ZIP_ENTRIES", 2)
    with pytest.raises(SourceError, match="more than 2 entries"):
        read_artifact_zip(artifact_zip({f"f{i}": b"" for i in range(3)}))


# -- the real gh runner, against a fake executable on PATH ----------------------------------


def fake_gh_on_path(tmp_path, monkeypatch, script: str) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "gh"
    exe.write_text("#!/bin/sh\n" + script)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}/usr/bin{os.pathsep}/bin")
    return bindir


def test_run_gh_passes_argv_without_a_shell(tmp_path, monkeypatch):
    fake_gh_on_path(tmp_path, monkeypatch, 'for a in "$@"; do printf "%s\\n" "$a"; done\n')
    marker = tmp_path / "pwned"
    out = run_gh(["api", f"$(touch {marker})", "a;b"], 5, 10_000)
    assert out.decode().splitlines() == ["api", f"$(touch {marker})", "a;b"]
    assert not marker.exists()


def test_run_gh_times_out(tmp_path, monkeypatch):
    fake_gh_on_path(tmp_path, monkeypatch, "exec sleep 5\n")
    with pytest.raises(GhError, match="timed out"):
        run_gh(["api"], 0.5, 1000)


def test_run_gh_caps_output(tmp_path, monkeypatch):
    fake_gh_on_path(tmp_path, monkeypatch, "i=0; while [ $i -lt 2000 ]; do echo 0123456789012345678901234567890123456789; i=$((i+1)); done\n")
    with pytest.raises(GhError, match="larger than 1000 bytes"):
        run_gh(["api"], 5, 1000)


def test_run_gh_failure_redacts_tokens(tmp_path, monkeypatch):
    fake_gh_on_path(tmp_path, monkeypatch, 'echo "bad credentials ghp_abcdefghijklmnop1234" >&2; exit 4\n')
    with pytest.raises(GhError) as info:
        run_gh(["api"], 5, 1000)
    assert "exited with 4" in str(info.value)
    assert "ghp_" not in str(info.value)


def test_run_gh_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(GhError, match="not found"):
        run_gh(["api"], 1, 10)


# -- --source parsing ------------------------------------------------------------------------


def test_parse_source(tmp_path):
    assert isinstance(parse_source(f"local:{tmp_path}"), LocalRunsSource)
    assert isinstance(parse_source("github:acme/app", gh=fake_github()), GitHubSource)
    for bad in ("", "local:", "s3:bucket", f"{tmp_path}", f"local:{tmp_path}/missing"):
        with pytest.raises(SourceError):
            parse_source(bad)


def test_identifier_patterns_reject_a_trailing_newline():
    assert not sources.RUN_ID_RE.match("run-a\n")
    assert not sources.ARTIFACT_RE.match("exhibit-a-ledger\n")
