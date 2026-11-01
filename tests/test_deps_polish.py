"""Polish tests using offline, hand-authored OSV records (not live advisories)."""

import json
from pathlib import Path

from exhibit_a.advisory.deps_report import scan
from exhibit_a.advisory.osv import RecordedOsvBackend, parse_advisory
from exhibit_a.advisory.symbols import severity_label


def _record(advisory_id, aliases=(), *, severity=None, vector=None):
    record = {
        "id": advisory_id,
        "aliases": list(aliases),
        "summary": "Hand-authored test advisory",
        "affected": [{
            "package": {"name": "starlette", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}],
        }],
    }
    if severity is not None:
        record["database_specific"] = {"severity": severity}
    if vector is not None:
        record["severity"] = [{"type": "CVSS_V3", "score": vector}]
    return record


def _backend(*records):
    return RecordedOsvBackend(records, label="hand-authored-test-records")


def test_alias_records_are_one_row_with_unique_counts(tmp_path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "requirements.txt").write_text("starlette==0.26.1\n")
    (repo / "app.py").write_text(
        "from starlette.staticfiles import StaticFiles\n"
        "from starlette.routing import Mount\n"
        "from starlette.applications import Starlette\n\n"
        "app = Starlette(routes=[Mount('/', app=StaticFiles(directory='static'))])\n"
    )
    report = scan(
        repo,
        _backend(
            _record("GHSA-v5gw-mw7f-84px", ["CVE-2023-29159"]),
            _record("PYSEC-2023-83", ["GHSA-v5gw-mw7f-84px"]),
        ),
    ).report
    assert report.counts.advisories == report.counts.reachable == 1
    assert set(report.advisories[0].advisory_ids) == {
        "GHSA-v5gw-mw7f-84px", "PYSEC-2023-83", "CVE-2023-29159",
    }


def test_severity_prefers_database_specific():
    assert severity_label(parse_advisory(
        _record("A", severity="HIGH", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    )) == "HIGH"
    assert severity_label(parse_advisory(_record(
        "B", severity="CVSS_V3",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ))) == "CRITICAL"


def test_severity_computes_published_cvss_v3_scores():
    assert severity_label(parse_advisory(
        _record("A", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    )) == "CRITICAL"  # 9.8
    assert severity_label(parse_advisory(
        _record("B", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N")
    )) == "MODERATE"  # 5.4


def test_severity_falls_back_to_unrated():
    assert severity_label(parse_advisory(_record("A"))) == "unrated"
    assert severity_label(parse_advisory(
        _record("B", vector="CVSS_V3:unknown")
    )) == "unrated"


def test_starlette_demo_is_reachable_without_include_tests():
    root = Path(__file__).resolve().parents[1] / "bench" / "deps-demo" / "starlette-static-app"
    fixture = root / "osv.json"
    fixture.write_text(json.dumps({"vulns": [_record(
        "GHSA-v5gw-mw7f-84px", ["CVE-2023-29159"],
        severity="MODERATE",
    )]}), encoding="utf-8")
    try:
        report = scan(root, RecordedOsvBackend.from_file(fixture)).report
        assert report.advisories[0].reachability.status == "reachable"
    finally:
        fixture.unlink()
