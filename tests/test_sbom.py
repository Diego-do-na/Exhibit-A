"""T110: CycloneDX 1.5 SBOM with VEX states derived from Exhibit A evidence.

Offline: hand-authored OSV records (labelled as such, never copies of a real
record) and stub :class:`Enrichment` values; no network. The Starlette-shaped
case uses the well-known CVE/GHSA ids only as identifier strings.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from exhibit_a.advisory import RecordedOsvBackend
from exhibit_a.advisory.deps_report import scan
from exhibit_a.advisory.enrich import Enrichment
from exhibit_a.cli import main as cli_main
from exhibit_a.report.sbom import (
    BOM_FORMAT,
    SPEC_VERSION,
    analysis_for,
    generate_sbom,
    validate_sbom,
)
from exhibit_a.schemas.advisory import DependencyProof

STARLETTE_ADVISORY = {
    "id": "GHSA-v5gw-mw7f-84px",
    "aliases": ["CVE-2023-29159"],
    "summary": "Hand-authored test fixture: path traversal in StaticFiles.",
    "details": "Hand-authored test fixture, not a copy of any real record.",
    "modified": "2023-06-01T00:00:00Z",
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-22"]},
    "affected": [{
        "package": {"name": "starlette", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0.13.5"},
                                                   {"fixed": "0.27.0"}]}],
    }],
    "references": [{"type": "ADVISORY",
                    "url": "https://github.com/encode/starlette/security/advisories/GHSA-v5gw-mw7f-84px"}],
}

STARLETTE_ENRICHMENT = Enrichment(
    advisory_id="GHSA-v5gw-mw7f-84px", cves=("CVE-2023-29159",),
    ghsa=("GHSA-v5gw-mw7f-84px",), epss=0.01234, epss_percentile=0.56789, kev=True,
)

APP_MOUNTED = {
    "requirements.txt": "starlette==0.26.1\n",
    "app.py": (
        "from starlette.applications import Starlette\n"
        "from starlette.routing import Mount\n"
        "from starlette.staticfiles import StaticFiles\n\n\n"
        "def create_app(directory):\n"
        "    return Starlette(routes=[Mount('/static', app=StaticFiles(directory=directory),"
        " name='static')])\n"
    ),
}

APP_NEVER_MOUNTED = {
    "requirements.txt": "starlette==0.26.1\n",
    "app.py": ("from starlette.staticfiles import StaticFiles\n\n"
               "FILES = StaticFiles(directory='static')\n"),
}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def _backend(*records: dict) -> RecordedOsvBackend:
    return RecordedOsvBackend(list(records), label="test-fixture")


def _enrichment() -> dict[str, Enrichment]:
    return {"GHSA-v5gw-mw7f-84px": STARLETTE_ENRICHMENT}


def _only_reachable(tmp_path: Path, files: dict[str, str] = APP_MOUNTED):
    repo = _write(tmp_path / "repo", files)
    report = scan(repo, _backend(STARLETTE_ADVISORY)).report
    assert len(report.advisories) == 1
    return repo, report


def _with_proof(report, status: str, **extra):
    item = report.advisories[0]
    proof = DependencyProof(status=status, reason=extra.pop("reason", "test"),
                            effect=item.effect, entry_point=item.reachability.paths[0].oracle_entry_point
                            if item.reachability.paths else "",
                            package=extra.pop("package", ""), **extra)
    return item.model_copy(update={"proof": proof})


def test_components_list_the_pinned_dependencies(tmp_path) -> None:
    repo, report = _only_reachable(tmp_path)
    sbom = generate_sbom(repo, report, _enrichment())
    assert sbom["bomFormat"] == BOM_FORMAT and sbom["specVersion"] == SPEC_VERSION
    assert sbom["components"] == [{
        "type": "library", "bom-ref": "pkg:pypi/starlette@0.26.1", "name": "starlette",
        "version": "0.26.1", "purl": "pkg:pypi/starlette@0.26.1",
        "properties": [{"name": "exhibit-a:dependency-source", "value": "requirements.txt:1"}],
    }]
    validate_sbom(sbom)


def test_unproven_advisory_is_in_triage(tmp_path) -> None:
    repo, report = _only_reachable(tmp_path)
    vuln = generate_sbom(repo, report, _enrichment())["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2023-29159" and vuln["bom-ref"] == "GHSA-v5gw-mw7f-84px"
    assert vuln["analysis"]["state"] == "in_triage"
    assert "triage pending" in vuln["analysis"]["detail"]
    assert vuln["affects"] == [{"ref": "pkg:pypi/starlette@0.26.1"}]
    methods = {r["method"] for r in vuln["ratings"]}
    assert methods == {"CVSSv3", "EPSS"}
    assert vuln["properties"] and \
        {"name": "exhibit-a:kev", "value": "true"} in vuln["properties"]
    assert any("CISA" in a["title"] for a in vuln["advisories"])
    assert any("GHSA-v5gw-mw7f-84px" in a["url"] for a in vuln["advisories"])


def test_proven_advisory_is_exploitable_with_the_bundle_path(tmp_path) -> None:
    repo, report = _only_reachable(tmp_path)
    proven = report.model_copy(update={"advisories": [
        _with_proof(report, "proven", package="deps/ghsa-starlette/packages/s1")]})
    vuln = generate_sbom(repo, proven, _enrichment())["vulnerabilities"][0]
    assert vuln["analysis"]["state"] == "exploitable"
    assert "deps/ghsa-starlette/packages/s1" in vuln["analysis"]["detail"]


def test_graph_with_no_path_is_not_affected_with_caveat(tmp_path) -> None:
    repo, report = _only_reachable(tmp_path, APP_NEVER_MOUNTED)
    item = report.advisories[0]
    assert item.reachability.status == "not_reachable"
    analysis = analysis_for(item)
    assert analysis["state"] == "not_affected"
    assert analysis["justification"] == "code_not_reachable"
    assert "not a proof of safety" in analysis["detail"]
    sbom = generate_sbom(repo, report, _enrichment())
    assert sbom["vulnerabilities"][0]["analysis"]["state"] == "not_affected"
    validate_sbom(sbom)


UNKNOWN_ADVISORY = {
    "id": "SYNTH-2026-0099",
    "aliases": [],
    "summary": "Hand-authored test fixture: no symbol named anywhere.",
    "modified": "2026-01-01T00:00:00Z",
    "affected": [{
        "package": {"name": "starlette", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                   {"fixed": "99.0"}]}],
    }],
}


def test_failed_proof_and_unknown_symbol_stay_in_triage(tmp_path) -> None:
    repo, report = _only_reachable(tmp_path)
    not_proven = report.model_copy(update={"advisories": [
        _with_proof(report, "not_proven", reason="the exploit passes on the fixed tree")]})
    assert analysis_for(not_proven.advisories[0])["state"] == "in_triage"
    # No affected symbol anywhere (not in the record, not in the map): unknown,
    # and a verdict-like string never promotes it to not_affected.
    plain_repo = _write(tmp_path / "plain", APP_MOUNTED)
    unknown = scan(plain_repo, _backend(UNKNOWN_ADVISORY)).report
    assert unknown.advisories[0].reachability.status == "unknown"
    assert analysis_for(unknown.advisories[0])["state"] == "in_triage"


def test_sboms_without_deps_json_list_components_only(tmp_path) -> None:
    repo = _write(tmp_path / "repo", APP_MOUNTED)
    sbom = generate_sbom(repo)
    assert len(sbom["components"]) == 1 and sbom["vulnerabilities"] == []
    validate_sbom(sbom)


def test_kev_false_and_missing_enrichment(tmp_path) -> None:
    repo, report = _only_reachable(tmp_path)
    plain = Enrichment(advisory_id="GHSA-v5gw-mw7f-84px", cves=("CVE-2023-29159",))
    vuln = generate_sbom(repo, report, {"GHSA-v5gw-mw7f-84px": plain})["vulnerabilities"][0]
    assert {"name": "exhibit-a:kev", "value": "false"} in vuln["properties"]
    assert all("CISA" not in a["title"] for a in vuln["advisories"])
    assert {r["method"] for r in vuln["ratings"]} == {"CVSSv3"}  # no EPSS without a score
    no_enrich = generate_sbom(repo, report)["vulnerabilities"][0]
    assert no_enrich["analysis"]["state"] == "in_triage"


def test_validate_sbom_rejects_missing_vex_fields(tmp_path) -> None:
    repo, report = _only_reachable(tmp_path)
    sbom = generate_sbom(repo, report, _enrichment())
    bad = json.loads(json.dumps(sbom))
    del bad["vulnerabilities"][0]["analysis"]
    with pytest.raises(ValueError):
        validate_sbom(bad)
    bad = json.loads(json.dumps(sbom))
    bad["vulnerabilities"][0]["analysis"] = {"state": "exploitable"}
    bad["vulnerabilities"][0]["affects"] = []
    with pytest.raises(ValueError):
        validate_sbom(bad)
    with pytest.raises(ValueError):
        validate_sbom({"bomFormat": "CycloneDX"})
    with pytest.raises(ValueError):
        validate_sbom({**sbom, "vulnerabilities": [
            {**sbom["vulnerabilities"][0], "analysis": {"state": "not_affected"}}]})


def test_cli_sbom_writes_a_file_offline(tmp_path, monkeypatch) -> None:
    import exhibit_a.cli.ext.sbom as sbom_ext

    repo, report = _only_reachable(tmp_path)
    deps_json = tmp_path / "deps.json"
    deps_json.write_text(json.dumps(report.model_dump(mode="json")), encoding="utf-8")
    monkeypatch.setattr(sbom_ext, "_live_enrichment", lambda report, cache: _enrichment())
    out = tmp_path / "out" / "sbom.json"
    assert cli_main(["sbom", "--repo", str(repo), "--deps-json", str(deps_json),
                     "--output", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    validate_sbom(data)
    assert data["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_cli_sbom_rejects_a_missing_repo(tmp_path, capsys) -> None:
    assert cli_main(["sbom", "--repo", str(tmp_path / "absent")]) == 2
    assert "does not exist" in capsys.readouterr().err
