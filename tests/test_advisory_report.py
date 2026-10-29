import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from exhibit_a.advisory import (
    PinnedDependency,
    RecordedOsvBackend,
    lookup,
    parse_requirements,
    reachability_hint,
)
from exhibit_a.schemas import AdvisoryMatch

HERE = Path(__file__).parent
FIXTURE = HERE / "fixtures" / "advisory" / "osv_synthetic.json"
PROJECT = HERE / "fixtures" / "advisory" / "project"
SCHEMA_FILE = HERE.parent / "src" / "exhibit_a" / "schemas" / "advisory_match.schema.json"


@pytest.fixture(scope="module")
def report():
    deps = parse_requirements((PROJECT / "requirements.txt").read_text()).dependencies
    return lookup(deps, RecordedOsvBackend.from_file(FIXTURE), project_root=PROJECT,
                  import_names={"fictional-yamlish": ["yamlish"]})


def _by_id(report, vid):
    return next(m for m in report.matches if m.advisory_id == vid)


def test_counts(report):
    assert sorted(m.advisory_id for m in report.matches) == [
        "SYNTH-2026-0001", "SYNTH-2026-0002", "SYNTH-2026-0004", "SYNTH-2026-0007"]
    assert report.packages_checked == 5  # fictional-safe>=1.0 is not a pin
    assert report.withdrawn == 1  # SYNTH-2026-0003
    assert report.unevaluable == 1  # SYNTH-2026-0005, GIT range only
    assert report.not_affected == 1  # SYNTH-2026-0006, 0.2.0 not in the version list
    assert report.data_source == "recorded"
    assert any("none of them is a proven finding" in n for n in report.notes)


def test_patch_available_minor_upgrade(report):
    m = _by_id(report, "SYNTH-2026-0001")
    assert m.package == "fictional-webkit"
    assert m.installed_version == "2.3.0"
    assert m.dependency_source == "requirements.txt:2"
    assert m.aliases == ["CVE-0000-0001"]
    assert m.affected_status == "affected"
    assert m.fixed_in == "2.4.1"
    assert m.patch_available is True
    assert m.upgrade_kind == "minor"
    assert m.upgrade_is_minor_or_major is True
    assert m.evidence_urls[0] == f"fixture://{FIXTURE}#SYNTH-2026-0001"
    assert "https://advisories.example.invalid/SYNTH-2026-0001" in m.evidence_urls
    assert m.severity[0].type == "CVSS_V3"
    assert m.signal == "advisory_hint" and m.schema_version == "1"


def test_no_fix_known(report):
    m = _by_id(report, "SYNTH-2026-0002")
    assert m.fixed_in is None
    assert m.patch_available is False
    assert m.upgrade_kind is None and m.upgrade_is_minor_or_major is None


def test_major_upgrade_semver(report):
    m = _by_id(report, "SYNTH-2026-0004")
    assert (m.fixed_in, m.upgrade_kind, m.upgrade_is_minor_or_major) == ("2.0.0", "major", True)


def test_patch_upgrade_is_not_minor_or_major(report):
    m = _by_id(report, "SYNTH-2026-0007")
    assert m.fixed_in == "1.0.0.post1"
    assert (m.upgrade_kind, m.upgrade_is_minor_or_major) == ("patch", False)


def test_reachability_hint_with_symbol(report):
    hint = _by_id(report, "SYNTH-2026-0001").reachability
    assert hint.kind == "static_hint"
    assert hint.package_imported is True
    assert hint.import_sites == ["app/server.py:3"]
    assert hint.symbols_referenced == ["fictional_webkit.static.serve_file"]
    assert "app/server.py:7" in hint.symbol_sites
    assert hint.files_skipped == 1  # app/broken.py does not parse
    assert any("hint only" in n for n in hint.notes)


def test_reachability_import_without_symbol(report):
    hint = _by_id(report, "SYNTH-2026-0004").reachability
    assert hint.package_imported is True
    assert hint.import_sites == ["app/config.py:3"]
    assert hint.symbols_listed == ["yamlish.loader.unsafe_load"]
    assert hint.symbols_referenced == []


def test_reachability_not_imported(report):
    hint = _by_id(report, "SYNTH-2026-0007").reachability
    assert hint.package_imported is False
    assert any("lists no affected symbols" in n for n in hint.notes)


def test_reachability_name_match_without_import_is_ignored(tmp_path):
    (tmp_path / "a.py").write_text("def serve_file():\n    return 1\n")
    hint = reachability_hint(tmp_path, "fictional-webkit", ["fictional_webkit.static.serve_file"])
    assert hint.package_imported is False
    assert hint.symbols_referenced == []


def test_reachability_skips_venv_and_symlinks(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "x.py").write_text("import fictional_webkit\n")
    (tmp_path / "real.py").write_text("import os\n")
    (tmp_path / "link.py").symlink_to(tmp_path / ".venv" / "x.py")
    hint = reachability_hint(tmp_path, "fictional-webkit", [])
    assert hint.package_imported is False
    assert hint.files_scanned == 1 and hint.files_skipped == 1


def test_marker_is_reported_not_evaluated():
    dep = PinnedDependency("fictional-webkit", "2.3.0", "x:1", marker='sys_platform == "win32"')
    report = lookup([dep], RecordedOsvBackend.from_file(FIXTURE))
    m = next(m for m in report.matches if m.advisory_id == "SYNTH-2026-0001")
    assert 'environment marker not evaluated: sys_platform == "win32"' in m.notes
    assert m.reachability is None


def test_duplicate_dependencies_reported_once():
    dep = PinnedDependency("fictional-tiny", "0.1.0", "a:1")
    again = PinnedDependency("fictional-tiny", "0.1.0", "b:1")
    report = lookup([dep, again], RecordedOsvBackend.from_file(FIXTURE))
    assert [m.advisory_id for m in report.matches] == ["SYNTH-2026-0006"]


def test_json_roundtrip_validates(report):
    data = json.loads(report.to_json())
    assert data["schema_version"] == "1"
    for item in data["matches"]:
        assert AdvisoryMatch.model_validate(item).model_dump(mode="json") == item


def test_schema_is_strict(report):
    item = report.matches[0].model_dump(mode="json")
    with pytest.raises(ValidationError):
        AdvisoryMatch.model_validate({**item, "verdict": "proven"})
    with pytest.raises(ValidationError):
        AdvisoryMatch.model_validate({**item, "signal": "proven"})
    with pytest.raises(ValidationError):
        AdvisoryMatch.model_validate({**item, "schema_version": "2"})


def test_schema_file_matches_model():
    on_disk = json.loads(SCHEMA_FILE.read_text())
    assert on_disk == AdvisoryMatch.model_json_schema(), (
        "regenerate advisory_match.schema.json from exhibit_a.schemas.advisory.AdvisoryMatch")


def test_live_backend_unevaluable_is_unverified():
    record = {"id": "SYNTH-2026-0099", "affected": [{
        "package": {"name": "fictional-gitonly", "ecosystem": "PyPI"},
        "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}]}

    class LiveLike(RecordedOsvBackend):
        source = "live"

    report = lookup([PinnedDependency("fictional-gitonly", "1.0.0", "x:1")], LiveLike([record]))
    (m,) = report.matches
    assert m.affected_status == "unverified"
    assert m.patch_available is False
    assert m.data_source == "live"
