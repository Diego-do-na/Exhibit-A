"""Hostile advisory input (audit F12): huge numbers, deep nesting, bad records, redirects."""

import io
import json
import urllib.request

import pytest

from exhibit_a.advisory import osv as osv_module
from exhibit_a.advisory.deps import PinnedDependency
from exhibit_a.advisory.osv import (
    AdvisoryDataError,
    HttpOsvBackend,
    RecordedOsvBackend,
    _HttpsOnlyRedirects,
    evaluate,
    parse_advisory,
)
from exhibit_a.advisory.report import lookup
from exhibit_a.advisory.version import InvalidVersion, Version, semver_key

HUGE = "9" * 4301


class _Reply(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeOpener:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, request, timeout):
        self.calls.append((request.get_method(), request.full_url))
        payload = self.routes[(request.get_method(), request.full_url.split("/v1", 1)[1])]
        return _Reply(payload if isinstance(payload, bytes) else json.dumps(payload).encode())


def _advisory(vid, introduced="0", fixed="1.0"):
    return {
        "id": vid, "modified": "2026-01-01T00:00:00Z", "summary": "synthetic",
        "affected": [{"package": {"name": "pkg", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": introduced}, {"fixed": fixed}]}]}],
    }


# ------------------------------------------------------------------ version components


@pytest.mark.parametrize("text", [
    HUGE, f"1.{HUGE}", f"{HUGE}!1.0", f"1.0a{HUGE}", f"1.0.post{HUGE}", f"1.0.dev{HUGE}",
    f"1.0+local.{HUGE}",
])
def test_numeric_components_over_the_cap_are_invalid(text):
    with pytest.raises(InvalidVersion):
        Version.parse(text)


def test_cap_boundary():
    assert Version.parse("1." + "9" * 20).release[1] == int("9" * 20)
    with pytest.raises(InvalidVersion):
        Version.parse("1." + "9" * 21)


def test_semver_components_over_the_cap_are_invalid():
    with pytest.raises(InvalidVersion):
        semver_key(f"{HUGE}.0.0")
    with pytest.raises(InvalidVersion):
        semver_key(f"1.0.0-{HUGE}")


def test_evaluate_with_a_huge_version_does_not_raise():
    entry = parse_advisory(_advisory("SYNTH-1")).affected[0]
    assert evaluate(entry, HUGE).affected is None
    huge_event = parse_advisory(_advisory("SYNTH-2", fixed=HUGE)).affected[0]
    assert evaluate(huge_event, "0.5").affected is None


def test_lookup_survives_a_huge_fixed_version():
    backend = RecordedOsvBackend([_advisory("SYNTH-3", fixed=HUGE)])
    report = lookup([PinnedDependency("pkg", "0.5", "requirements.txt:1")], backend)
    assert report.candidates_seen == 1


# ------------------------------------------------------------------ deep nesting


def test_deeply_nested_json_is_a_data_error_not_a_crash():
    nested = b"[" * 2_000_000 + b"]" * 2_000_000
    backend = HttpOsvBackend(opener=FakeOpener({("POST", "/querybatch"): nested}),
                             max_response_bytes=10_000_000)
    with pytest.raises(AdvisoryDataError):
        backend.query([("pkg", "1.0")])


def test_recursion_error_while_parsing_a_reply_becomes_a_data_error(monkeypatch):
    def boom(_payload):
        raise RecursionError

    monkeypatch.setattr(osv_module.json, "loads", boom)
    backend = HttpOsvBackend(opener=FakeOpener({("POST", "/querybatch"): b"{}"}))
    with pytest.raises(AdvisoryDataError, match="nested too deeply"):
        backend.query([("pkg", "1.0")])


def test_recorded_fixture_nested_too_deeply_is_a_data_error(tmp_path, monkeypatch):
    path = tmp_path / "f.json"
    path.write_text("{}")

    def boom(_fh):
        raise RecursionError

    monkeypatch.setattr(osv_module.json, "load", boom)
    with pytest.raises(AdvisoryDataError, match="nested too deeply"):
        RecordedOsvBackend.from_file(path)


def test_recursion_error_while_evaluating_is_a_data_error(monkeypatch):
    backend = RecordedOsvBackend([_advisory("SYNTH-4")])

    def boom(*_a, **_k):
        raise RecursionError

    monkeypatch.setattr("exhibit_a.advisory.report._match", boom)
    with pytest.raises(AdvisoryDataError):
        lookup([PinnedDependency("pkg", "0.5", "requirements.txt:1")], backend)


# ------------------------------------------------------------------ per-record isolation


def test_recorded_bad_record_is_skipped_and_reported():
    backend = RecordedOsvBackend(["not an object", _advisory("SYNTH-5")])
    report = lookup([PinnedDependency("pkg", "0.5", "requirements.txt:1")], backend)
    assert [m.advisory_id for m in report.matches] == ["SYNTH-5"]
    assert any("record #0 skipped" in note for note in report.notes)


def test_live_bad_record_is_skipped_and_reported():
    routes = {
        ("POST", "/querybatch"): {"results": [{"vulns": [{"id": "BAD"}, {"id": "SYNTH-6"}]}]},
        ("GET", "/vulns/BAD"): {"id": "BAD", "affected": "nope"},
        ("GET", "/vulns/SYNTH-6"): _advisory("SYNTH-6"),
    }
    backend = HttpOsvBackend(opener=FakeOpener(routes))
    report = lookup([PinnedDependency("pkg", "0.5", "requirements.txt:1")], backend)
    assert [m.advisory_id for m in report.matches] == ["SYNTH-6"]
    assert any("BAD skipped" in note for note in report.notes)


def test_ids_per_package_are_capped():
    ids = [{"id": f"SYNTH-{i}"} for i in range(50)]
    routes = {("POST", "/querybatch"): {"results": [{"vulns": ids}]}}
    routes.update({("GET", f"/vulns/SYNTH-{i}"): _advisory(f"SYNTH-{i}") for i in range(50)})
    opener = FakeOpener(routes)
    out = HttpOsvBackend(opener=opener, max_ids_per_package=5).query([("pkg", "0.5")])
    assert len(out[("pkg", "0.5")]) == 5
    assert sum(1 for method, _ in opener.calls if method == "GET") == 5


def test_capped_ids_show_up_in_the_report_notes():
    ids = [{"id": f"SYNTH-{i}"} for i in range(4)]
    routes = {("POST", "/querybatch"): {"results": [{"vulns": ids}]}}
    routes.update({("GET", f"/vulns/SYNTH-{i}"): _advisory(f"SYNTH-{i}") for i in range(4)})
    backend = HttpOsvBackend(opener=FakeOpener(routes), max_ids_per_package=2)
    report = lookup([PinnedDependency("pkg", "0.5", "requirements.txt:1")], backend)
    assert any("only the first 2" in note for note in report.notes)


# ------------------------------------------------------------------ redirects


def _redirect(newurl):
    req = urllib.request.Request("https://api.osv.dev/v1/vulns/X")
    return _HttpsOnlyRedirects().redirect_request(req, None, 302, "Found", {}, newurl)


def test_non_https_redirect_is_refused():
    for target in ("http://api.osv.dev/v1/vulns/X", "ftp://example.org/x", "file:///etc/passwd"):
        with pytest.raises(AdvisoryDataError, match="non-https"):
            _redirect(target)


def test_https_redirect_is_followed():
    assert _redirect("https://api.osv.dev/v1/vulns/Y").full_url == "https://api.osv.dev/v1/vulns/Y"


def test_the_default_opener_uses_the_https_only_handler():
    assert any(isinstance(h, _HttpsOnlyRedirects) for h in osv_module._OPENER.handlers)

