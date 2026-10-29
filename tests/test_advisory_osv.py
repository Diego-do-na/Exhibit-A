import io
import json
from pathlib import Path

import pytest

from exhibit_a.advisory.osv import (
    AdvisoryDataError,
    HttpOsvBackend,
    RecordedOsvBackend,
    evaluate,
    parse_advisory,
)

FIXTURE = Path(__file__).parent / "fixtures" / "advisory" / "osv_synthetic.json"


@pytest.fixture(scope="module")
def backend():
    return RecordedOsvBackend.from_file(FIXTURE)


def _record(vid):
    data = json.loads(FIXTURE.read_text())
    return next(v for v in data["vulns"] if v["id"] == vid)


def test_fixture_is_labelled_synthetic():
    data = json.loads(FIXTURE.read_text())
    assert "HAND-AUTHORED SYNTHETIC" in data["_comment"]
    for vuln in data["vulns"]:
        assert vuln["id"].startswith("SYNTH-")
        assert all(a.startswith("CVE-0000-") for a in vuln.get("aliases", []))
        for aff in vuln["affected"]:
            assert aff["package"]["name"].lower().startswith("fictional")


def test_parse_advisory_fields():
    adv = parse_advisory(_record("SYNTH-2026-0001"))
    assert adv.aliases == ("CVE-0000-0001",)
    assert adv.severity[0]["type"] == "CVSS_V3"
    pkg = adv.affected[0]
    assert pkg.name == "fictional-webkit"  # normalized from Fictional_WebKit
    assert [r.type for r in pkg.ranges] == ["ECOSYSTEM", "ECOSYSTEM"]
    assert pkg.symbols == ("fictional_webkit.static.serve_file",)
    assert adv.references[0].startswith("https://advisories.example.invalid/")
    assert parse_advisory(_record("SYNTH-2026-0004")).affected[0].symbols == (
        "yamlish.loader.unsafe_load",)


@pytest.mark.parametrize(
    "record",
    [
        [],
        {"affected": []},  # no id
        {"id": "X", "affected": [{"package": {"name": "p", "ecosystem": "PyPI"},
                                  "ranges": [{"type": "ECOSYSTEM", "events": [{"bogus": "1"}]}]}]},
        {"id": "X", "affected": [{"package": {"name": "p", "ecosystem": "PyPI"},
                                  "ranges": [{"type": "ECOSYSTEM",
                                              "events": [{"introduced": "0", "fixed": "1"}]}]}]},
        {"id": "X", "affected": "nope"},
        {"id": "X", "aliases": [1]},
    ],
)
def test_parse_advisory_rejects_malformed(record):
    with pytest.raises(AdvisoryDataError):
        parse_advisory(record)


@pytest.mark.parametrize(
    "version,affected,fixes",
    [
        ("0.1", True, ("2.4.1",)),
        ("2.3.0", True, ("2.4.1",)),
        ("2.4.1rc1", True, ("2.4.1",)),  # a pre-release of the fix is still affected
        ("2.4.1", False, ()),
        ("2.9.0", False, ()),
        ("3.0.0", True, ("3.0.2",)),
        ("3.0.1.post1", True, ("3.0.2",)),
        ("3.0.2", False, ()),
        ("1!0.1", False, ()),  # a higher epoch is past every fix
    ],
)
def test_ecosystem_ranges(version, affected, fixes):
    pkg = parse_advisory(_record("SYNTH-2026-0001")).affected[0]
    result = evaluate(pkg, version)
    assert result.affected is affected
    assert result.fixed_versions == fixes


def test_last_affected_has_no_fix():
    pkg = parse_advisory(_record("SYNTH-2026-0002")).affected[0]
    assert evaluate(pkg, "2.9.9").affected is True
    assert evaluate(pkg, "2.9.9").fixed_versions == ()
    assert evaluate(pkg, "2.9.10").affected is False
    assert evaluate(pkg, "1.9").affected is False


def test_semver_range():
    pkg = parse_advisory(_record("SYNTH-2026-0004")).affected[0]
    assert evaluate(pkg, "1.4.2").affected is True
    assert evaluate(pkg, "2.0.0").affected is False
    assert evaluate(pkg, "2.0.0-rc.1").affected is True
    unparsable = evaluate(pkg, "1.4")  # not SemVer: reported, not guessed
    assert unparsable.affected is None
    assert "SEMVER range not evaluated" in unparsable.notes[0]


def test_git_range_not_evaluated():
    pkg = parse_advisory(_record("SYNTH-2026-0005")).affected[0]
    result = evaluate(pkg, "1.0.0")
    assert result.affected is None
    assert result.notes == ("GIT range not evaluated",)


def test_explicit_versions_list():
    pkg = parse_advisory(_record("SYNTH-2026-0006")).affected[0]
    assert evaluate(pkg, "0.1.0").affected is True
    assert evaluate(pkg, "0.1.1.0").affected is True  # PEP 440 equal to 0.1.1
    assert evaluate(pkg, "0.2.0").affected is False


def test_prerelease_window():
    pkg = parse_advisory(_record("SYNTH-2026-0007")).affected[0]
    assert evaluate(pkg, "1.0.0b9").affected is False
    assert evaluate(pkg, "1.0.0rc1").affected is True
    assert evaluate(pkg, "1.0.0").affected is True
    assert evaluate(pkg, "1.0.0.post1.dev0").affected is True
    assert evaluate(pkg, "1.0.0.post1").affected is False


def test_recorded_backend_candidates(backend):
    out = backend.query([("Fictional_WebKit", "2.3.0"), ("fictional-unknown", "1.0")])
    ids = sorted(a.id for a in out[("fictional-webkit", "2.3.0")])
    assert ids == ["SYNTH-2026-0001", "SYNTH-2026-0002", "SYNTH-2026-0003"]
    assert out[("fictional-unknown", "1.0")] == []
    assert backend.evidence_url("SYNTH-2026-0001").startswith("fixture://")


def test_recorded_backend_rejects_bad_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"no": "vulns"}))
    with pytest.raises(AdvisoryDataError):
        RecordedOsvBackend.from_file(bad)


# ---------------------------------------------------------------- HTTP backend, fake opener


class _Reply(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeOpener:
    """Stands in for urllib; records every request so the payload can be audited."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, request, timeout):
        body = json.loads(request.data) if request.data else None
        self.calls.append((request.get_method(), request.full_url, body, timeout))
        key = (request.get_method(), request.full_url.split("/v1", 1)[1])
        handler = self.routes[key]
        payload = handler(body) if callable(handler) else handler
        return _Reply(payload if isinstance(payload, bytes) else json.dumps(payload).encode())


def test_http_backend_batch_then_fetch():
    routes = {
        ("POST", "/querybatch"): {"results": [
            {"vulns": [{"id": "SYNTH-2026-0001", "modified": "x"}]},
            {},
        ]},
        ("GET", "/vulns/SYNTH-2026-0001"): _record("SYNTH-2026-0001"),
    }
    opener = FakeOpener(routes)
    backend = HttpOsvBackend(opener=opener, timeout=3.0)
    out = backend.query([("Fictional_WebKit", "2.3.0"), ("fictional-tiny", "0.2.0")])
    assert [a.id for a in out[("fictional-webkit", "2.3.0")]] == ["SYNTH-2026-0001"]
    assert out[("fictional-tiny", "0.2.0")] == []
    method, url, body, timeout = opener.calls[0]
    assert (method, url, timeout) == ("POST", "https://api.osv.dev/v1/querybatch", 3.0)
    # Privacy: only package name, ecosystem and version are sent.
    assert body == {"queries": [
        {"package": {"name": "fictional-webkit", "ecosystem": "PyPI"}, "version": "2.3.0"},
        {"package": {"name": "fictional-tiny", "ecosystem": "PyPI"}, "version": "0.2.0"},
    ]}
    assert opener.calls[1][:2] == ("GET", "https://api.osv.dev/v1/vulns/SYNTH-2026-0001")
    assert backend.evidence_url("SYNTH-2026-0001") == "https://osv.dev/vulnerability/SYNTH-2026-0001"


def test_http_backend_paginates_via_query():
    pages = iter([
        {"vulns": [{"id": "SYNTH-2026-0001"}], "next_page_token": "t1"},
        {"vulns": [{"id": "SYNTH-2026-0002"}]},
    ])
    routes = {
        ("POST", "/querybatch"): {"results": [{"vulns": [{"id": "SYNTH-2026-0001"}],
                                               "next_page_token": "t0"}]},
        ("POST", "/query"): lambda body: next(pages),
        ("GET", "/vulns/SYNTH-2026-0001"): _record("SYNTH-2026-0001"),
        ("GET", "/vulns/SYNTH-2026-0002"): _record("SYNTH-2026-0002"),
    }
    opener = FakeOpener(routes)
    out = HttpOsvBackend(opener=opener).query([("fictional-webkit", "2.3.0")])
    assert [a.id for a in out[("fictional-webkit", "2.3.0")]] == [
        "SYNTH-2026-0001", "SYNTH-2026-0002"]
    query_bodies = [c[2] for c in opener.calls if c[1].endswith("/query")]
    assert "page_token" not in query_bodies[0]
    assert query_bodies[1]["page_token"] == "t1"


def test_http_backend_rejects_bad_replies():
    with pytest.raises(AdvisoryDataError):
        HttpOsvBackend(opener=FakeOpener({("POST", "/querybatch"): b"<html>"})).query(
            [("p", "1.0")])
    with pytest.raises(AdvisoryDataError):
        HttpOsvBackend(opener=FakeOpener({("POST", "/querybatch"): {"results": []}})).query(
            [("p", "1.0")])
    big = {("POST", "/querybatch"): b"x" * 101}
    with pytest.raises(AdvisoryDataError, match="size limit"):
        HttpOsvBackend(opener=FakeOpener(big), max_response_bytes=100).query([("p", "1.0")])


def test_http_backend_pagination_is_bounded():
    routes = {
        ("POST", "/querybatch"): {"results": [{"next_page_token": "t"}]},
        ("POST", "/query"): {"vulns": [], "next_page_token": "again"},
    }
    with pytest.raises(AdvisoryDataError, match="pagination"):
        HttpOsvBackend(opener=FakeOpener(routes), max_pages=3).query([("p", "1.0")])


def test_http_backend_requires_https():
    with pytest.raises(ValueError):
        HttpOsvBackend(base_url="http://api.osv.dev/v1")


def test_http_backend_empty_query_makes_no_request():
    opener = FakeOpener({})
    assert HttpOsvBackend(opener=opener).query([]) == {}
    assert opener.calls == []
