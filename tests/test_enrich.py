"""T110: EPSS scores, CISA KEV membership, and GHSA aliases.

All feeds are exercised through an injected fake opener; no test reaches the
network. Fixtures are hand-authored and synthetic (CVE ids under the reserved
documentation range where possible, else the well-known Starlette CVE used only
as an identifier string, never fetched).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from exhibit_a.advisory.enrich import (
    EnrichDataError,
    enrich_advisory,
    fetch_epss,
    fetch_kev,
    ghsa_aliases,
    kev_cache_path,
    normalize_cves,
    parse_epss_reply,
    parse_kev_reply,
)

EPSS_REPLY = {
    "status": "OK",
    "version": "v1",
    "total": 2,
    "data": [
        {"cve": "CVE-2023-29159", "epss": "0.01234", "percentile": "0.56789",
         "date": "2026-10-01"},
        {"cve": "CVE-0000-0001", "epss": "0.90000", "percentile": "0.99000",
         "date": "2026-10-01"},
    ],
}

KEV_REPLY = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.10.01",
    "dateReleased": "2026-10-01T00:00:00.000Z",
    "count": 1,
    "vulnerabilities": [
        {"cveID": "CVE-2023-29159", "vendorProject": "Encode",
         "product": "Starlette", "vulnerabilityName": "hand-authored test row",
         "dateAdded": "2023-06-01", "shortDescription": "test fixture",
         "requiredAction": "Apply updates", "dueDate": "2023-06-22",
         "knownRansomwareCampaignUse": "Unknown", "notes": ""},
    ],
}


class _Reply(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeOpener:
    """Stands in for urllib; records every request so the payload can be audited."""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[tuple[str, str, float]] = []

    def __call__(self, request, timeout):
        url = request.full_url
        self.calls.append((request.get_method(), url, timeout))
        for prefix, payload in self.routes.items():
            if url.startswith(prefix):
                body = payload(url) if callable(payload) else payload
                return _Reply(body if isinstance(body, bytes) else json.dumps(body).encode())
        raise AssertionError(f"unexpected request: {url}")


def test_normalize_cves_keeps_only_cve_ids():
    assert normalize_cves(["cve-2023-29159", "GHSA-v5gw-mw7f-84px", "PYSEC-1",
                           "not a cve", "CVE-2023-29159", 123]) == ["CVE-2023-29159"]


def test_ghsa_aliases_keeps_only_ghsa_ids():
    assert ghsa_aliases(["GHSA-v5gw-mw7f-84px", "CVE-2023-29159", "PYSEC-1"]) == [
        "GHSA-v5gw-mw7f-84px"]


def test_fetch_epss_parses_scores_and_sends_only_cve_ids():
    opener = FakeOpener({"https://api.first.org/data/v1/epss": EPSS_REPLY})
    out = fetch_epss(["CVE-2023-29159", "GHSA-v5gw-mw7f-84px", "cve-0000-0001",
                      "garbage; rm -rf"], opener=opener, timeout=3.0)
    assert out["CVE-2023-29159"].epss == pytest.approx(0.01234)
    assert out["CVE-0000-0001"].percentile == pytest.approx(0.99)
    assert len(opener.calls) == 1
    method, url, timeout = opener.calls[0]
    assert method == "GET" and timeout == 3.0
    query = url.split("?", 1)[1]
    assert "GHSA" not in query and "garbage" not in query and "rm" not in query
    assert "CVE-2023-29159" in query and "CVE-0000-0001" in query


def test_fetch_epss_empty_input_makes_no_request():
    opener = FakeOpener({})
    assert fetch_epss([], opener=opener) == {}
    assert fetch_epss(["GHSA-v5gw-mw7f-84px"], opener=opener) == {}
    assert opener.calls == []


def test_fetch_epss_rejects_bad_replies():
    with pytest.raises(EnrichDataError):
        fetch_epss(["CVE-2023-29159"],
                   opener=FakeOpener({"https://api.first.org": b"<html>"}))
    with pytest.raises(EnrichDataError):
        fetch_epss(["CVE-2023-29159"],
                   opener=FakeOpener({"https://api.first.org": {"no": "data"}}))
    big = {"https://api.first.org": b"x" * 101}
    with pytest.raises(EnrichDataError, match="size limit"):
        fetch_epss(["CVE-2023-29159"], opener=FakeOpener(big), max_response_bytes=100)


def test_parse_epss_reply_ignores_bad_rows_and_clamps():
    reply = {"data": [{"cve": "CVE-2023-29159", "epss": "7.5", "percentile": "-1"},
                      {"cve": "not-a-cve", "epss": "0.5"},
                      "junk"]}
    out = parse_epss_reply(reply)
    assert out["CVE-2023-29159"].epss == 1.0
    assert out["CVE-2023-29159"].percentile == 0.0


def test_fetch_kev_caches_per_day_under_the_run_directory(tmp_path):
    opener = FakeOpener({"https://www.cisa.gov/": KEV_REPLY})
    first = fetch_kev(cache_dir=tmp_path, day="2026-10-01", opener=opener)
    assert "CVE-2023-29159" in first and "CVE-0000-0001" not in first
    assert (tmp_path / "kev-2026-10-01.json").is_file()
    calls = len(opener.calls)
    second = fetch_kev(cache_dir=tmp_path, day="2026-10-01", opener=opener)
    assert second == first and len(opener.calls) == calls  # cache hit: no new request
    third = fetch_kev(cache_dir=tmp_path, day="2026-10-02", opener=opener)
    assert third == first and len(opener.calls) == calls + 1  # new day: re-fetch
    assert kev_cache_path(tmp_path, "2026-10-02") == tmp_path / "kev-2026-10-02.json"


def test_fetch_kev_ignores_a_corrupt_cache(tmp_path):
    (tmp_path / "kev-2026-10-01.json").write_text("{not json", encoding="utf-8")
    opener = FakeOpener({"https://www.cisa.gov/": KEV_REPLY})
    assert "CVE-2023-29159" in fetch_kev(cache_dir=tmp_path, day="2026-10-01", opener=opener)
    assert len(opener.calls) == 1


def test_parse_kev_reply_rejects_bad_shapes():
    with pytest.raises(EnrichDataError):
        parse_kev_reply({"no": "vulnerabilities"})
    assert parse_kev_reply({"vulnerabilities": [{"cveID": 1}, "junk"]}) == {}


def test_enrich_advisory_combines_epss_kev_and_ghsa():
    from exhibit_a.advisory.enrich import EpssEntry

    epss = {"CVE-2023-29159": EpssEntry("CVE-2023-29159", 0.01, 0.5),
            "CVE-0000-0001": EpssEntry("CVE-0000-0001", 0.9, 0.99)}
    kev = {"CVE-2023-29159": {"cveID": "CVE-2023-29159"}}
    out = enrich_advisory("GHSA-v5gw-mw7f-84px",
                          ["CVE-2023-29159", "CVE-0000-0001", "GHSA-v5gw-mw7f-84px"],
                          epss, kev)
    assert out.cves == ("CVE-2023-29159", "CVE-0000-0001")
    assert out.ghsa == ("GHSA-v5gw-mw7f-84px",)
    assert out.epss == pytest.approx(0.9) and out.kev is True  # best EPSS wins
    plain = enrich_advisory("X", ["CVE-0000-0001"], epss, {})
    assert plain.epss == pytest.approx(0.9) and plain.kev is False and plain.ghsa == ()


def test_enrich_advisory_needs_no_feeds_for_ghsa():
    out = enrich_advisory("GHSA-v5gw-mw7f-84px", ["GHSA-v5gw-mw7f-84px"])
    assert out.ghsa == ("GHSA-v5gw-mw7f-84px",)
    assert out.epss is None and out.kev is False


def test_kev_cache_path_rejects_bad_days(tmp_path):
    with pytest.raises(ValueError):
        kev_cache_path(tmp_path, "yesterday")
    assert Path(str(kev_cache_path(tmp_path, "2026-01-02"))).name == "kev-2026-01-02.json"
