"""Advisory enrichment: EPSS scores, CISA KEV membership, and GHSA aliases.

EPSS (https://api.first.org/data/v1/epss) and the CISA Known Exploited
Vulnerabilities catalog are public, keyless feeds. They are triage signals only:
a high EPSS score or KEV membership never proves exploitability here; only the
oracle-observed proof loop in SPEC.md section 4 does, and a green result means
"nothing could be proven", never "safe".

Privacy: only CVE ids are ever sent. EPSS is queried by ``?cve=CVE-...`` (one
request, comma-joined CVE ids, nothing else). The KEV catalog is downloaded whole
(it has no per-CVE query) and cached per day under the run directory, so a
second run the same day makes no request. GHSA ids are extracted locally from
OSV ``aliases``; they are never sent anywhere by this module.

Network use mirrors ``osv.py``: stdlib ``urllib`` only, https only, an injected
opener (tests use a fake; they never reach the network), a per-request timeout
and a response size cap.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Callable, Iterable

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_TIMEOUT = 10.0
MAX_RESPONSE_BYTES = 5_000_000

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA = re.compile(r"^GHSA-[a-z0-9-]{4,}$", re.IGNORECASE)

Opener = Callable[[urllib.request.Request, float], Any]


class EnrichDataError(ValueError):
    """An enrichment feed reply does not have the expected shape."""


@dataclass(frozen=True)
class EpssEntry:
    """EPSS score for one CVE id. ``epss``/``percentile`` are None when unknown."""

    cve: str
    epss: float | None = None
    percentile: float | None = None


@dataclass(frozen=True)
class Enrichment:
    """Everything the SBOM needs for one advisory."""

    advisory_id: str
    cves: tuple[str, ...] = ()
    ghsa: tuple[str, ...] = ()
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False


def _default_opener(request: urllib.request.Request, timeout: float):
    return urllib.request.urlopen(request, timeout=timeout)  # noqa: S310 (fixed https hosts)


def _check_https(url: str, what: str) -> None:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise EnrichDataError(f"{what} URL must be https: {url!r}")


def _read_limited(opener: Opener, url: str, timeout: float, max_bytes: int) -> Any:
    """GET ``url`` through the injected opener; parse the body as JSON (bounded)."""
    _check_https(url, "enrichment")
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "exhibit-a-advisory"},
    )
    with opener(request, timeout) as response:
        payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise EnrichDataError(f"enrichment reply from {url.split('?')[0]!r} exceeds size limit")
    try:
        return json.loads(payload)
    except RecursionError as exc:
        raise EnrichDataError("enrichment reply is nested too deeply") from exc
    except ValueError as exc:
        raise EnrichDataError("enrichment reply is not JSON") from exc


def normalize_cves(ids: Iterable[str]) -> list[str]:
    """Upper-cased, de-duplicated CVE ids; anything that is not a CVE id is dropped."""
    out: list[str] = []
    for raw in ids:
        if not isinstance(raw, str):
            continue
        text = raw.strip().upper()
        if _CVE.match(text) and text not in out:
            out.append(text)
    return out


def ghsa_aliases(aliases: Iterable[str]) -> list[str]:
    """GHSA ids from an OSV ``aliases`` list, de-duplicated, order kept."""
    out: list[str] = []
    for raw in aliases:
        if not isinstance(raw, str):
            continue
        text = raw.strip()
        if _GHSA.match(text) and text not in out:
            out.append(text)
    return out


def _float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")):
        return None
    return number


def parse_epss_reply(reply: Any) -> dict[str, EpssEntry]:
    """Parse an EPSS ``/epss`` reply into CVE id -> entry. Unknown fields are ignored."""
    if not isinstance(reply, dict) or not isinstance(reply.get("data"), list):
        raise EnrichDataError("EPSS reply must be an object with a 'data' list")
    out: dict[str, EpssEntry] = {}
    for row in reply["data"]:
        if not isinstance(row, dict) or not isinstance(row.get("cve"), str):
            continue
        cve = row["cve"].strip().upper()
        if not _CVE.match(cve):
            continue
        epss = _float(row.get("epss"))
        percentile = _float(row.get("percentile"))
        if epss is not None:
            epss = min(max(epss, 0.0), 1.0)
        if percentile is not None:
            percentile = min(max(percentile, 0.0), 1.0)
        out[cve] = EpssEntry(cve=cve, epss=epss, percentile=percentile)
    return out


def fetch_epss(
    cves: Iterable[str],
    *,
    opener: Opener | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, EpssEntry]:
    """EPSS scores for CVE ids. Only CVE ids are sent (as ``?cve=...``); anything else
    in ``cves`` is dropped before the request. Empty input makes no request."""
    wanted = normalize_cves(cves)
    if not wanted:
        return {}
    query = urllib.parse.urlencode({"cve": ",".join(wanted)})
    url = f"{EPSS_API}?{query}"
    reply = _read_limited(opener or _default_opener, url, timeout, max_response_bytes)
    return parse_epss_reply(reply)


def parse_kev_reply(reply: Any) -> dict[str, dict[str, Any]]:
    """Parse a KEV catalog reply into upper-cased CVE id -> the catalog entry."""
    if not isinstance(reply, dict) or not isinstance(reply.get("vulnerabilities"), list):
        raise EnrichDataError("KEV catalog must be an object with a 'vulnerabilities' list")
    out: dict[str, dict[str, Any]] = {}
    for row in reply["vulnerabilities"]:
        if not isinstance(row, dict) or not isinstance(row.get("cveID"), str):
            continue
        cve = row["cveID"].strip().upper()
        if _CVE.match(cve):
            out[cve] = row
    return out


def kev_cache_path(cache_dir: str | Path, day: date | str) -> Path:
    """Cache file for one day: ``<cache_dir>/kev-YYYY-MM-DD.json``."""
    text = day.isoformat() if isinstance(day, date) else str(day)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        raise ValueError(f"KEV cache day must be YYYY-MM-DD, got {text!r}")
    return Path(cache_dir) / f"kev-{text}.json"


def fetch_kev(
    *,
    cache_dir: str | Path | None = None,
    day: date | str | None = None,
    opener: Opener | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, dict[str, Any]]:
    """KEV catalog as CVE id -> entry. With ``cache_dir``, the catalog is read from
    (and written to) ``kev-YYYY-MM-DD.json`` for ``day`` (default: today), so repeat
    runs the same day make no request. Without ``cache_dir`` the catalog is fetched
    every call. A corrupt cache file is ignored and re-fetched."""
    target = day.isoformat() if isinstance(day, date) else day
    path: Path | None = None
    if cache_dir is not None:
        path = kev_cache_path(cache_dir, target or date.today().isoformat())
        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
            return parse_kev_reply(cached)
        except (OSError, UnicodeDecodeError, ValueError):
            pass  # missing or unreadable cache: fetch below and overwrite it
    reply = _read_limited(opener or _default_opener, KEV_URL, timeout, max_response_bytes)
    catalog = parse_kev_reply(reply)
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(reply)[: max_response_bytes + 1], encoding="utf-8")
        except OSError:
            pass  # a cache write failure never fails the lookup
    return catalog


def enrich_advisory(
    advisory_id: str,
    aliases: Iterable[str],
    epss: dict[str, EpssEntry] | None = None,
    kev: dict[str, dict[str, Any]] | set[str] | None = None,
) -> Enrichment:
    """Combine one advisory's aliases with fetched EPSS/KEV data.

    The advisory's CVE aliases pick the best EPSS score (highest ``epss``); KEV
    membership is by CVE id. GHSA aliases are extracted locally. Model text is
    never consulted: only the record's alias list and the feeds decide.
    """
    names = list(aliases)
    cves = tuple(normalize_cves(names))
    ghsa = tuple(ghsa_aliases(names))
    best: EpssEntry | None = None
    for cve in cves:
        entry = (epss or {}).get(cve)
        if entry is not None and entry.epss is not None:
            if best is None or entry.epss > (best.epss or 0.0):
                best = entry
    kev_ids = {k.strip().upper() for k in kev} if isinstance(kev, set) else set((kev or {}).keys())
    return Enrichment(
        advisory_id=advisory_id,
        cves=cves,
        ghsa=ghsa,
        epss=best.epss if best else None,
        epss_percentile=best.percentile if best else None,
        kev=any(cve in kev_ids for cve in cves),
    )


__all__ = [
    "DEFAULT_TIMEOUT",
    "EPSS_API",
    "KEV_URL",
    "MAX_RESPONSE_BYTES",
    "EnrichDataError",
    "Enrichment",
    "EpssEntry",
    "Opener",
    "enrich_advisory",
    "fetch_epss",
    "fetch_kev",
    "ghsa_aliases",
    "kev_cache_path",
    "normalize_cves",
    "parse_epss_reply",
    "parse_kev_reply",
]
