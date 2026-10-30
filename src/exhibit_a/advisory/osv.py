"""OSV advisory records, range evaluation, and two lookup backends.

The backend only proposes candidate advisories for a (package, version). Whether the
installed version is affected is always re-evaluated locally from the record's ranges, so
a backend (live or recorded) can widen the candidate set but cannot by itself mark a
version affected without a range or version list that says so.

Backends:

* `RecordedOsvBackend` answers from in-memory OSV records (hand-authored fixtures in the
  tests). It never touches the network.
* `HttpOsvBackend` queries https://api.osv.dev with stdlib urllib, bounded timeouts and a
  response size cap. Only package names, the ecosystem and versions are sent. The tests
  exercise it through an injected fake opener; they never reach the real service.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol

from .deps import normalize_name
from .version import InvalidVersion, Version, semver_key

ECOSYSTEM = "PyPI"
OSV_API = "https://api.osv.dev/v1"
OSV_WEB = "https://osv.dev/vulnerability/"


class AdvisoryDataError(ValueError):
    """An OSV record or API response does not have the expected shape."""


@dataclass(frozen=True)
class RangeEvent:
    kind: str  # introduced | fixed | last_affected | limit
    version: str


@dataclass(frozen=True)
class AffectedRange:
    type: str  # SEMVER | ECOSYSTEM | GIT
    events: tuple[RangeEvent, ...]


@dataclass(frozen=True)
class AffectedPackage:
    name: str  # normalized
    ecosystem: str
    ranges: tuple[AffectedRange, ...]
    versions: tuple[str, ...]
    symbols: tuple[str, ...]  # dotted names from ecosystem_specific, best effort


@dataclass(frozen=True)
class Advisory:
    id: str
    aliases: tuple[str, ...]
    summary: str
    modified: str
    severity: tuple[dict[str, str], ...]
    references: tuple[str, ...]
    affected: tuple[AffectedPackage, ...]
    withdrawn: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise AdvisoryDataError(f"{what} must be a string")
    return value


def _list(value: Any, what: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AdvisoryDataError(f"{what} must be a list")
    return value


def _symbols(ecosystem_specific: Any) -> tuple[str, ...]:
    """Collect affected symbols. OSV has no PyPI-standard field for them, so two shapes
    seen in the wild are accepted: ``imports: [{path, symbols}]`` (the Go shape) and
    ``affected_functions: ["pkg.mod.func"]``."""
    if not isinstance(ecosystem_specific, dict):
        return ()
    found: list[str] = []
    for entry in ecosystem_specific.get("imports") or []:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            names = [s for s in entry.get("symbols") or [] if isinstance(s, str)]
            if names:
                found.extend(f"{entry['path']}.{s}" for s in names)
            else:
                found.append(entry["path"])
    for name in ecosystem_specific.get("affected_functions") or []:
        if isinstance(name, str):
            found.append(name)
    return tuple(found)


def parse_advisory(record: Any) -> Advisory:
    """Validate and convert one OSV JSON record. Unknown fields are kept in `raw`."""
    if not isinstance(record, dict):
        raise AdvisoryDataError("advisory must be an object")
    affected = []
    for item in _list(record.get("affected"), "affected"):
        if not isinstance(item, dict):
            raise AdvisoryDataError("affected entry must be an object")
        pkg = item.get("package") or {}
        if not isinstance(pkg, dict):
            raise AdvisoryDataError("affected.package must be an object")
        ranges = []
        for rng in _list(item.get("ranges"), "ranges"):
            if not isinstance(rng, dict):
                raise AdvisoryDataError("range must be an object")
            events = []
            for evt in _list(rng.get("events"), "events"):
                if not isinstance(evt, dict) or len(evt) != 1:
                    raise AdvisoryDataError("range event must have exactly one key")
                (kind, version), = evt.items()
                if kind not in {"introduced", "fixed", "last_affected", "limit"}:
                    raise AdvisoryDataError(f"unknown range event {kind!r}")
                events.append(RangeEvent(kind, _str(version, f"event {kind}")))
            ranges.append(AffectedRange(_str(rng.get("type"), "range.type"), tuple(events)))
        affected.append(AffectedPackage(
            name=normalize_name(_str(pkg.get("name", ""), "package.name")),
            ecosystem=_str(pkg.get("ecosystem", ""), "package.ecosystem"),
            ranges=tuple(ranges),
            versions=tuple(_str(v, "versions[]") for v in _list(item.get("versions"), "versions")),
            symbols=_symbols(item.get("ecosystem_specific")),
        ))
    severity = []
    for sev in _list(record.get("severity"), "severity"):
        if isinstance(sev, dict) and isinstance(sev.get("type"), str) \
                and isinstance(sev.get("score"), str):
            severity.append({"type": sev["type"], "score": sev["score"]})
    references = tuple(
        ref["url"] for ref in _list(record.get("references"), "references")
        if isinstance(ref, dict) and isinstance(ref.get("url"), str)
    )
    withdrawn = record.get("withdrawn")
    return Advisory(
        id=_str(record.get("id"), "id"),
        aliases=tuple(_str(a, "aliases[]") for a in _list(record.get("aliases"), "aliases")),
        summary=record.get("summary") if isinstance(record.get("summary"), str) else "",
        modified=record.get("modified") if isinstance(record.get("modified"), str) else "",
        severity=tuple(severity),
        references=references,
        affected=tuple(affected),
        withdrawn=withdrawn if isinstance(withdrawn, str) else None,
        raw=record,
    )


# ---------------------------------------------------------------- range evaluation


@dataclass(frozen=True)
class RangeResult:
    affected: bool | None  # None: no range or version list could be evaluated
    fixed_versions: tuple[str, ...]  # fixed events after the version, in evaluable ranges
    notes: tuple[str, ...]


def _key_fn(range_type: str) -> Callable[[str], Any] | None:
    if range_type == "ECOSYSTEM":
        return lambda v: Version.parse(v)
    if range_type == "SEMVER":
        return semver_key
    return None  # GIT ranges need commit graphs; not evaluated here.


def _evaluate_range(rng: AffectedRange, installed: str) -> tuple[bool | None, list[str], str | None]:
    key = _key_fn(rng.type)
    if key is None:
        return None, [], f"{rng.type} range not evaluated"
    try:
        current = key(installed)
        events = []
        for evt in rng.events:
            if evt.kind == "introduced" and evt.version == "0":
                events.append((None, evt))  # sorts before everything
            else:
                events.append((key(evt.version), evt))
    except InvalidVersion as exc:
        return None, [], f"{rng.type} range not evaluated: {exc}"
    order = {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 1}
    # "introduced: 0" sorts first; at equal versions an introduced event comes first.
    events.sort(key=lambda pair: (0, order[pair[1].kind]) if pair[0] is None
                else (1, pair[0], order[pair[1].kind]))
    vulnerable = False
    for k, evt in events:
        if evt.kind == "introduced":
            if k is None or current >= k:
                vulnerable = True
        elif evt.kind == "fixed":
            if current >= k:
                vulnerable = False
        elif evt.kind == "last_affected":
            if current > k:
                vulnerable = False
        elif evt.kind == "limit":
            if current >= k:
                vulnerable = False
    fixed = [evt.version for k, evt in events if evt.kind == "fixed" and k > current]
    return vulnerable, fixed if vulnerable else [], None


def evaluate(pkg: AffectedPackage, installed: str) -> RangeResult:
    """Is `installed` affected according to this package entry, and which fixes exist?"""
    notes: list[str] = []
    verdicts: list[bool] = []
    fixed: list[str] = []
    if pkg.versions:
        listed = installed in pkg.versions
        if not listed:
            try:
                iv = Version.parse(installed)
                listed = any(_safe_eq(iv, v) for v in pkg.versions)
            except InvalidVersion:
                pass
        verdicts.append(listed)
    for rng in pkg.ranges:
        result, fixes, note = _evaluate_range(rng, installed)
        if note:
            notes.append(note)
        if result is not None:
            verdicts.append(result)
            fixed.extend(fixes)
    if not verdicts:
        return RangeResult(None, (), tuple(notes))
    return RangeResult(any(verdicts), tuple(dict.fromkeys(fixed)), tuple(notes))


def _safe_eq(installed: Version, text: str) -> bool:
    try:
        return Version.parse(text) == installed
    except InvalidVersion:
        return False


# ---------------------------------------------------------------- backends


class OsvBackend(Protocol):
    """Source of candidate advisories. `source` is 'live' or 'recorded'."""

    source: str

    def query(self, packages: Iterable[tuple[str, str]]) -> dict[tuple[str, str], list[Advisory]]:
        """Map each (normalized name, version) to candidate advisories."""

    def evidence_url(self, advisory_id: str) -> str:
        """A URL (or fixture reference) where a human can read the record."""


class RecordedOsvBackend:
    """Answers from a fixed list of OSV records; candidates are every record that names
    the package in the PyPI ecosystem (the version filter is applied by `evaluate`)."""

    source = "recorded"

    def __init__(self, records: Iterable[Any], label: str = "recorded") -> None:
        self._advisories = []
        self.warnings: list[str] = []
        for index, record in enumerate(records):
            # One bad record is skipped and reported; it does not hide the others.
            try:
                self._advisories.append(parse_advisory(record))
            except (AdvisoryDataError, RecursionError) as exc:
                self.warnings.append(f"recorded record #{index} skipped: {exc}")
        self.label = label

    @classmethod
    def from_file(cls, path) -> "RecordedOsvBackend":
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except RecursionError as exc:
            raise AdvisoryDataError("recorded fixture is nested too deeply") from exc
        if not isinstance(data, dict) or not isinstance(data.get("vulns"), list):
            raise AdvisoryDataError("recorded fixture must be an object with a 'vulns' list")
        return cls(data["vulns"], label=str(path))

    def query(self, packages):
        out: dict[tuple[str, str], list[Advisory]] = {}
        for name, version in packages:
            name = normalize_name(name)
            out[(name, version)] = [
                adv for adv in self._advisories
                if any(p.name == name and p.ecosystem == ECOSYSTEM for p in adv.affected)
            ]
        return out

    def evidence_url(self, advisory_id: str) -> str:
        return f"fixture://{self.label}#{advisory_id}"


Opener = Callable[[urllib.request.Request, float], Any]


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https URLs, so a redirect cannot downgrade the transport."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise AdvisoryDataError(f"refusing non-https redirect to {newurl.split('?')[0]!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects)


def _default_opener(request: urllib.request.Request, timeout: float):
    return _OPENER.open(request, timeout=timeout)  # noqa: S310 (fixed https host)


class HttpOsvBackend:
    """Live lookups against api.osv.dev: one querybatch call for candidate ids, then one
    GET per id for the full record. Paginated batch results fall back to /v1/query.

    Not used by the test suite against the real service; see docs/security/advisory.md for the
    network allowlist this needs in CI.
    """

    source = "live"

    def __init__(self, *, base_url: str = OSV_API, timeout: float = 10.0,
                 max_response_bytes: int = 5_000_000, max_pages: int = 10,
                 max_ids_per_package: int = 200, opener: Opener | None = None) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("OSV base_url must be https")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.max_pages = max_pages
        self.max_ids_per_package = max_ids_per_package
        self.warnings: list[str] = []
        self._open = opener or _default_opener

    def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": "exhibit-a-advisory"},
        )
        with self._open(request, self.timeout) as response:
            payload = response.read(self.max_response_bytes + 1)
        if len(payload) > self.max_response_bytes:
            raise AdvisoryDataError(f"OSV response from {path} exceeds size limit")
        try:
            return json.loads(payload)
        except RecursionError as exc:
            raise AdvisoryDataError(f"OSV response from {path} is nested too deeply") from exc
        except ValueError as exc:
            raise AdvisoryDataError(f"OSV response from {path} is not JSON") from exc

    def _query_one(self, name: str, version: str) -> list[str]:
        ids: list[str] = []
        token = None
        for _ in range(self.max_pages):
            body: dict[str, Any] = {"package": {"name": name, "ecosystem": ECOSYSTEM},
                                    "version": version}
            if token:
                body["page_token"] = token
            reply = self._request("POST", "/query", body)
            if not isinstance(reply, dict):
                raise AdvisoryDataError("OSV /query reply must be an object")
            ids.extend(v["id"] for v in _list(reply.get("vulns"), "vulns")
                       if isinstance(v, dict) and isinstance(v.get("id"), str))
            token = reply.get("next_page_token")
            if not token:
                return ids
        raise AdvisoryDataError(f"OSV pagination for {name} exceeded {self.max_pages} pages")

    def query(self, packages):
        keys = [(normalize_name(n), v) for n, v in packages]
        if not keys:
            return {}
        reply = self._request("POST", "/querybatch", {"queries": [
            {"package": {"name": n, "ecosystem": ECOSYSTEM}, "version": v} for n, v in keys
        ]})
        results = reply.get("results") if isinstance(reply, dict) else None
        if not isinstance(results, list) or len(results) != len(keys):
            raise AdvisoryDataError("OSV /querybatch reply does not match the queries")
        cache: dict[str, Advisory | None] = {}
        out: dict[tuple[str, str], list[Advisory]] = {}
        for key, result in zip(keys, results):
            if not isinstance(result, dict):
                raise AdvisoryDataError("OSV /querybatch result must be an object")
            ids = [v["id"] for v in _list(result.get("vulns"), "vulns")
                   if isinstance(v, dict) and isinstance(v.get("id"), str)]
            if result.get("next_page_token"):
                ids = self._query_one(*key)
            ids = list(dict.fromkeys(ids))
            if len(ids) > self.max_ids_per_package:
                self.warnings.append(f"{key[0]}: {len(ids)} advisory ids returned, only the first "
                                     f"{self.max_ids_per_package} were fetched")
                ids = ids[:self.max_ids_per_package]
            advisories = []
            for vid in ids:
                if vid not in cache:
                    # One unreadable record is skipped and reported; the rest are still used.
                    try:
                        cache[vid] = parse_advisory(
                            self._request("GET", "/vulns/" + urllib.parse.quote(vid, safe="")))
                    except (AdvisoryDataError, RecursionError) as exc:
                        self.warnings.append(f"{vid} skipped: {exc}")
                        cache[vid] = None
                if cache[vid] is not None:
                    advisories.append(cache[vid])
            out[key] = advisories
        return out

    def evidence_url(self, advisory_id: str) -> str:
        return OSV_WEB + urllib.parse.quote(advisory_id, safe="")
