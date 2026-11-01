# SBOM and VEX: `exhibit-a sbom` and `sbom.json`

`exhibit-a sbom` writes a CycloneDX 1.5 JSON software bill of materials for the
repository's pinned Python dependencies, with a `vulnerabilities` section whose
VEX (`vulnerability exploitability exchange`) `analysis` states come from
Exhibit A evidence only.

A green SBOM means "nothing could be proven", never "safe".

## Usage

```bash
exhibit-a sbom --repo DIR [--deps-json deps-out/deps.json] [--output sbom.json]
```

Without `--deps-json` the SBOM lists `components` only. With it, each advisory
in `deps.json` (see [dependency-proofs.md](dependency-proofs.md)) becomes one
entry in `vulnerabilities`. EPSS scores and CISA KEV membership are fetched live
when reachable (bounded timeouts; only CVE ids are sent); when the feeds are
unreachable the SBOM is still written without them. The KEV catalog is cached
per day (`kev-YYYY-MM-DD.json`) next to `--output`, or under `--repo` when
writing to stdout, so repeat runs the same day make no request.

## Components

One `component` per exact pin from `requirements.txt` / `pyproject.toml`
(`src/exhibit_a/advisory/deps.py`; versions as resolved):

```json
{"type": "library", "bom-ref": "pkg:pypi/starlette@0.26.1", "name": "starlette",
 "version": "0.26.1", "purl": "pkg:pypi/starlette@0.26.1",
 "properties": [{"name": "exhibit-a:dependency-source", "value": "requirements.txt:1"}]}
```

Ranges, URLs, editable installs and includes are not resolved and do not become
components. Transitive dependencies (no lock file is read) and vendored code are
invisible, same as for `exhibit-a deps`.

## Vulnerabilities

One entry per advisory in `deps.json`:

| field | meaning |
| --- | --- |
| `bom-ref` | the advisory id (`GHSA-…`), suffixed with `package@version` when the same advisory names two pins |
| `id` | the first CVE alias, else the advisory id |
| `description` | the advisory summary |
| `references` | the advisory id plus every alias (CVE → NVD, GHSA → github.com/advisories, else OSV) |
| `ratings` | CVSS from the OSV record as given (`method` CVSSv2/v3/v4, `vector`, `severity` from `database_specific.severity` when known), plus EPSS (`method` EPSS, `score`) when the feed provided one |
| `advisories` | OSV page, GitHub advisory pages for GHSA aliases, and the CISA KEV catalog link when the CVE is a member |
| `properties` | `exhibit-a:kev` (`true`/`false`), `exhibit-a:advisory-id`, and `exhibit-a:epss-percentile` when known |
| `affects` | the pinned component's `bom-ref` |
| `analysis` | the VEX state (below) |

### VEX states (evidence only)

| `deps.json` evidence | `analysis.state` | notes |
| --- | --- | --- |
| `proof.status == "proven"` | `exploitable` | `detail` carries the proof bundle path (`proof.package`) and entry point |
| `reachability.status == "not_reachable"` | `not_affected`, `justification: code_not_reachable` | `detail` quotes the graph's reason and adds the honest caveat (below) |
| anything else | `in_triage` | proof not run, not proven, errored, skipped, or the advisory names no affected symbol |

`not_affected` never comes from model text: only `proof.status` and
`reachability.status` (both machine-computed) decide. In particular a failed or
skipped proof, an `unknown` reachability, or a model-written verdict string
stays `in_triage`.

The `not_affected` detail always ends with this caveat:

> The static call graph found no path from any entry point to the affected
> symbol. The graph cannot see dynamic dispatch, monkeypatching, calls through
> another dependency, or non-Python entry points, so this is a coverage
> statement, not a proof of safety; any change to entry points, dependencies or
> pins can invalidate it.

## Enrichment feeds (`src/exhibit_a/advisory/enrich.py`)

* **EPSS** (`https://api.first.org/data/v1/epss?cve=CVE-…`): score (0–1) and
  percentile per CVE id. One request for all CVE ids, comma-joined; anything
  that is not a CVE id is dropped before the request, so GHSA/PYSEC ids and any
  other text are never sent.
* **CISA KEV** (the catalog JSON at `cisa.gov`): downloaded whole (it has no
  per-CVE query) and matched locally by `cveID`. Cached per day under the run
  directory.
* **GHSA aliases**: extracted locally from the OSV `aliases` list; no network.

Both feeds use stdlib `urllib` only, https only, an injected opener (tests use a
fake), a per-request timeout (default 10 s) and a response size cap (default
5 MB), mirroring `src/exhibit_a/advisory/osv.py`. They are triage signals only:
a high EPSS score or KEV membership never proves exploitability.

## Example (Starlette-shaped case)

With a `deps.json` whose proof is `proven`:

```json
{"bom-ref": "GHSA-v5gw-mw7f-84px", "id": "CVE-2023-29159",
 "analysis": {"state": "exploitable",
              "detail": "Exhibit A proved this advisory through entry point StaticFiles.__call__. Proof bundle: deps/ghsa-starlette/packages/s1."},
 "affects": [{"ref": "pkg:pypi/starlette@0.26.1"}]}
```

With the same repository but no proof run (`proof.status == "not_attempted"`):

```json
{"bom-ref": "GHSA-v5gw-mw7f-84px", "id": "CVE-2023-29159",
 "analysis": {"state": "in_triage",
              "detail": "Reachability was computed but the proof loop was not run (--prove was not given); triage pending."},
 "affects": [{"ref": "pkg:pypi/starlette@0.26.1"}]}
```

## Validation

`src/exhibit_a/report/sbom.py:validate_sbom` checks the structural CycloneDX
fields this module writes (`bomFormat`, `specVersion`, `version`,
`metadata.timestamp`, component `type`/`bom-ref`/`name`/`version`, vulnerability
`bom-ref`/`id`, a valid `analysis.state` with `justification` when
`not_affected`, non-empty `affects`, and a `method` on every rating).
`tests/test_sbom.py` exercises the proven / in-triage / not-affected mapping
with fixtures and never touches the network.
