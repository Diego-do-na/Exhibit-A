"""Implementation of the ``sbom`` CLI subcommand (extension module).

``exhibit-a sbom --repo DIR [--deps-json FILE] [--output FILE]`` writes a
CycloneDX 1.5 JSON SBOM of the repository's pinned Python dependencies. With
``--deps-json`` (a ``deps.json`` report from ``exhibit-a deps``) the SBOM also
carries a ``vulnerabilities`` section whose VEX ``analysis`` states come from
Exhibit A evidence only (``proven`` -> ``exploitable``; the graph reporting no
path -> ``not_affected``; anything else -> ``in_triage``).

EPSS scores and CISA KEV membership enrich the ratings when the feeds are
reachable (bounded timeouts, only CVE ids sent); when they are not, the SBOM is
still written without them. The KEV catalog is cached per day next to the
output (or under the repository).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_deps(path: str):  # noqa: ANN202
    from exhibit_a.schemas.advisory import DepsReport

    try:
        return DepsReport.model_validate_json(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"cannot read deps report {path}: {exc}") from exc


def _live_enrichment(report, cache_dir: Path) -> dict:
    """EPSS + KEV enrichment for the report's CVE aliases; {} when unreachable."""
    from exhibit_a.advisory.enrich import (
        EnrichDataError,
        enrich_advisory,
        fetch_epss,
        fetch_kev,
    )

    try:
        cves = sorted({a.upper() for item in report.advisories for a in item.aliases
                       if a.upper().startswith("CVE-")})
        epss = fetch_epss(cves) if cves else {}
        kev = fetch_kev(cache_dir=cache_dir)
        return {item.advisory_id: enrich_advisory(item.advisory_id, item.aliases, epss, kev)
                for item in report.advisories}
    except (EnrichDataError, OSError, ValueError, TimeoutError) as exc:
        print(f"sbom: enrichment feeds unreachable ({exc}); writing SBOM without EPSS/KEV",
              file=sys.stderr)
        return {}


def cmd_sbom(args: argparse.Namespace) -> int:
    """Write the CycloneDX SBOM for ``--repo`` to ``--output`` or stdout."""
    from exhibit_a.report.sbom import generate_sbom

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"sbom: repository does not exist: {repo}", file=sys.stderr)
        return 2
    report = None
    if args.deps_json is not None:
        try:
            report = _load_deps(args.deps_json)
        except ValueError as exc:
            print(f"sbom: {exc}", file=sys.stderr)
            return 1
    if report is not None:
        out = Path(args.output) if args.output else None
        cache_dir = out.parent if out is not None else repo
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            cache_dir = repo
        enrichment = _live_enrichment(report, cache_dir)
    else:
        enrichment = {}
    try:
        sbom = generate_sbom(repo, report, enrichment or None)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"sbom: cannot build the SBOM: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(sbom, indent=2, sort_keys=True) + "\n"
    if args.output:
        try:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"sbom: could not write {args.output}: {exc}", file=sys.stderr)
            return 1
        print(f"sbom.json {out}")
    else:
        sys.stdout.write(text)
    return 0


def register(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Add the ``sbom`` subcommand to the CLI."""
    parser = sub.add_parser(
        "sbom",
        help="CycloneDX 1.5 SBOM with VEX states derived from Exhibit A evidence.",
    )
    parser.add_argument("--repo", required=True, help="Repository directory to analyse.")
    parser.add_argument("--deps-json", default=None, metavar="FILE",
                        help="deps.json from `exhibit-a deps` for the vulnerabilities section.")
    parser.add_argument("--output", default=None, metavar="FILE",
                        help="File to write the SBOM JSON to (default: stdout).")
    parser.set_defaults(func=cmd_sbom)
