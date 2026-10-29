"""Implementation of the ``advisories`` CLI subcommand."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..advisory import HttpOsvBackend, RecordedOsvBackend, lookup, parse_pyproject, parse_requirements


def _dependencies(args: argparse.Namespace):
    dependencies = []
    unsupported = []
    roots = []
    if args.requirements:
        path = Path(args.requirements)
        roots.append(path.parent)
        result = parse_requirements(path.read_text(encoding="utf-8"), str(path))
        dependencies.extend(result.dependencies)
        unsupported.extend(result.unsupported)
    if args.pyproject:
        path = Path(args.pyproject)
        roots.append(path.parent)
        result = parse_pyproject(path.read_text(encoding="utf-8"), str(path))
        dependencies.extend(result.dependencies)
        unsupported.extend(result.unsupported)
    return dependencies, unsupported, roots


def _text_report(report) -> str:
    lines = ["Advisories (hint, not proof)", ""]
    if report.matches:
        headers = ["PACKAGE", "INSTALLED", "ADVISORY", "STATUS", "FIXED IN"]
        rows = [
            [m.package, m.installed_version, m.advisory_id, m.affected_status, m.fixed_in or "-"]
            for m in report.matches
        ]
        widths = [len(header) for header in headers]
        for row in rows:
            widths = [max(width, len(value)) for width, value in zip(widths, row)]
        lines.append("  ".join(value.ljust(width) for value, width in zip(headers, widths)))
        lines.append("  ".join("-" * width for width in widths))
        lines.extend("  ".join(value.ljust(width) for value, width in zip(row, widths)) for row in rows)
    else:
        lines.append("No advisory matches.")
    lines.extend(["", f"Packages checked: {report.packages_checked}",
                  f"Data source: {report.data_source}", "Advisories are a hint, not proof."])
    return "\n".join(lines)


def cmd_advisories(args: argparse.Namespace) -> int:
    """Look up pinned dependencies against recorded or live OSV data."""
    try:
        dependencies, unsupported, roots = _dependencies(args)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"advisories: cannot parse input: {exc}", file=sys.stderr)
        return 2
    if not dependencies and not unsupported:
        print("advisories: provide --requirements or --pyproject", file=sys.stderr)
        return 2
    try:
        backend = (
            RecordedOsvBackend.from_file(args.offline)
            if args.offline
            else HttpOsvBackend()
        )
        report = lookup(
            dependencies,
            backend,
            project_root=roots[0] if roots else None,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"advisories: lookup failed: {exc}", file=sys.stderr)
        return 1
    payload = report.to_dict()
    payload["unsupported"] = [
        {"text": item.text, "source": item.source, "reason": item.reason}
        for item in unsupported
    ]
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_text_report(report))
        for item in unsupported:
            print(f"unsupported: {item.source}: {item.reason}: {item.text}", file=sys.stderr)
    return 0
