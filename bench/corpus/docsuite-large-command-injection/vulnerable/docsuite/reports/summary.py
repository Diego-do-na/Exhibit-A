"""One-paragraph renders of the usage report."""

from ..util.text import truncate


def summarize_usage(report, width=500):
    """The headline numbers of ``report`` as a single paragraph."""
    parts = [
        f"{report.get('accounts', 0)} accounts",
        f"{report.get('documents', 0)} documents",
        f"{report.get('bytes_on_disk', 0)} bytes on disk",
        f"{report.get('exports', 0)} exports",
    ]
    scopes = report.get("scopes", [])
    if scopes:
        biggest = max(scopes, key=lambda scope: scope.get("bytes", 0))
        parts.append(
            f"largest scope {biggest.get('directory', '')} "
            f"at {biggest.get('bytes', 0)} bytes"
        )
    health = report.get("health", {})
    if health:
        parts.append(f"storage health {health.get('overall', 'unknown')}")
    return truncate("The service holds " + ", ".join(parts) + ".", width)


def summarize_account(entry):
    """One line about a per-account entry of the usage report."""
    quota = entry.get("quota", {})
    return (
        f"{entry.get('name', '?')} ({entry.get('role', '?')}): "
        f"{entry.get('documents', 0)} documents, "
        f"{quota.get('percent', 0.0)}% of quota"
    )


def summarize_all(report):
    """The paragraph plus one line per account."""
    lines = [summarize_usage(report)]
    lines += [summarize_account(entry) for entry in report.get("per_account", [])]
    return lines
