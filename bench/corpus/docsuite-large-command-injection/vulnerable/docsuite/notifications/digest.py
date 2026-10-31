"""Periodic summaries queued for accounts."""

from ..util.text import truncate
from .templates import render


def digest_lines(documents, jobs, limit=5):
    """Short lines about the newest documents and finished exports."""
    lines = []
    for document in documents[:limit]:
        lines.append(f"- {document.title} ({document.id})")
    for job in jobs[:limit]:
        lines.append(f"- export {job['id']} of {job['document']}: {job['state']}")
    return lines


def build_digest(account, documents, jobs):
    """The weekly-digest body for ``account``."""
    lines = digest_lines(documents, jobs)
    body = render("cleanup_done", {"name": account.name, "scope": "library",
                                   "removed": 0})
    if lines:
        body += "\n" + "\n".join(lines)
    return truncate(body, 2000)


def queue_digest(outbox, account, documents, jobs):
    """Queue the digest message for ``account`` and return its id."""
    return outbox.queue(account.id, "Weekly digest",
                         build_digest(account, documents, jobs))
