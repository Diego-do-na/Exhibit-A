"""How the library grows over time."""

from collections import Counter


def per_day(documents):
    """Document counts keyed by the calendar day of their last update."""
    days = Counter()
    for document in documents:
        day = (document.updated or document.created or "")[:10]
        if day:
            days[day] += 1
    return [{"day": day, "documents": days[day]} for day in sorted(days)]


def tag_growth(documents):
    """First-seen day of every tag, oldest first."""
    seen = {}
    for document in sorted(documents, key=lambda doc: (doc.updated, doc.id)):
        day = (document.updated or document.created or "")[:10]
        for tag in document.tags:
            seen.setdefault(tag, day)
    return [{"tag": tag, "since": seen[tag]} for tag in sorted(seen)]


def trends(documents, limit=30):
    """Daily counts and tag growth for the usage report."""
    return {"per_day": per_day(documents)[:limit],
            "tag_growth": tag_growth(documents)}
