"""Documents related to the one being read."""

from .tags import normalize_tag


def shared_tags(left, right):
    """The normalized tags two documents have in common, sorted."""
    mine = {normalize_tag(tag) for tag in left.tags}
    theirs = {normalize_tag(tag) for tag in right.tags}
    return sorted(mine & theirs)


def related(documents, document, limit=5):
    """Documents sharing tags with ``document``, most shared tags first.

    Each entry carries the shared tags, so readers see why it was suggested.
    """
    scored = []
    for other in documents:
        if other.id == document.id:
            continue
        common = shared_tags(document, other)
        if common:
            scored.append((len(common), other, common))
    scored.sort(key=lambda item: (-item[0], item[1].id))
    return [
        dict(other.summary(), shared_tags=common)
        for _, other, common in scored[:limit]
    ]


def neighbours(documents, document):
    """The ids before and after ``document`` in id order."""
    ordered = sorted(doc.id for doc in documents)
    position = ordered.index(document.id)
    before = ordered[position - 1] if position > 0 else None
    after = ordered[position + 1] if position + 1 < len(ordered) else None
    return {"previous": before, "next": after}
