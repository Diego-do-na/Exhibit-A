"""Full-text search over titles and bodies."""

from ..util.text import snippet


def score_document(document, words):
    """How many of ``words`` appear in the title (counted twice) or the body."""
    title = document.title.lower()
    body = document.body.lower()
    score = 0
    for word in words:
        if word in title:
            score += 2
        if word in body:
            score += 1
    return score


def search_documents(documents, query, limit=20):
    """Documents matching ``query``, best first, with a text excerpt each."""
    words = [word.lower() for word in query.split() if word.strip()]
    if not words:
        return []
    ranked = []
    for document in documents:
        score = score_document(document, words)
        if score:
            ranked.append((score, document))
    ranked.sort(key=lambda item: (-item[0], item[1].id))
    return [
        dict(document.summary(), score=score, excerpt=snippet(document.body, words[0]))
        for score, document in ranked[:limit]
    ]


def search_by_tag(documents, tag, limit=20):
    """Documents carrying ``tag``, ordered by id."""
    wanted = tag.strip().lower()
    return [doc.summary() for doc in documents
            if wanted in [t.lower() for t in doc.tags]][:limit]


def recent(documents, limit=10):
    """The most recently updated documents, newest first."""
    ordered = sorted(documents, key=lambda doc: (doc.updated, doc.id), reverse=True)
    return [doc.summary() for doc in ordered[:limit]]
