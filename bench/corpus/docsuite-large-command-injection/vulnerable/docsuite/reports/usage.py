"""Numbers about accounts, documents and storage."""

from ..storage.quota import quota_report, tree_bytes


def usage_report(accounts, documents, data_dir, export_jobs=()):
    """One mapping with the headline numbers of the service."""
    by_owner = {}
    for document in documents:
        by_owner[document.owner] = by_owner.get(document.owner, 0) + 1
    per_account = [
        {"id": account.id, "name": account.name, "role": account.role,
         "documents": by_owner.get(account.id, 0),
         "quota": quota_report(
             by_owner.get(account.id, 0) * 4096, account.quota * 1024 * 1024)}
        for account in accounts
    ]
    return {
        "accounts": len(accounts),
        "documents": len(documents),
        "bytes_on_disk": tree_bytes(data_dir),
        "exports": len(list(export_jobs)),
        "per_account": per_account,
    }


def document_stats(documents):
    """Counts and averages over a document collection."""
    total = len(documents)
    bodies = sum(doc.length() for doc in documents)
    tags = sum(len(doc.tags) for doc in documents)
    return {
        "documents": total,
        "body_chars": bodies,
        "average_chars": round(bodies / total, 1) if total else 0.0,
        "tag_uses": tags,
    }
