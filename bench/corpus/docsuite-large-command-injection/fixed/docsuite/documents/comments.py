"""Margin notes on documents."""

from dataclasses import asdict, dataclass

from ..util import dates, ids


@dataclass
class Comment:
    """One note left on a document."""

    id: str
    author: str
    text: str
    created: str = ""


class CommentBoard:
    """Notes per document, kept in memory."""

    def __init__(self):
        self._notes = {}

    def add(self, doc_id, author, text):
        """Leave ``text`` on ``doc_id`` and return the note."""
        cleaned = text.strip()
        if not cleaned:
            raise ValueError("the note must not be empty")
        note = Comment(id=ids.next_id("note"), author=author, text=cleaned,
                       created=dates.stamp())
        self._notes.setdefault(doc_id, []).append(note)
        return note

    def for_document(self, doc_id):
        """Every note left on ``doc_id``, oldest first."""
        return [asdict(note) for note in self._notes.get(doc_id, [])]

    def remove(self, doc_id, note_id):
        """Remove one note; True when something was removed."""
        notes = self._notes.get(doc_id, [])
        kept = [note for note in notes if note.id != note_id]
        self._notes[doc_id] = kept
        return len(kept) != len(notes)

    def count(self, doc_id):
        """How many notes ``doc_id`` has."""
        return len(self._notes.get(doc_id, []))
