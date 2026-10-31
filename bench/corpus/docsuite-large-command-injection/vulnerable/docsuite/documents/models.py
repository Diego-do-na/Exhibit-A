"""The document record."""

from dataclasses import asdict, dataclass, field


@dataclass
class Document:
    """One written document with its metadata."""

    id: str
    title: str
    body: str
    owner: str
    tags: list = field(default_factory=list)
    created: str = ""
    updated: str = ""

    def to_dict(self):
        """The document as plain JSON-serializable data."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        """A document rebuilt from :meth:`to_dict` output."""
        return cls(
            id=data["id"],
            title=data.get("title", ""),
            body=data.get("body", ""),
            owner=data.get("owner", ""),
            tags=list(data.get("tags", [])),
            created=data.get("created", ""),
            updated=data.get("updated", ""),
        )

    def summary(self):
        """The fields shown in listings."""
        return {"id": self.id, "title": self.title, "owner": self.owner,
                "tags": list(self.tags), "updated": self.updated}

    def length(self):
        """The body length in characters."""
        return len(self.body)
