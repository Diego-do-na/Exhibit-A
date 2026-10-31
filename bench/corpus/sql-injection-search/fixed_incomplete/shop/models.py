"""Plain data shapes shared by the layers."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Product:
    """One catalog row."""

    id: int
    name: str
    category: str
    price_cents: int


@dataclass(frozen=True)
class SearchCriteria:
    """What a search asks for, already parsed from the request."""

    term: str = ""
    categories: tuple = field(default_factory=tuple)
    sort: str = "id"
    descending: bool = False
    limit: int = 20
