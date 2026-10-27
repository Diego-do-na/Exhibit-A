"""suspicion.json: a hypothesis proposed by the adversary, not yet proven."""

from pydantic import ConfigDict, Field

from .base import StrictModel


class Location(StrictModel):
    file: str
    line: int = Field(ge=0)


class Suspicion(StrictModel):
    # "class" is a Python keyword, so the field is vuln_class with a JSON alias.
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    vuln_class: str = Field(alias="class")
    location: Location
    entry_point: str
    hypothesis: str
    source: str

    def to_json(self) -> str:
        return self.model_dump_json(by_alias=True)
