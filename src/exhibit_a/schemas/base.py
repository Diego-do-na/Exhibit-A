"""Shared base model: strict, no unknown fields."""

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base for every contract. Unknown fields are rejected, not ignored."""

    model_config = ConfigDict(extra="forbid")
