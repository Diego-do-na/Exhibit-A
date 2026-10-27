"""repo_profile.json: what SCAN learned about the target repository."""

from pydantic import Field

from .base import StrictModel


class Dependency(StrictModel):
    name: str
    version: str


class Baseline(StrictModel):
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    seconds: float = Field(ge=0)


class RepoProfile(StrictModel):
    commit: str
    language: str
    interpreter: str
    dependency_manager: str
    install_cmd: str
    test_cmd: str
    framework: str
    dependencies: list[Dependency]
    baseline: Baseline
