"""advisory_match.json: a known advisory that names a pinned dependency.

This is a SECOND SIGNAL, not a finding. It says "a public advisory claims this pinned
version is affected", with evidence a human can follow. It can feed a suspicion, but it
never carries a verdict and can never be `proven` on its own: proof still requires the
exploit loop in SPEC.md section 4.
"""

from typing import Literal

from pydantic import Field

from .base import StrictModel

ADVISORY_SCHEMA_VERSION = "1"


class Severity(StrictModel):
    type: str  # e.g. CVSS_V3, CVSS_V4, as given by the record; not recomputed
    score: str


class ReachabilityHint(StrictModel):
    kind: Literal["static_hint"] = "static_hint"
    package_imported: bool
    import_sites: list[str]  # "path:line", relative to the scanned root
    symbols_listed: list[str]  # affected symbols named by the advisory (may be empty)
    symbols_referenced: list[str]  # listed symbols whose name appears in project code
    symbol_sites: list[str]
    files_scanned: int = Field(ge=0)
    files_skipped: int = Field(ge=0)
    notes: list[str]


class AdvisoryMatch(StrictModel):
    schema_version: Literal["1"] = ADVISORY_SCHEMA_VERSION
    signal: Literal["advisory_hint"] = "advisory_hint"
    ecosystem: Literal["PyPI"] = "PyPI"
    package: str
    installed_version: str
    dependency_source: str
    advisory_id: str
    aliases: list[str]
    summary: str
    severity: list[Severity]
    # affected: the record's ranges/versions include the installed version.
    # unverified: the backend returned it but no range could be evaluated locally.
    affected_status: Literal["affected", "unverified"]
    fixed_in: str | None
    patch_available: bool
    upgrade_kind: Literal["patch", "minor", "major"] | None
    upgrade_is_minor_or_major: bool | None
    evidence_urls: list[str]
    data_source: Literal["live", "recorded"]
    advisory_modified: str
    notes: list[str]
    reachability: ReachabilityHint | None = None
