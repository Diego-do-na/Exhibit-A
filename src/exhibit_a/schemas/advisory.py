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


# ---------------------------------------------------------------- deps.json (T109)
#
# ``exhibit-a deps`` goes one step past the advisory hint: it asks the static call graph
# whether an entry point of THIS application reaches a symbol the advisory names, and, on
# request, runs the normal proof loop through that entry point against the installed
# vulnerable version, then verifies the upgrade. ``reachable`` is still not a finding; only
# ``proof.status == "proven"`` is, and a missing proof means "nothing could be proven",
# never "not exploitable". See docs/reference/dependency-proofs.md.

DEPS_SCHEMA_VERSION = "1"

ReachStatus = Literal["reachable", "not_reachable", "unknown"]
SymbolSource = Literal["osv_ecosystem_specific", "osv_database_specific", "symbol_map", "none"]
#: not_attempted: --prove was not given. skipped: --prove was given but this advisory was not
#: run (not reachable, no effect, no fixed version, budget spent). not_proven: the loop ran and
#: no verdict met the proof standard. error: the run could not complete (install, sandbox).
ProofStatus = Literal["not_attempted", "skipped", "proven", "not_proven", "error"]


class SymbolUse(StrictModel):
    """One place where repository code uses an affected symbol (or holds a copy of it)."""

    node: str  # graph node that makes the call / holds the definition
    file: str
    line: int = Field(ge=0)
    target: str  # the dotted name the graph resolved (external edge dst or in-repo node)
    symbol: str  # the affected symbol it matched
    edge_kind: Literal["call", "ref", "in_repo"]
    context: Literal["function", "module_level", "test"]
    mounted: bool = False  # an ASGI/WSGI app symbol handed to a route table or mount call


class DependencyPath(StrictModel):
    """``entry -> ... -> use site -> affected symbol``, found by the static graph."""

    kind: Literal["call", "served", "vendored"]
    entry: str
    entry_kind: str
    oracle_entry_point: str  # the frame name the oracle must see first, for the proof
    nodes: list[str]  # entry ... the function that uses the symbol (repository nodes)
    use: SymbolUse
    hops: int = Field(ge=0)
    unresolved_hops: int = Field(ge=0)
    confidence: float = Field(ge=0, le=1)
    rendered: str


class DependencyReachability(StrictModel):
    status: ReachStatus
    reason: str
    symbols: list[str]
    symbol_source: SymbolSource
    package_imported: bool
    import_sites: list[str]
    uses: list[SymbolUse]  # every use the graph found, reachable or not
    paths: list[DependencyPath]
    possible_unresolved: list[str]  # "file:line text": calls the graph could not resolve
    blind_spots: list[str]  # what the graph cannot see, for this repository


class UpgradeFix(StrictModel):
    package: str
    from_version: str
    to_version: str
    requirement_file: str | None = None  # repository-relative file rewritten, if any
    change: str = ""  # "starlette==0.26.1 -> starlette==0.27.0"


class DependencyProof(StrictModel):
    status: ProofStatus
    reason: str
    effect: str | None = None
    entry_point: str = ""
    run_id: str = ""
    suspicion_id: str = ""
    verdict: str = ""
    upgrade: UpgradeFix | None = None
    upgrade_verified: bool = False  # the exploit passes with the upgraded dependency alone
    app_fix_proposed: bool = False
    app_fix_verified: bool | None = None  # None: no app-level fix was proposed or tried
    package: str = ""  # proof bundle directory, relative to the output directory
    cost_usd: float = Field(default=0.0, ge=0)


class DependencyAdvisory(StrictModel):
    advisory_id: str
    aliases: list[str]
    package: str
    installed_version: str
    dependency_source: str
    summary: str
    severity: list[Severity]
    severity_label: str  # database_specific.severity when given (e.g. MODERATE), else the type
    affected_status: Literal["affected", "unverified"]
    fixed_in: str | None
    upgrade_kind: Literal["patch", "minor", "major"] | None
    evidence_urls: list[str]
    vuln_class: str | None
    effect: str | None  # oracle effect that can prove this class today, if any
    reachability: DependencyReachability
    proof: DependencyProof
    fixed_by: str  # human summary, e.g. "upgrade to 0.27.0 (verified)"


class DependencyRef(StrictModel):
    name: str
    version: str
    source: str


class UnsupportedRef(StrictModel):
    text: str
    source: str
    reason: str


class GraphSummary(StrictModel):
    files: int = Field(ge=0)
    nodes: int = Field(ge=0)
    edges: int = Field(ge=0)
    external: int = Field(ge=0)
    unresolved: int = Field(ge=0)
    entry_points: int = Field(ge=0)
    truncated: bool
    skipped: int = Field(ge=0)


class ProveSettings(StrictModel):
    requested: bool
    profile: str = "compact"
    provider: str | None = None
    model: str | None = None
    budget_usd: float | None = None
    spent_usd: float = Field(default=0.0, ge=0)


class DepsCounts(StrictModel):
    advisories: int = Field(ge=0)
    reachable: int = Field(ge=0)
    not_reachable: int = Field(ge=0)
    unknown: int = Field(ge=0)
    proven: int = Field(ge=0)


class DepsReport(StrictModel):
    schema_version: Literal["1"] = DEPS_SCHEMA_VERSION
    kind: Literal["exhibit_a.deps"] = "exhibit_a.deps"
    repo: str
    generated_at: str
    data_source: Literal["live", "recorded"]
    dependency_files: list[str]
    dependencies: list[DependencyRef]
    unsupported: list[UnsupportedRef]
    include_tests: bool
    graph: GraphSummary
    prove: ProveSettings
    counts: DepsCounts
    advisories: list[DependencyAdvisory]
    notes: list[str]
