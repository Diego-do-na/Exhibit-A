"""Findings: group duplicate proofs of one effect, place them with the oracle, explain them.

See ``dedupe.py`` for the grouping rule and the observed location, ``explain.py`` for the
explanation template that opens a proven finding in the report and the CI summary.
"""

from exhibit_a.findings.dedupe import (
    FindingGroup,
    ProofFacts,
    group_findings,
    proof_facts,
    proof_key,
    refine_with_graph,
)
from exhibit_a.findings.explain import MODEL_GUESS_LABEL, clean_facts, explain, model_guess, summarize_patch, where

__all__ = [
    "FindingGroup",
    "MODEL_GUESS_LABEL",
    "ProofFacts",
    "clean_facts",
    "explain",
    "group_findings",
    "model_guess",
    "proof_facts",
    "proof_key",
    "refine_with_graph",
    "summarize_patch",
    "where",
]
