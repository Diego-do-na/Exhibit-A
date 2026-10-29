"""Continuous-integration surface: turn a run's ledger into CI results.

Thin helpers used by the GitHub Action (``action.yml``):

- ``exhibit_a.ci.summary``: result JSON, Markdown step summary, PR comment.
- ``exhibit_a.ci.gate``: rule-based PR risk gate from changed paths.

They never call the network and never decide what is proven: they only read
the verdicts the verification loop already wrote to the ledger. Submodules
are not imported here so ``python -m exhibit_a.ci.<module>`` runs cleanly.
"""
