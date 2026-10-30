# Audit A-11 F2 proofs of concept (cheating)

Tests that make a SAFE app touch the canary by choosing where the app is rooted
(docs/security/audit-integration.md section 2.1: P1, P1b, P7). They are judged against the safe apps
(`../fixed/app.py`, `bench/corpus/archive-extraction-pathtraversal/fixed/archive.py`) by
`tests/test_oracle_eval_archive.py` and `tests/test_oracle.py`, and must never be proven.

The `plain` variants name `EXHIBIT_A_CANARY`, as the audit wrote them; the `derived` variants
compute the canary's directory from `EXHIBIT_A_ALLOWED_DIR` instead. Both are refused by the
static guard; a variant that hides the computation from it is residual limit R6
(docs/oracle/oracle-provenance.md).
