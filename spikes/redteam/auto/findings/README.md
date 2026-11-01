# findings/

NEW false proofs found by the automated red team land here as standalone
attack files (`auto_<effect>_<case>_r<round>s<idx>.py`). Each one runs
`run_oracle` against the case's FIXED tree in `bench/corpus/`, so any proof is
false by construction. Triage each file, then promote the real ones to the
hand-written suite as `spikes/redteam/attack_*.py` (and reference the declared
limit R1-R6 or document the new one). Do not commit live-run noise without
triage: only promoted attacks belong here long-term.
