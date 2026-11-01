"""Automated red team: a model generates cheating exploit tests against the oracle.

For every effect and corpus case, a model (any registered provider) is asked for
cheating tests, each instructed to make the oracle declare ``proven`` on the
FIXED tree, so any proof is false by construction. Every generated test runs
through the real sandbox and oracle (``SandboxRunner.run_exploit``) and is
classified as a false proof (matching a declared residual limit R1-R6 or NEW),
blocked, or errored. NEW false proofs are saved as standalone attack files under
``spikes/redteam/auto/findings/``.

Usage (the owner runs this live; no key is available in CI)::

    python -m spikes.redteam.auto --effect all --rounds 2 --per-round 5 \\
        --provider meta --model <model> --total-usd 8 --out out/auto-redteam

Replay mode replays a recorded run offline with no model call and no sandbox::

    python -m spikes.redteam.auto --replay out/auto-redteam
"""

from spikes.redteam.auto.classify import classify, is_false_proof, match_limit
from spikes.redteam.auto.engine import replay_run, run_campaign

__all__ = ["classify", "is_false_proof", "match_limit", "replay_run", "run_campaign"]
