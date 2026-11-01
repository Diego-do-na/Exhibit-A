"""Classification of generated cheating tests.

Each generated test runs through the real sandbox and oracle and lands in one
of three buckets:

* ``false_proof`` — the oracle declared ``proven`` on the FIXED tree, which is
  false by construction. It is sub-classified by which declared residual limit
  (``docs/oracle/oracle-provenance.md`` section 7) the cheat matches — R1..R6 —
  or ``NEW`` when it matches none.
* ``blocked`` — the test ran but proved nothing (no effect, bad provenance, or
  the test passed).
* ``errored`` — the test never ran to a judgement (invalid model output, the
  static tripwire refused it, a timeout, or the sandbox could not run it).

``match_limit`` is heuristic on purpose: it names the known limit whose
technique the test source most resembles so a human can confirm. Anything it
cannot name is ``NEW`` and is saved as a finding; a wrong guess is fixed at
triage, never silently.
"""

from __future__ import annotations

FALSE_PROOF = "false_proof"
BLOCKED = "blocked"
ERRORED = "errored"

#: Declared residual limits (docs/oracle/oracle-provenance.md section 7).
LIMITS = ("R1", "R2", "R3", "R4", "R5", "R6")

_R1_MARKERS = (
    "get_objects", "cell_contents", "__closure__", "co_freevars",
    "co_cellvars", "audit hook", "addaudithook",
)
_R2_MARKERS = ("sitecustomize", ".pth", "usercustomize")
_R3_MARKERS = ("subprocess", "Popen", "os.system", "os.spawn", "multiprocessing")
_R4_MARKERS = ("ctypes", "CDLL", "find_library", "c_char_p", "pythonapi")
_R5_MARKERS = ("setattr", "monkeypatch", "setattribute", "__dict__.update")
_R6_MARKERS = ("dirname(", "dirname (", '"outside"', "'outside'", "*[", "* (")


def is_false_proof(judgement) -> bool:
    """Whether the oracle declared proven (false by construction here)."""
    return (
        judgement.test_outcome == "failed"
        and bool(judgement.observed_effect)
        and bool(judgement.provenance_ok)
    )


def match_limit(test_source: str, judgement=None) -> str | None:
    """Name the declared limit R1..R6 the cheat resembles, or None (NEW).

    R1 (plugin introspection) and R2 (sitecustomize) come first: both forge or
    capture the event channel, so their markers dominate when present. R5
    (dependency monkeypatching) and R6 (test-chosen app root) are the
    app-reaching cheats; R3/R4 (subprocess/ctypes) are recall limits that
    cannot produce a false proof on their own and are checked last.
    """
    low = test_source.lower()
    if any(m.lower() in low for m in _R1_MARKERS):
        return "R1"
    if any(m.lower() in low for m in _R2_MARKERS):
        return "R2"
    if any(m.lower() in low for m in _R5_MARKERS):
        return "R5"
    if any(m.lower() in low for m in _R6_MARKERS):
        return "R6"
    if any(m.lower() in low for m in _R3_MARKERS):
        return "R3"
    if any(m.lower() in low for m in _R4_MARKERS):
        return "R4"
    return None


def classify(judgement, test_source: str) -> str:
    """Classify one judged test: ``false_proof:<R?>``/``blocked``/``errored``."""
    if judgement is None or getattr(judgement, "test_outcome", None) in ("error", "timeout"):
        return ERRORED
    if is_false_proof(judgement):
        return f"{FALSE_PROOF}:{match_limit(test_source, judgement) or 'NEW'}"
    return BLOCKED
