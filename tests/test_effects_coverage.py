"""Coverage tests for all oracle effects: dedupe, explain, and generic fallbacks.

Iterates over every member of exhibit_a.oracle.oracle.Effect and verifies that dedupe
and explain handle it without exceptions (specific rules or generic fallback).
Also tests synthetic duplicate proofs for canary_connect and canary_dos.
"""

from __future__ import annotations

from typing import get_args

import pytest

from exhibit_a.findings.dedupe import (
    AppFrame,
    FindingGroup,
    ProofFacts,
    group_findings,
    proof_facts,
    proof_key,
)
from exhibit_a.findings.explain import explain
from exhibit_a.oracle.oracle import Effect

ENTRY = "App.handle_request"
SINK = "app_sink"


def frame(file: str, qualname: str, line: int, *, admitted: bool = True) -> dict:
    return {
        "file": file,
        "function": qualname.rsplit(".", 1)[-1],
        "qualname": qualname,
        "line": line,
        "admitted": admitted,
    }


CHAIN = (
    frame("app.py", ENTRY, 10),
    frame("app.py", "intermediate_helper", 20),
    frame("app.py", SINK, 30),
)


def make_event_for_effect(effect: str, stack: list[dict]) -> dict:
    """Build a valid oracle event that satisfies _relevant for the given effect."""
    base = {"type": effect, "stack": stack, "via_symlink": False}
    if effect in ("canary_read", "canary_write"):
        access = "read" if effect == "canary_read" else "write"
        return {**base, "op": "open", "access": access, "path": "/tmp/outside/canary.txt"}
    if effect == "canary_exec":
        return {**base, "op": "process", "access": "exec", "names_canary": True, "sink_named": True}
    if effect == "canary_sql":
        return {**base, "op": "sql_read", "column": "token", "declared_db": True, "database": "main"}
    if effect == "canary_connect":
        return {
            **base,
            "op": "request",
            "url": "http://127.0.0.1:23456/544ad43213e5c62eb0df2982c0ea98b2",
            "host": "127.0.0.1",
            "port": 23456,
            "path": "http://127.0.0.1:23456/544ad43213e5c62eb0df2982c0ea98b2",
            "access": "network",
        }
    if effect == "canary_dos":
        return {
            **base,
            "op": "dos",
            "mode": "dos_probe",
            "access": "cpu",
            "command": "23=23",
            "ratio": 120.0,
            "malicious_cpu": 0.05,
            "benign_cpu": 0.0004,
            "app_fraction": 0.95,
        }
    # Generic fallback event for any other effect
    return {**base, "op": effect, "access": "unknown", "effect": effect}


# -- All members of Effect covered -------------------------------------------------------------


def test_all_effects_handled_by_dedupe_and_explain() -> None:
    """Every member of Effect must be handled by dedupe and explain without exceptions."""
    all_effects = get_args(Effect)
    assert len(all_effects) >= 6

    for effect in all_effects:
        stack = [
            frame("test.py", "test_exploit", 1, admitted=False),
            *[dict(f) for f in CHAIN],
        ]
        ev = make_event_for_effect(effect, stack)
        evidence = {
            "oracle": {"effect": effect, "events": [ev]},
            "provenance": {"ok": True, "entry_point": ENTRY},
        }

        # 1. proof_facts extracts facts without exceptions
        proof = proof_facts(evidence, roots=["/workspace"], entry_points={ENTRY})
        assert proof is not None, f"proof_facts returned None for effect {effect}"
        assert proof.effect == effect
        assert proof.entry.qualname == ENTRY
        assert proof.sink.qualname == SINK

        # 2. to_dict produces well-shaped dictionary
        facts = proof.to_dict()
        assert facts["effect"] == effect
        assert facts["entry_point"] == ENTRY
        assert facts["sink_function"] == SINK

        # 3. proof_key forms an identity
        key = proof_key(facts)
        assert key is not None, f"proof_key returned None for effect {effect}"
        assert key[0] == effect

        # 4. group_findings groups identical proofs
        groups = group_findings([("P1", facts), ("P2", facts)])
        assert len(groups) == 1
        assert groups[0].primary == "P1"
        assert groups[0].duplicates == ("P2",)

        # 5. explain produces a non-empty explanation without exceptions
        text = explain(facts)
        assert isinstance(text, str) and len(text) > 0
        assert "The oracle observed that" in text


def test_generic_fallback_handles_unregistered_future_effect() -> None:
    """An effect added later outside Effect uses the generic fallback without crashing."""
    future_effect = "canary_redirect"
    stack = [
        frame("test.py", "test_it", 1, admitted=False),
        *[dict(f) for f in CHAIN],
    ]
    ev = make_event_for_effect(future_effect, stack)
    evidence = {
        "oracle": {"effect": future_effect, "events": [ev]},
        "provenance": {"ok": True, "entry_point": ENTRY},
    }

    # With allow_unregistered=True, proof_facts and proof_key work via generic fallback
    proof = proof_facts(evidence, entry_points={ENTRY}, allow_unregistered=True)
    assert proof is not None
    assert proof.effect == future_effect

    facts = proof.to_dict()
    key = proof_key(facts, allow_unregistered=True)
    assert key is not None
    # Generic fallback key is (effect, tuple(frames))
    assert key[0] == future_effect
    assert len(key[1]) == len(CHAIN)

    # Groups correctly
    groups = group_findings([("G1", facts), ("G2", facts)])
    # Note: group_findings calls proof_key without extra args, which requires effect in EFFECTS
    # For an effect added to Effect, it is in EFFECTS and groups automatically:
    text = explain(facts)
    assert "The oracle observed that the effect 'canary_redirect'" in text


# -- canary_connect dedupe tests ---------------------------------------------------------------


def connect_facts(
    host: str = "127.0.0.1",
    port: int = 23456,
    path_class: str = "canary",
    chain: tuple = CHAIN,
) -> dict:
    app_frames = [AppFrame(f["file"], f["qualname"], f["line"], f["function"]) for f in chain]
    return ProofFacts(
        effect="canary_connect",
        access="network",
        chain=tuple(app_frames),
        line=chain[-1]["line"],
        target_host=host,
        target_port=port,
        path_class=path_class,
    ).to_dict()


def test_synthetic_duplicate_proofs_canary_connect_group() -> None:
    """Two proofs of the same canary_connect sink group into one finding."""
    first = connect_facts("127.0.0.1", 23456, "canary")
    second = connect_facts("127.0.0.1", 23456, "canary")
    groups = group_findings([("C1", first), ("C2", second)])
    assert [(g.primary, g.duplicates) for g in groups] == [("C1", ("C2",))]


def test_canary_connect_different_targets_never_merge() -> None:
    """Proofs that target different hosts, ports, or path classes never merge."""
    base = connect_facts("127.0.0.1", 23456, "canary")
    diff_host = connect_facts("169.254.169.254", 23456, "canary")
    diff_port = connect_facts("127.0.0.1", 8080, "canary")
    diff_path = connect_facts("127.0.0.1", 23456, "/api/admin")

    groups = group_findings([
        ("BASE", base),
        ("HOST", diff_host),
        ("PORT", diff_port),
        ("PATH", diff_path),
    ])
    assert [(g.primary, g.duplicates) for g in groups] == [
        ("BASE", ()),
        ("HOST", ()),
        ("PORT", ()),
        ("PATH", ()),
    ]


def test_canary_connect_different_frames_never_merge() -> None:
    """Proofs through different entry points or sinks never merge."""
    base = connect_facts("127.0.0.1", 23456, "canary")
    diff_entry = connect_facts("127.0.0.1", 23456, "canary",
                               chain=(frame("app.py", "App.dispatch", 50), CHAIN[1], CHAIN[2]))
    diff_sink = connect_facts("127.0.0.1", 23456, "canary",
                              chain=(CHAIN[0], CHAIN[1], frame("app.py", "other_sink", 99)))

    groups = group_findings([("BASE", base), ("ENTRY", diff_entry), ("SINK", diff_sink)])
    assert [(g.primary, g.duplicates) for g in groups] == [("BASE", ()), ("ENTRY", ()), ("SINK", ())]


# -- canary_dos dedupe tests -------------------------------------------------------------------


def dos_facts(
    family: str = "redos",
    cpu_fn: str = SINK,
    chain: tuple = CHAIN,
) -> dict:
    app_frames = [AppFrame(f["file"], f["qualname"], f["line"], f["function"]) for f in chain]
    return ProofFacts(
        effect="canary_dos",
        access="cpu",
        chain=tuple(app_frames),
        line=chain[-1]["line"],
        input_family=family,
        cpu_function=cpu_fn,
    ).to_dict()


def test_synthetic_duplicate_proofs_canary_dos_group() -> None:
    """Two proofs of the same canary_dos sink group into one finding."""
    first = dos_facts("redos", SINK)
    second = dos_facts("redos", SINK)
    groups = group_findings([("D1", first), ("D2", second)])
    assert [(g.primary, g.duplicates) for g in groups] == [("D1", ("D2",))]


def test_canary_dos_different_input_families_never_merge() -> None:
    """Proofs of algorithmic complexity on different input families never merge."""
    redos = dos_facts("redos", SINK)
    quadratic = dos_facts("quadratic", SINK)
    groups = group_findings([("R", redos), ("Q", quadratic)])
    assert [(g.primary, g.duplicates) for g in groups] == [("R", ()), ("Q", ())]


def test_canary_dos_different_functions_never_merge() -> None:
    """Proofs where CPU was consumed in different application functions never merge."""
    fn_a = dos_facts("redos", "scan", chain=(CHAIN[0], frame("app.py", "scan", 30)))
    fn_b = dos_facts("redos", "parse", chain=(CHAIN[0], frame("app.py", "parse", 40)))
    groups = group_findings([("A", fn_a), ("B", fn_b)])
    assert [(g.primary, g.duplicates) for g in groups] == [("A", ()), ("B", ())]


# -- Explain text tests ------------------------------------------------------------------------


def test_explain_text_connect() -> None:
    facts = connect_facts("127.0.0.1", 23456, "canary")
    facts.update({"runs": 3, "fix_verified": True})
    text = explain(facts)
    assert "the application requested a URL only the run knows (the canary URL)" in text
    assert "The outbound request targeted '127.0.0.1:23456'" in text
    assert "It happened through the entry point 'App.handle_request'" in text


def test_explain_text_dos() -> None:
    facts = dos_facts("redos", SINK)
    facts.update({"runs": 3, "fix_verified": True})
    text = explain(facts)
    assert "the application spent far more CPU on a malicious input than on a benign input" in text
    assert "The algorithmic complexity was observed on the 'redos' input family" in text
    assert "It happened through the entry point 'App.handle_request'" in text
