"""Deterministic judge matrix used as a mutation-testing regression guard."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from exhibit_a.oracle.oracle import (
    _judge,
    _judge_access,
    _judge_connect,
    _judge_dos,
    _judge_exec,
    _judge_redirect,
    _judge_sql,
)
from exhibit_a.oracle import OracleEvent


ENTRY = {"App.handle_request"}
ROOT = Path("/app")
TEST_DIR = Path("/tests")


def _frame(file: str, qualname: str, admitted: bool = True) -> dict:
    return {"file": file, "function": qualname.rsplit(".", 1)[-1],
            "qualname": qualname, "line": 4, "admitted": admitted}


def _event(**fields) -> OracleEvent:
    base = {
        "path": "/outside/canary.txt", "mode": "r", "op": "open", "flags": 0, "access": "read",
        "stack": [_frame("/tests/test.py", "test"), _frame("/app/app.py", "App.handle_request")],
        "requested": "/app/../outside/canary.txt",
    }
    return OracleEvent.model_validate({**base, **fields})


def test_shared_judge_rejects_channel_tampering():
    j = _judge("failed", [_event()], ROOT, TEST_DIR / "test.py", ENTRY, forged_events=1)
    assert not (j.observed_effect and j.provenance_ok)


def test_shared_judge_rejects_changed_tree():
    j = _judge("failed", [_event()], ROOT, TEST_DIR / "test.py", ENTRY,
               app_tree_changes=["modified: app.py"])
    assert not (j.observed_effect and j.provenance_ok)


def test_shared_judge_requires_failed_test():
    j = _judge("passed", [_event()], ROOT, TEST_DIR / "test.py", ENTRY)
    assert j.reason_code == "no_effect"


def test_shared_judge_requires_relevant_access():
    j = _judge("failed", [_event(access="write")], ROOT, TEST_DIR / "test.py", ENTRY)
    assert j.reason_code == "no_effect"


def test_exec_requires_tree_and_marker():
    event = _event(op="process", access="exec", names_canary=True, sink_named=True)
    j = _judge_exec("failed", [event], ROOT, TEST_DIR, ENTRY, None, True)
    assert not j.provenance_ok
    class Tree:
        def check(self, frame):
            return None

    j = _judge_exec("failed", [event], ROOT, TEST_DIR, ENTRY, Tree(), False)
    assert j.reason_code == "no_effect"
    j = _judge_exec("failed", [event], ROOT, TEST_DIR, ENTRY, Tree(), True)
    assert j.provenance_ok


def test_sql_requires_tree_and_canary_read():
    j = _judge_sql("failed", [], ROOT, TEST_DIR, ENTRY, None)
    assert not j.provenance_ok
    j = _judge_sql("failed", [], ROOT, TEST_DIR, ENTRY, object())
    assert j.reason_code == "no_effect"


def test_connect_requires_tree_and_listener_hit():
    j = _judge_connect("failed", [], ROOT, TEST_DIR, ENTRY, None, "http://127.0.0.1:1234/x", [])
    assert not j.provenance_ok
    j = _judge_connect("failed", [], ROOT, TEST_DIR, ENTRY, object(),
                       "http://127.0.0.1:1234/x", [])
    assert j.reason_code == "no_effect"


def test_dos_requires_tree_and_probe():
    j = _judge_dos("failed", [], ROOT, TEST_DIR, ENTRY, None)
    assert not j.provenance_ok
    j = _judge_dos("failed", [], ROOT, TEST_DIR, ENTRY, object())
    assert j.reason_code == "no_effect"


def test_redirect_requires_tree_and_match():
    j = _judge_redirect("failed", [], ROOT, TEST_DIR, ENTRY, None, "canary.invalid", False)
    assert not j.provenance_ok
    j = _judge_redirect("failed", [], ROOT, TEST_DIR, ENTRY, object(), "canary.invalid", False)
    assert j.reason_code == "no_effect"


def test_access_requires_tree_and_token_response():
    contract = {"attacker": "attacker", "resource": "resource"}
    j = _judge_access("failed", [], ROOT, TEST_DIR, ENTRY, None, contract, "TOKEN")
    assert not j.provenance_ok
    j = _judge_access("failed", [], ROOT, TEST_DIR, ENTRY, object(), contract, "TOKEN")
    assert j.reason_code == "no_effect"


def test_full_mutation_catalog_is_killed():
    if os.environ.get("EXHIBIT_A_MUTATION_CHILD"):
        pytest.skip("child runs only the deterministic matrix")
    from spikes.mutation import __main__ as mutation

    assert all(killed for _, killed in mutation.results())
