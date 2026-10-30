"""Every model call is charged to the ledger exactly once.

The adversary answers once per source file with a list of suspicions. Its usage used to ride
on every SUSPICION_RAISED event, so a call that raised three suspicions was charged three
times and ledger totals (and runs.jsonl, the dashboard and the demo) overstated the spend; a
call that raised none was not charged at all. Found by T071 (docs/bench.md).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from exhibit_a.ledger import Ledger
from exhibit_a.loop import Roles, VerificationLoop
from exhibit_a.models import Completion, ModelRole, Role
from exhibit_a.models.cost import Pricing
from exhibit_a.schemas import EventType

FIXTURES = Path(__file__).parent / "fixtures" / "oracle"
ADVERSARY_COST = 0.25


def _suspicion(sid):
    return {"id": sid, "class": "path_traversal", "location": {"file": "app.py", "line": 45},
            "entry_point": "App.handle_request", "hypothesis": "h", "source": "q"}


class Adversary:
    """Only the adversary answers; with the naive flag no other role is called."""

    name = "scripted"
    pricing = Pricing()

    def __init__(self, ids):
        self.ids = ids

    def complete(self, role, prompt, schema):
        assert role == Role.ADVERSARY
        body = {"suspicions": [_suspicion(i) for i in self.ids]}
        return Completion(json.dumps(body), 100, 50, 1, model="scripted", cost_usd=ADVERSARY_COST)


class PassingBaseline:
    def run_baseline(self, clone, test_path, timeout):
        return {"outcome": "passed", "exit_code": 0, "stdout": "", "stderr": "", "oracle_events": []}

    def run_exploit(self, *args, **kwargs):  # never reached with the naive flag
        raise AssertionError("no exploit expected")


def _run(tmp_path, ids):
    from bench.flags import ABLATIONS

    clone = tmp_path / "clone"
    shutil.copytree(FIXTURES / "vulnerable", clone)
    provider = Adversary(ids)
    roles = Roles(*(ModelRole(r, provider) for r in (Role.ADVERSARY, Role.TEST_WRITER, Role.FIXER, Role.DEFENDER)))
    ledger = Ledger(tmp_path / "ledger.jsonl")
    VerificationLoop(clone, tmp_path / "out", ledger, roles, "test_baseline.py", run_id="r1",
                     runner=PassingBaseline(), flags=ABLATIONS["baseline"]).run("app.py")
    events = list(ledger.replay("r1"))
    assert ledger.totals("r1")["cost_usd"] == sum(e.cost_usd for e in events)  # what runs/dashboard show
    return events


def _charged(events):
    return sum(e.cost_usd for e in events), sum(e.tokens_in for e in events), [e for e in events if e.cost_usd]


def test_an_adversary_call_with_three_suspicions_is_charged_once(tmp_path):
    events = _run(tmp_path, ["S1", "S2", "S3"])
    cost, tokens_in, charged = _charged(events)
    assert [e.type for e in events].count(EventType.SUSPICION_RAISED) == 3
    assert cost == ADVERSARY_COST and tokens_in == 100
    assert len(charged) == 1 and charged[0].type == EventType.SUSPICION_RAISED
    assert charged[0].role == Role.ADVERSARY.value


def test_an_adversary_call_with_no_suspicion_is_still_charged(tmp_path):
    events = _run(tmp_path, [])
    cost, _, charged = _charged(events)
    assert cost == ADVERSARY_COST
    assert len(charged) == 1 and charged[0].type == EventType.SCAN_DONE
    assert charged[0].payload["status"] == "no_suspicions"


def test_duplicate_suspicions_do_not_add_charges(tmp_path):
    events = _run(tmp_path, ["S1", "S1", "S2"])
    assert _charged(events)[0] == ADVERSARY_COST
