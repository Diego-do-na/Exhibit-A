"""Offline pins for replay determinism (docs/ci/replay-determinism.md).

The batch replay verdicts flipped between CI runs because the recorded
exploits' outcomes depend on load (CPU-ratio timing and a thread race).
These tests pin the fix without running Docker: thresholds unchanged,
warm-up present, and only replay gets wall-clock slack.
"""

import inspect

import exhibit_a.oracle.plugin as plugin
from bench import record_meta


def test_dos_thresholds_are_unchanged():
    assert plugin.DOS_RATIO == 50.0
    assert plugin.DOS_FLOOR == 0.015
    assert plugin.DOS_MIN_APP_FRACTION == 0.80
    assert plugin.DOS_SPREAD == 4.0


def test_dos_probe_warms_up_and_samples_more():
    assert plugin.DOS_SAMPLES == 9
    source = inspect.getsource(plugin)
    warm_up = source.index("timed_call(fn, benign, test_dir)\n        timed_call(fn, malicious, test_dir)")
    sampling = source.index("for _ in range(DOS_SAMPLES):")
    assert warm_up < sampling
    # Miss returns 0.0, not None, so recorded tests that assert on the
    # bound result do not flip pass/fail around the 50x threshold.
    miss = source.index("return 0.0")
    assert sampling < miss


def test_sandbox_cpu_ulimit_outlives_the_wall_clock():
    import exhibit_a.sandbox.runner as runner

    source = inspect.getsource(runner)
    assert "ceil(timeout) * 4" in source


def test_only_replay_gets_timeout_slack(monkeypatch):
    assert record_meta.RECORD_TIMEOUT_S == 60.0
    assert record_meta.REPLAY_TIMEOUT_S == 360.0
    calls = {}

    def fake_run_case(case, provider, out_dir, meter=None, profile="standard", *, timeout):
        calls["timeout"] = timeout
        return record_meta.CaseOutcome(case.id)

    real_default = inspect.signature(record_meta.run_case).parameters["timeout"].default
    monkeypatch.setattr(record_meta, "run_case", fake_run_case)
    monkeypatch.setattr(record_meta, "load_case", lambda case_id: type("C", (), {"id": case_id})())
    monkeypatch.setattr(record_meta, "replay_meter", lambda *a: None)
    record_meta.replay_case("redos-search-query", record_meta.DEFAULT_MODEL, record_meta.Path("/tmp/x"), "compact")
    assert calls["timeout"] == record_meta.REPLAY_TIMEOUT_S
    # Recording keeps the strict timeout by default.
    assert real_default == record_meta.RECORD_TIMEOUT_S
