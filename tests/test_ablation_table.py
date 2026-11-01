"""Ablation table generator and the test-only oracle layer switch.

The CLI must not be able to disable a provenance layer. The table is built from
replayed red-team attacks and labelled corpus exploits; tests inject runners so
they never call a live model.
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from bench.ablation_table import (
    DETECTED,
    FALSE_PROVEN,
    SUPPRESSED_TRUE,
    ConfigRow,
    Observation,
    classify,
    collect,
    iter_corpus_exploits,
    reclassify,
    redteam_attack_names,
    render,
    render_document,
    rows_from_observations,
    run_probes,
    update_document,
)
from bench.flags import ABLATIONS, Flags
from exhibit_a.cli.parser import build_parser
from exhibit_a.oracle import ORACLE_LAYERS, disable_oracle_layers, run_oracle
from exhibit_a.oracle.layers import (
    LAYER_APP_TREE,
    LAYER_CANARY_LINKS,
    LAYER_DIR_FD,
    LAYER_GUARD,
    LAYER_ROUTE_ACCESS,
    LAYER_WITNESS,
    parse_disabled_layers,
)
from exhibit_a.oracle.oracle import Frame, OracleEvent, _judge

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "src" / "exhibit_a" / "cli"


def test_cli_parser_has_no_layer_switch() -> None:
    parser = build_parser()
    option_strings: set[str] = set()
    for action in parser._actions:
        option_strings.update(action.option_strings)
        if hasattr(action, "choices") and isinstance(action.choices, dict):
            for subparser in action.choices.values():
                for sub_action in subparser._actions:
                    option_strings.update(sub_action.option_strings)
    assert "--disabled-layers" not in option_strings
    assert "--disable-layer" not in option_strings
    assert "--disable-oracle-layer" not in option_strings


def test_cli_source_cannot_reach_the_switch() -> None:
    """No CLI module names the test-only switch or forwards the plugin env var."""
    hits: list[str] = []
    for path in sorted(CLI.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for needle in (
            "disabled_layers",
            "disable_oracle_layers",
            "EXHIBIT_A_DISABLED_LAYERS",
            "ORACLE_LAYERS",
        ):
            if needle in text:
                hits.append(f"{path.relative_to(ROOT)}: {needle}")
    assert hits == []


def test_unknown_layer_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown oracle layer"):
        parse_disabled_layers(["not_a_layer"])
    assert parse_disabled_layers(None) == frozenset()
    assert LAYER_WITNESS in ORACLE_LAYERS
    assert len(ORACLE_LAYERS) == 8


def test_reclassify_naive_reports_everything() -> None:
    safe = Observation("cheat", "redteam", True, "BLOCKED", test_failed=True)
    real = Observation("true", "redteam", False, "DETECTED", test_failed=True)
    assert reclassify(safe, ABLATIONS["baseline"]) == FALSE_PROVEN
    assert reclassify(real, ABLATIONS["baseline"]) == DETECTED


def test_reclassify_failing_test_only_counts_any_failure() -> None:
    wrong = Observation("wrong", "redteam", True, "BLOCKED", test_failed=True)
    passed = Observation("pass", "redteam", True, "BLOCKED", test_failed=False)
    assert reclassify(wrong, ABLATIONS["failing_test_only"]) == FALSE_PROVEN
    assert reclassify(passed, ABLATIONS["failing_test_only"]) == "BLOCKED"


def test_table_generator_uses_injected_runners() -> None:
    def fake_redteam(name: str, disabled: frozenset[str]) -> Observation:
        if LAYER_CANARY_LINKS in disabled and name == "attack_symlink_recheck":
            return Observation(name, "redteam", True, FALSE_PROVEN, test_failed=True)
        if name == "attack_symlink_recheck":
            return Observation(name, "redteam", True, "BLOCKED", test_failed=True)
        return Observation(name, "redteam", False, DETECTED, test_failed=True)

    def fake_corpus(item: dict, disabled: frozenset[str]) -> Observation:
        return Observation(str(item["name"]), "corpus", False, DETECTED, test_failed=True)

    by_config = collect(
        redteam=["attack_symlink_recheck", "attack_os_open_dir_fd"],
        corpus_items=[{"name": "case:true"}],
        redteam_runner=fake_redteam,
        corpus_runner=fake_corpus,
        include_probes=False,
        configs=[
            ("loop:full", Flags(), frozenset()),
            ("loop:baseline", ABLATIONS["baseline"], frozenset()),
            ("oracle:no_L7_canary_links", Flags(), frozenset({LAYER_CANARY_LINKS})),
        ],
    )
    rows = {row.configuration: row for row in rows_from_observations(by_config)}
    assert rows["loop:full"].false_proofs == 0
    assert rows["loop:full"].true_proofs == 2
    assert rows["loop:baseline"].false_proofs == 1
    assert "attack_symlink_recheck" in rows["oracle:no_L7_canary_links"].got_through
    table = render(rows_from_observations(by_config))
    assert table.splitlines()[0] == "<!-- BEGIN GENERATED: python -m bench.ablation_table -->"
    assert "| configuration | false proofs | true proofs |" in table
    assert "`oracle:no_L7_canary_links`" in table


def test_render_is_idempotent(tmp_path: Path) -> None:
    rows = [
        ConfigRow("loop:full", 2, 4, 1, 0.0, ["attack_r1"], "pinned R1"),
        ConfigRow("oracle:no_L4_guard", 2, 4, 1, 0.0, ["attack_r1"],
                  "no additional attack on the current attack set (other layers still hold; defense in depth)"),
    ]
    first = render(rows)
    second = render(rows)
    assert first == second
    doc = tmp_path / "ablations.md"
    update_document(rows, doc)
    update_document(rows, doc)
    assert doc.read_text(encoding="utf-8") == render_document(rows)


def test_redteam_attack_list_matches_run_all() -> None:
    names = redteam_attack_names()
    assert "attack_forged_frame_filename" in names
    assert "attack_os_open_dir_fd" in names
    assert "attack_symlink_recheck" in names
    assert len(names) >= 40


def test_corpus_exploits_are_labelled_replays() -> None:
    items = iter_corpus_exploits()
    names = {str(item["name"]) for item in items}
    assert any(name.startswith("archive-extraction-pathtraversal:") for name in names)
    labels = {str(item["label"]) for item in items}
    assert "true-exploit" in labels
    assert "cheating" in labels


def _write_app(tmp_path: Path, app_src: str, test_src: str) -> tuple[Path, Path]:
    app_root = tmp_path / "app"
    tests = tmp_path / "tests"
    app_root.mkdir()
    tests.mkdir()
    (app_root / "app.py").write_text(textwrap.dedent(app_src), encoding="utf-8")
    test = tests / "test_exploit.py"
    test.write_text(textwrap.dedent(test_src), encoding="utf-8")
    return app_root, test


VULN_APP = """
    import os
    class App:
        def __init__(self, base_dir):
            self.base_dir = base_dir
        def handle_request(self, name):
            with open(os.path.join(self.base_dir, name), encoding="utf-8") as fh:
                return fh.read()
"""

SAFE_APP = """
    import os
    class App:
        def __init__(self, base_dir):
            self.base_dir = os.path.realpath(base_dir)
        def handle_request(self, name):
            full = os.path.realpath(os.path.join(self.base_dir, name))
            if os.path.commonpath([full, self.base_dir]) != self.base_dir:
                raise PermissionError("escapes")
            with open(full, encoding="utf-8") as fh:
                return fh.read()
"""


def test_guard_layer_off_skips_the_tripwire(tmp_path: Path) -> None:
    app_root, test = _write_app(
        tmp_path, VULN_APP,
        """
        def test_mentions_channel():
            assert "EXHIBIT_A_EVENTS" or True
        """,
    )
    blocked = run_oracle(app_root, test, {"App.handle_request"})
    assert blocked.reason_code == "channel_tripwire"
    with disable_oracle_layers(LAYER_GUARD):
        ran = run_oracle(app_root, test, {"App.handle_request"})
    assert ran.reason_code != "channel_tripwire"


def test_canary_links_layer_off_lets_a_planted_symlink_through(tmp_path: Path) -> None:
    # Lexically safe (rejects "..") but follows a symlink planted in the allowed dir.
    app_root, test = _write_app(
        tmp_path,
        """
        import os
        class App:
            def __init__(self, base_dir):
                self.base_dir = os.path.realpath(base_dir)
            def handle_request(self, name):
                if ".." in name.split("/"):
                    raise PermissionError("no traversal")
                with open(os.path.join(self.base_dir, name), encoding="utf-8") as fh:
                    return fh.read()
        """,
        """
        import os
        from app import App
        def test_symlink():
            allowed = os.environ["EXHIBIT_A_ALLOWED_DIR"]
            canary = os.path.join(os.path.dirname(allowed), "outside", "canary.txt")
            token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
            link = os.path.join(allowed, "leak.txt")
            os.symlink(canary, link)
            leaked = App(allowed).handle_request("leak.txt")
            assert token not in leaked
        """,
    )
    blocked = run_oracle(app_root, test, {"App.handle_request"})
    assert not (blocked.observed_effect and blocked.provenance_ok)
    proven = run_oracle(
        app_root, test, {"App.handle_request"},
        disabled_layers={LAYER_CANARY_LINKS},
    )
    assert proven.observed_effect and proven.provenance_ok and proven.test_outcome == "failed"


def test_dir_fd_layer_off_misses_a_true_openat(tmp_path: Path) -> None:
    app_root, test = _write_app(
        tmp_path,
        """
        import os
        class App:
            def __init__(self, base_dir):
                self.base_dir = base_dir
            def handle_request(self, name):
                outside = os.path.join(os.path.dirname(self.base_dir), "outside")
                dfd = os.open(outside, os.O_RDONLY)
                try:
                    fd = os.open(name, os.O_RDONLY, dir_fd=dfd)
                    try:
                        return os.read(fd, 1 << 20).decode()
                    finally:
                        os.close(fd)
                finally:
                    os.close(dfd)
        """,
        """
        import os
        from app import App
        def test_openat():
            token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
            leaked = App(os.environ["EXHIBIT_A_ALLOWED_DIR"]).handle_request("canary.txt")
            assert token not in leaked
        """,
    )
    detected = run_oracle(app_root, test, {"App.handle_request"})
    assert detected.observed_effect and detected.provenance_ok
    missed = run_oracle(app_root, test, {"App.handle_request"}, disabled_layers={LAYER_DIR_FD})
    assert not (missed.observed_effect and missed.provenance_ok)


def test_witness_layer_off_drops_os_agreement() -> None:
    app_root = Path("/tmp/exhibit_a_ablation_app")
    test_path = Path("/tmp/exhibit_a_ablation_tests/test_x.py")
    event = OracleEvent(
        path="/tmp/work/outside/canary.txt",
        mode="r",
        stack=[
            Frame(file=str(test_path), function="test_x", qualname="test_x", line=1, admitted=False),
            Frame(
                file=str(app_root / "app.py"), function="handle_request",
                qualname="App.handle_request", line=1, admitted=True,
            ),
        ],
        op="open", flags=getattr(os, "O_RDONLY", 0), access="read",
        requested="/tmp/work/allowed/../outside/canary.txt",
    )
    refused = _judge(
        "failed", [event], app_root, test_path, {"App.handle_request"},
        allowed_dir="/tmp/work/allowed",
        witness={"status": "ok", "observed": []},
    )
    assert refused.reason_code == "witness_mismatch"
    with disable_oracle_layers(LAYER_WITNESS):
        proven = _judge(
            "failed", [event], app_root, test_path, {"App.handle_request"},
            allowed_dir="/tmp/work/allowed",
            witness={"status": "ok", "observed": []},
        )
    assert proven.observed_effect and proven.provenance_ok and proven.reason_code == ""


def test_probes_show_l3_l6_l14_when_those_layers_are_off() -> None:
    full = {obs.name: obs.verdict for obs in run_probes()}
    assert full["probe_L3_app_tree_change"] != FALSE_PROVEN
    assert full["probe_L6_route_access"] != FALSE_PROVEN
    assert full["probe_L14_witness"] != FALSE_PROVEN
    l3 = {obs.name: obs.verdict for obs in run_probes(frozenset({LAYER_APP_TREE}))}
    l6 = {obs.name: obs.verdict for obs in run_probes(frozenset({LAYER_ROUTE_ACCESS}))}
    l14 = {obs.name: obs.verdict for obs in run_probes(frozenset({LAYER_WITNESS}))}
    assert l3["probe_L3_app_tree_change"] == FALSE_PROVEN
    assert l6["probe_L6_route_access"] == FALSE_PROVEN
    assert l14["probe_L14_witness"] == FALSE_PROVEN


def test_committed_doc_has_the_required_columns() -> None:
    from bench.ablation_table import DOC
    text = DOC.read_text(encoding="utf-8")
    assert "| configuration | false proofs | true proofs |" in text
    assert "`loop:full`" in text
    assert "`oracle:no_L14_witness`" in text
    assert "`oracle:no_L7_canary_links`" in text
    assert "isolated and resource-limited" in text
    assert "nothing could be proven" in text
    assert "The CLI has no flag" in text


def test_classify_matches_the_redteam_harness() -> None:
    assert classify(True, True, "failed", app_is_safe=True) == FALSE_PROVEN
    assert classify(True, True, "failed", app_is_safe=False) == DETECTED
    assert classify(False, False, "failed", app_is_safe=False) == SUPPRESSED_TRUE
