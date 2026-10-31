"""The CLI extension package: commands discovered from src/exhibit_a/cli/ext/."""

from __future__ import annotations

import argparse
from typing import get_args

from exhibit_a.cli import ext
from exhibit_a.cli.parser import build_parser
from exhibit_a.oracle.oracle import Effect


def test_register_all_adds_a_module_that_defines_register(tmp_path, monkeypatch):
    (tmp_path / "hello.py").write_text(
        "def register(sub):\n"
        "    p = sub.add_parser('hello')\n"
        "    p.set_defaults(func=lambda args: 0)\n",
        encoding="utf-8",
    )
    (tmp_path / "_private.py").write_text("def register(sub):\n    raise AssertionError\n")
    (tmp_path / "helper.py").write_text("VALUE = 1\n")
    monkeypatch.setattr(ext, "__path__", [str(tmp_path)])
    monkeypatch.setattr(ext, "__name__", "exhibit_ext_probe")
    monkeypatch.syspath_prepend(str(tmp_path.parent))
    import sys, types
    pkg = types.ModuleType("exhibit_ext_probe")
    pkg.__path__ = [str(tmp_path)]
    monkeypatch.setitem(sys.modules, "exhibit_ext_probe", pkg)

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    assert ext.register_all(sub) == ["hello"]
    assert parser.parse_args(["hello"]).command == "hello"


def test_the_built_in_parser_still_builds_with_the_extension_hook():
    args = build_parser().parse_args(["run"])
    assert args.command == "run"


def test_effect_choices_follow_the_oracle():
    for effect in get_args(Effect):
        assert build_parser().parse_args(["run", "--effect", effect]).effect == effect
