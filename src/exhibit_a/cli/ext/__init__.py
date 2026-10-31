"""Optional subcommands, discovered at parser build time.

Every module in this package that defines ``register(sub)`` adds its own subcommand to the
CLI: ``sub`` is the ``argparse`` subparsers object, and ``register`` must call
``sub.add_parser(...)`` and ``set_defaults(func=...)`` like the built-in commands in
``cli/parser.py``. Modules are registered in name order. A new command therefore lives in
one new file and never has to edit the shared parser module.
"""

from __future__ import annotations

import argparse
import importlib
import pkgutil


def register_all(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> list[str]:
    """Register every extension command; return the module names registered."""
    names: list[str] = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        register = getattr(module, "register", None)
        if callable(register):
            register(sub)
            names.append(info.name)
    return names
