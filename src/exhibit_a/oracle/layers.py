"""Test-only switch that turns off one oracle provenance layer at a time.

A suspicion is proven only when every layer agrees. Bench ablations disable exactly one
layer so a judge can see what that layer was stopping. The CLI never sets this switch:
there is no flag, no environment variable it forwards, and no parser option. Callers
pass ``disabled_layers`` to ``run_oracle`` or enter ``disable_oracle_layers`` in process.
Production callers leave every layer on.

The names match ``docs/oracle/oracle-provenance.md`` sections 3.1–3.8 and 3.15 (T114's
OS-level witness). The plugin copy that runs inside the test process reads the same
names from ``EXHIBIT_A_DISABLED_LAYERS``, which ``run_oracle`` sets only when this
switch is on and which the plugin pops at install. That variable is not part of the
test contract.
"""

from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Collection, Iterator

from exhibit_a.oracle.plugin import (
    LAYER_ADMISSION,
    LAYER_APP_TREE,
    LAYER_CANARY_LINKS,
    LAYER_DIR_FD,
    LAYER_GUARD,
    LAYER_MANIFEST,
    LAYER_ROUTE_ACCESS,
    LAYER_WITNESS,
    ORACLE_LAYERS,
)

_disabled_layers: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "exhibit_a_disabled_oracle_layers", default=frozenset()
)


def parse_disabled_layers(layers: Collection[str] | None) -> frozenset[str]:
    """Validate and freeze a set of layer names; empty/None means every layer stays on."""
    if not layers:
        return frozenset()
    parsed = frozenset(layers)
    unknown = parsed - ORACLE_LAYERS
    if unknown:
        raise ValueError(
            "unknown oracle layer(s): " + ", ".join(sorted(unknown))
            + "; known: " + ", ".join(sorted(ORACLE_LAYERS))
        )
    return parsed


def disabled_oracle_layers() -> frozenset[str]:
    """Layers the current call has switched off. Empty during normal operation."""
    return _disabled_layers.get()


@contextlib.contextmanager
def disable_oracle_layers(*layers: str) -> Iterator[frozenset[str]]:
    """Test-only: skip the named provenance layers until the context exits.

    The CLI never enters this context. Nested uses replace, they do not accumulate.
    """
    parsed = parse_disabled_layers(layers)
    token = _disabled_layers.set(parsed)
    try:
        yield parsed
    finally:
        _disabled_layers.reset(token)


__all__ = [
    "LAYER_ADMISSION",
    "LAYER_APP_TREE",
    "LAYER_CANARY_LINKS",
    "LAYER_DIR_FD",
    "LAYER_GUARD",
    "LAYER_MANIFEST",
    "LAYER_ROUTE_ACCESS",
    "LAYER_WITNESS",
    "ORACLE_LAYERS",
    "disable_oracle_layers",
    "disabled_oracle_layers",
    "parse_disabled_layers",
]
