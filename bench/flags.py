"""Feature flags that define the ablations (SPEC.md section 11)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Flags:
    """Which verification modules are switched on for one pipeline run."""

    naive: bool = False  # "LLM reports everything": no exploit test, no verdicts
    oracle: bool = True  # the exploit must fail for the intended reason
    differential: bool = True  # the exploit must pass again after the fix
    defender: bool = True  # defender tries bypass variants of the fix


ABLATIONS: dict[str, Flags] = {
    "baseline": Flags(naive=True, oracle=False, differential=False, defender=False),
    "failing_test_only": Flags(oracle=False, differential=False, defender=False),
    "no_differential": Flags(differential=False),
    "no_defender": Flags(defender=False),
    "full": Flags(),
}


def select(names: list[str] | None) -> dict[str, Flags]:
    """Return the named ablations (all of them when `names` is empty or None)."""
    if not names:
        return dict(ABLATIONS)
    unknown = [name for name in names if name not in ABLATIONS]
    if unknown:
        raise ValueError(f"unknown ablation(s): {', '.join(unknown)}")
    return {name: ABLATIONS[name] for name in names}
