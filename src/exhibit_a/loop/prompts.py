"""Output schemas and prompt builders for the four roles.

Every role gets only the slice of context it needs. Model output is untrusted: the schemas
below are enforced by ModelRole, and the loop re-checks paths before touching the disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from exhibit_a.schemas import Suspicion

_STR = {"type": "string"}

SUSPICIONS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["suspicions"],
    "properties": {
        "suspicions": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "class", "location", "entry_point", "hypothesis", "source"],
                "properties": {
                    "id": _STR,
                    "class": _STR,
                    "location": {
                        "type": "object",
                        "required": ["file", "line"],
                        "properties": {"file": _STR, "line": {"type": "integer", "minimum": 0}},
                    },
                    "entry_point": _STR,
                    "hypothesis": _STR,
                    "source": _STR,
                },
            },
        }
    },
}

EXPLOIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["test_source"],
    "properties": {"test_source": _STR},
}

FIX_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["files"],
    "properties": {
        "files": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["path", "content"],
                "properties": {"path": _STR, "content": _STR},
            },
        }
    },
}

VARIANTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["variants"],
    "properties": {
        "variants": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "test_source"],
                "properties": {"name": _STR, "test_source": _STR},
            },
        }
    },
}

# The test contract. The canary's own path is deliberately not part of it (finding A-11 F2,
# see oracle/guard.py TEST_CONTRACT): an exploit reaches the canary from the allowed directory.
# The text is part of every recorded replay key (models/replay.py), so changing it invalidates
# the recorded runs.
_ENV_NOTE = (
    "The test finds the allowed directory in EXHIBIT_A_ALLOWED_DIR and the canary token in "
    "EXHIBIT_A_CANARY_TOKEN, and must reach the application only through its entry point."
)


def adversary_prompt(diff_or_source: str, file: str) -> str:
    return (
        "ROLE: adversary. List suspected vulnerabilities in the code below. Reply with JSON "
        '{"suspicions": [...]}.\n'
        f"FILE: {file}\n{diff_or_source}"
    )


def writer_prompt(suspicion: Suspicion, source: str) -> str:
    return (
        "ROLE: test_writer. Write one pytest exploit test for this suspicion. It must FAIL on "
        'vulnerable code. Reply with JSON {"test_source": "..."}.\n'
        f"{_ENV_NOTE}\nSUSPICION {suspicion.id}: {suspicion.to_json()}\n"
        f"SOURCE ({suspicion.location.file}):\n{source}"
    )


def fixer_prompt(suspicion: Suspicion, source: str, exploit: str, reason: str) -> str:
    return (
        "ROLE: fixer. Fix the proven vulnerability. Reply with JSON "
        '{"files": [{"path": "<repo-relative>", "content": "<full new file>"}]}.\n'
        f"SUSPICION {suspicion.id}: {suspicion.to_json()}\nPROOF: {reason}\n"
        f"EXPLOIT:\n{exploit}\nSOURCE ({suspicion.location.file}):\n{source}"
    )


def defender_prompt(suspicion: Suspicion, patched_source: str, exploit: str) -> str:
    return (
        "ROLE: defender. Try to bypass the fix with variants of the exploit. Reply with JSON "
        '{"variants": [{"name": "...", "test_source": "..."}]}.\n'
        f"{_ENV_NOTE}\nSUSPICION {suspicion.id}: {suspicion.to_json()}\n"
        f"ORIGINAL EXPLOIT:\n{exploit}\nPATCHED SOURCE ({suspicion.location.file}):\n{patched_source}"
    )


# -- compact profile ---------------------------------------------------------------------
#
# The "standard" builders above are frozen: their text and schemas are part of every
# recorded replay key, so changing them would invalidate the recorded runs. The compact
# profile is opt-in (``--profile compact``) and exists to cut output tokens, which are the
# bulk of the cost with reasoning models: it bounds every free-text field and every list,
# asks for code without comments or prose, and has the fixer return small search/replace
# edits instead of whole files. The loop re-checks every edit before touching the disk.

_BRIEF = "Be terse: no prose, no comments, no docstrings, no explanations outside the JSON."
_MAX_TEST_CHARS = 6000


def _bounded(max_length: int) -> dict[str, Any]:
    return {"type": "string", "maxLength": max_length}


COMPACT_SUSPICIONS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["suspicions"],
    "properties": {
        "suspicions": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "required": ["id", "class", "location", "entry_point", "hypothesis", "source"],
                "properties": {
                    "id": _bounded(32),
                    "class": _bounded(40),
                    "location": {
                        "type": "object",
                        "required": ["file", "line"],
                        "properties": {"file": _bounded(200), "line": {"type": "integer", "minimum": 0}},
                    },
                    "entry_point": _bounded(120),
                    "hypothesis": _bounded(200),
                    "source": _bounded(120),
                },
            },
        }
    },
}

COMPACT_EXPLOIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["test_source"],
    "properties": {"test_source": _bounded(_MAX_TEST_CHARS)},
}

COMPACT_FIX_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["edits"],
    "properties": {
        "edits": {
            "type": "array",
            "minItems": 1,
            "maxItems": 10,
            "items": {
                "type": "object",
                "required": ["path", "find", "replace"],
                "properties": {"path": _bounded(200), "find": _bounded(4000), "replace": _bounded(8000)},
            },
        }
    },
}

COMPACT_VARIANTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["variants"],
    "properties": {
        "variants": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "required": ["name", "test_source"],
                "properties": {"name": _bounded(60), "test_source": _bounded(_MAX_TEST_CHARS)},
            },
        }
    },
}


def test_contract(effect: str = "canary_read", packages: Sequence[str] = ()) -> str:
    """The proof contract an exploit test must meet, spelled out for the model.

    The standard profile only names the two environment variables, so a model cannot know
    where the canary is: in the first real Meta run (docs/meta-run.md) every archive exploit
    wrote outside the allowed directory, but to a file name it invented, and no Starlette
    exploit aimed at the canary. Saying where the canary is does not weaken the proof: the
    oracle still requires the application itself to touch it through the entry point.
    """
    canary = "os.path.join(os.path.dirname(os.environ['EXHIBIT_A_ALLOWED_DIR']), 'outside', 'canary.txt')"
    token = "os.environ['EXHIBIT_A_CANARY_TOKEN']"
    if effect == "canary_write":
        goal = (
            f"The canary path is {canary}; it does not exist before the test. The flaw is "
            f"proven only if the APPLICATION, handling input the test sends through its entry "
            f"point, creates that file with the token {token} as its content. End with "
            "assert not os.path.exists(<canary path>) so the test FAILS on vulnerable code."
        )
    elif effect == "canary_read":
        goal = (
            f"The canary file is {canary} (a directory named 'outside' beside the allowed "
            f"directory); it contains the token {token}. The flaw is proven only if the "
            "APPLICATION, handling a request the test sends through its entry point, reads that "
            "file. Assert the token is NOT in the application's response so the test FAILS on "
            "vulnerable code."
        )
    else:
        raise ValueError(f"unknown oracle effect {effect!r}")
    allowed = ", ".join(packages) if packages else "nothing beyond the application itself"
    return (
        f"PROOF CONTRACT: {goal} The test must PASS once the flaw is fixed: if the "
        "application refuses the input by raising an exception or answering with an error, "
        "catch that and treat it as safe, so that only the canary assertion can fail. Root the application at EXHIBIT_A_ALLOWED_DIR or at a "
        "directory the test creates beside it, never at 'outside' or inside it. Never open, "
        "create or write the canary from the test itself; never monkeypatch, replace or edit "
        "application code or modules; never use ctypes, subprocess, eval, exec or importlib "
        "tricks. Imports: the Python standard library, pytest, the application, and the "
        f"installed packages: {allowed}."
    )


def compact_adversary_prompt(diff_or_source: str, file: str) -> str:
    return (
        f"SOURCE ({file}):\n{diff_or_source}\n"
        "ROLE: adversary. List at most 3 suspected vulnerabilities that an attacker can reach "
        "through an entry point, most likely first; none if nothing is reachable. entry_point: "
        "only the exact dotted name of the function or method the attacker's input reaches "
        "first, such as App.handle_request or StaticFiles.__call__, with no arguments and no "
        "call chain. hypothesis: one sentence. source: the tainted expression only. Reply with JSON "
        f'{{"suspicions": [...]}}. {_BRIEF}'
    )


def compact_writer_prompt(suspicion: Suspicion, source: str, contract: str = _ENV_NOTE) -> str:
    return (
        f"SOURCE ({suspicion.location.file}):\n{source}\n"
        "ROLE: test_writer. Write one short pytest exploit test for this suspicion that FAILS "
        f"on the vulnerable code. {contract}\nSUSPICION {suspicion.id}: {suspicion.to_json()}\n"
        f'Reply with JSON {{"test_source": "..."}}. {_BRIEF}'
    )


def compact_fixer_prompt(suspicion: Suspicion, source: str, exploit: str, reason: str) -> str:
    return (
        f"SOURCE ({suspicion.location.file}):\n{source}\n"
        "ROLE: fixer. Fix the proven vulnerability with the smallest change. Reply with JSON "
        '{"edits": [{"path": "<repo-relative>", "find": "<exact text>", "replace": "<new text>"}]}: '
        "each find must appear exactly once in the current file; include just enough lines to "
        f"be unique. Do not rewrite the file. {_BRIEF}\n"
        f"SUSPICION {suspicion.id}: {suspicion.to_json()}\nPROOF: {reason}\nEXPLOIT:\n{exploit}"
    )


def compact_defender_prompt(
    suspicion: Suspicion, patched_source: str, exploit: str, contract: str = _ENV_NOTE
) -> str:
    return (
        f"PATCHED SOURCE ({suspicion.location.file}):\n{patched_source}\n"
        "ROLE: defender. Try to bypass the fix with at most 3 short variants of the exploit. "
        f"{contract}\nSUSPICION {suspicion.id}: {suspicion.to_json()}\nORIGINAL EXPLOIT:\n{exploit}\n"
        f'Reply with JSON {{"variants": [{{"name": "...", "test_source": "..."}}]}}. {_BRIEF}'
    )


_DOTTED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")


def canonical_entry_point(text: str) -> str:
    """The dotted name at the start of a model's entry_point, without decoration.

    Models write "App.handle_request(POST, blob)" or "StaticFiles.__call__ -> get_path";
    the oracle matches frames by exact name, so only the leading dotted name is kept. It is
    the name the model itself declared, so nothing new is allowed: a test must still reach
    the application first through that function. Text that does not start with a dotted
    name is returned unchanged and simply matches no frame.
    """
    match = _DOTTED.match(text.strip())
    return match.group(0) if match else text


PROFILES = ("standard", "compact")


@dataclass(frozen=True)
class PromptProfile:
    """One consistent set of prompt builders and output schemas."""

    name: str
    adversary_prompt: Callable[[str, str], str]
    writer_prompt: Callable[[Suspicion, str], str]
    fixer_prompt: Callable[[Suspicion, str, str, str], str]
    defender_prompt: Callable[[Suspicion, str, str], str]
    suspicions_schema: dict[str, Any]
    exploit_schema: dict[str, Any]
    fix_schema: dict[str, Any]
    variants_schema: dict[str, Any]
    #: The fixer answers with whole files ("files") or with search/replace edits ("edits").
    fix_format: str
    #: Whether the test writer and defender take a ``contract=`` text (see test_contract).
    takes_contract: bool = False
    #: Whether the suspicion's entry_point is reduced to its leading dotted name.
    canonical_entry_points: bool = False


def profile(name: str) -> PromptProfile:
    """Return the prompt profile called ``name`` ("standard" or "compact")."""
    if name == "standard":
        return PromptProfile(
            "standard", adversary_prompt, writer_prompt, fixer_prompt, defender_prompt,
            SUSPICIONS_SCHEMA, EXPLOIT_SCHEMA, FIX_SCHEMA, VARIANTS_SCHEMA, "files",
        )
    if name == "compact":
        return PromptProfile(
            "compact", compact_adversary_prompt, compact_writer_prompt, compact_fixer_prompt,
            compact_defender_prompt, COMPACT_SUSPICIONS_SCHEMA, COMPACT_EXPLOIT_SCHEMA,
            COMPACT_FIX_SCHEMA, COMPACT_VARIANTS_SCHEMA, "edits", takes_contract=True,
            canonical_entry_points=True,
        )
    raise ValueError(f"unknown prompt profile {name!r}; known profiles: {list(PROFILES)}")
