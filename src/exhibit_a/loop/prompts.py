"""Output schemas and prompt builders for the four roles.

Every role gets only the slice of context it needs. Model output is untrusted: the schemas
below are enforced by ModelRole, and the loop re-checks paths before touching the disk.
"""

from __future__ import annotations

from typing import Any

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
