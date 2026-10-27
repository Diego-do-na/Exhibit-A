"""Integration coverage for real Ollama model-role completions."""

from __future__ import annotations

import os
import socket

import pytest

from exhibit_a.loop import prompts
from exhibit_a.models import ModelRole, OllamaProvider, Role
from exhibit_a.schemas import Location, Suspicion


_OLLAMA_HOST = "localhost"
_OLLAMA_PORT = 11434
_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
_SOURCE = """
def read_report(path):
    with open(path, encoding="utf-8") as report:
        return report.read()
"""
_SUSPICION = Suspicion(
    id="S-INTEGRATION",
    vuln_class="path_traversal",
    location=Location(file="app.py", line=2),
    entry_point="read_report(path)",
    hypothesis="The path comes from the caller without confinement to the report directory.",
    source="integration-test",
)


def _role_requests() -> list[tuple[Role, str, dict]]:
    return [
        (
            Role.ADVERSARY,
            prompts.adversary_prompt(_SOURCE, "app.py"),
            prompts.SUSPICIONS_SCHEMA,
        ),
        (
            Role.TEST_WRITER,
            prompts.writer_prompt(_SUSPICION, _SOURCE),
            prompts.EXPLOIT_SCHEMA,
        ),
        (
            Role.FIXER,
            prompts.fixer_prompt(
                _SUSPICION,
                _SOURCE,
                "def test_exploit():\n    pass\n",
                "The vulnerable entry point reads an attacker-selected path.",
            ),
            prompts.FIX_SCHEMA,
        ),
        (
            Role.DEFENDER,
            prompts.defender_prompt(
                _SUSPICION,
                _SOURCE.replace("open(path", "open(os.path.join(ALLOWED_DIR, path)"),
                "def test_exploit():\n    pass\n",
            ),
            prompts.VARIANTS_SCHEMA,
        ),
    ]


@pytest.fixture(scope="module")
def ollama_provider() -> OllamaProvider:
    try:
        with socket.create_connection((_OLLAMA_HOST, _OLLAMA_PORT), timeout=1.0):
            pass
    except (OSError, TimeoutError):
        pytest.skip("localhost:11434 is unreachable")
    return OllamaProvider(_OLLAMA_MODEL)


@pytest.mark.ollama
@pytest.mark.integration
@pytest.mark.parametrize("role, prompt, schema", _role_requests(), ids=lambda value: str(value))
def test_ollama_roles_return_schema_valid_json(
    ollama_provider: OllamaProvider,
    role: Role,
    prompt: str,
    schema: dict,
) -> None:
    result = ModelRole(role, ollama_provider).run(prompt, schema)

    assert isinstance(result.output, dict)
