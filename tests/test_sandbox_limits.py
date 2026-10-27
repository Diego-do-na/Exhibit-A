import sys
from pathlib import Path

import pytest

from src.exhibit_a.sandbox import run


def test_sandbox_limits_run_inside_sandbox():
    """Run the sandbox-internal limits tests inside an ephemeral sandbox via runner.run()."""
    repo_root = Path(__file__).resolve().parents[1]
    result = run(str(repo_root), "tests/sandbox_internal_tests.py", timeout=120)

    if result.get("outcome") == "env_failure":
        pytest.skip(f"docker not available: {result.get('stderr')!r}")

    # Expect the inner pytest suite to pass inside the sandbox.
    assert result.get("outcome") == "passed", (
        "Sandbox internal tests failed\n"
        f"exit_code: {result.get('exit_code')}\n\nSTDOUT:\n{result.get('stdout')}\n\nSTDERR:\n{result.get('stderr')}"
    )

