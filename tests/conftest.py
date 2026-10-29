import subprocess

import pytest


@pytest.fixture(scope="session")
def _docker_daemon() -> None:
    """Fail (never skip) when a test marked `docker` runs without a reachable Docker daemon."""
    try:
        ok = subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    if not ok:
        pytest.fail("Docker is required: start Colima/Docker", pytrace=False)


@pytest.fixture(autouse=True)
def _require_docker_for_marked_tests(request: pytest.FixtureRequest) -> None:
    if request.node.get_closest_marker("docker"):
        request.getfixturevalue("_docker_daemon")


@pytest.fixture(autouse=True)
def _not_running_under_github_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI refuses `--case` without `--replay` when GITHUB_ACTIONS is set.

    CI sets it for every step, so tests must not inherit it. A test that
    exercises the rule sets it explicitly with monkeypatch.setenv.
    """
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
