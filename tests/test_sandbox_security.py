import os
from pathlib import Path
import textwrap
import pytest

from exhibit_a.sandbox import runner


_HOST_SECRET_ENV = "HOST_SECRET_TEST"


def _write_test_file(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content))


@pytest.mark.docker
def test_no_host_env_secrets(tmp_path: Path) -> None:
    """The sandbox must not inherit arbitrary host env vars (only explicit EXHIBIT_A_* keys)."""
    # Simulate a secret on the host
    os.environ[_HOST_SECRET_ENV] = "topsecret"

    clone = tmp_path / "repo"
    clone.mkdir()
    test_file = clone / "test_env_leak.py"
    _write_test_file(
        test_file,
        """
        import os

        def test_no_host_secret():
            # If the host secret leaked into the container, this will fail.
            assert "HOST_SECRET_TEST" not in os.environ
        """,
    )

    res = runner.run(str(clone), str(test_file.name), timeout=120)
    assert res["outcome"] == "passed", f"unexpected outcome: {res}"


@pytest.mark.docker
def test_cannot_reach_docker_socket(tmp_path: Path) -> None:
    """Container must not be able to access the Docker socket at /var/run/docker.sock."""
    clone = tmp_path / "repo2"
    clone.mkdir()
    test_file = clone / "test_docker_socket.py"
    _write_test_file(
        test_file,
        """
        import os

        def test_no_docker_socket():
            # Attempt to open the host docker socket; it must not be accessible.
            try:
                with open("/var/run/docker.sock", "rb"):
                    assert False, "/var/run/docker.sock should not be accessible from the sandbox"
            except (FileNotFoundError, PermissionError):
                # expected
                pass
        """,
    )

    res = runner.run(str(clone), str(test_file.name), timeout=120)
    assert res["outcome"] == "passed", f"unexpected outcome: {res}"


@pytest.mark.docker
def test_cannot_see_host_paths_outside_clone(tmp_path: Path) -> None:
    """The sandbox must only see the copied clone; host files outside the clone must be invisible."""
    # Create a host-side file outside the clone we will check for from inside the container.
    host_secret = Path.home() / f"exhibit_a_host_secret_{os.getpid()}"
    try:
        host_secret.write_text("host-only-secret")

        clone = tmp_path / "repo3"
        clone.mkdir()
        test_file = clone / "test_host_paths.py"
        _write_test_file(
            test_file,
            f'''
        import os

        def test_host_path_not_visible():
            # The exact host path must not be visible inside the container unless mounted.
            assert not os.path.exists("{host_secret.as_posix()}"), "host path leaked into sandbox"
        ''',
        )

        res = runner.run(str(clone), str(test_file.name), timeout=120)
        assert res["outcome"] == "passed", f"unexpected outcome: {res}"
    finally:
        try:
            host_secret.unlink()
        except Exception:
            pass

