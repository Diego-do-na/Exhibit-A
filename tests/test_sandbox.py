import sys
import pytest

# Old duplicated sandbox tests — skipped. New canonical tests live in tests/test_sandbox_clean.py
pytest.skip("skipping legacy duplicated test_sandbox.py; see tests/test_sandbox_clean.py", allow_module_level=True)
import subprocess
from pathlib import Path

import pytest

# Ensure `src/` is on sys.path so `exhibit_a` can be imported when tests run from project root.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from exhibit_a.sandbox import run


def docker_available() -> bool:
    from shutil import which

    if which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


@pytest.mark.skipif(not docker_available(), reason="docker is not available")
def test_sandbox_positive_and_isolation(tmp_path: Path):
    """
    Positive case and isolation checks:
      - a simple test passes -> outcome == 'passed'
      - network is blocked
      - writing outside the clone fails
      - host file (outside clone) is not visible
      - runaway loop is killed by timeout -> outcome == 'timeout'
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    tests_dir = repo / "tests"
    tests_dir.mkdir()

    # positive passing test
    (tests_dir / "test_pass.py").write_text("def test_ok():\n    assert True\n")

    # network blocked test
    (tests_dir / "test_network_blocked.py").write_text(
        "def test_no_network():\n"
        "    import socket\n"
        "    try:\n"
        "        socket.create_connection(('1.1.1.1', 80), timeout=2)\n"
        "        connected = True\n"
        "    except Exception:\n"
        "        connected = False\n"
        "    assert not connected\n"
    )

    # write outside clone should fail
    (tests_dir / "test_write_outside.py").write_text(
        "def test_cannot_write_outside():\n"
        "    try:\n"
        "        with open('/out_of_clone_attempt.txt','w') as f:\n"
        "            f.write('x')\n"
        "        wrote = True\n"
        "    except Exception:\n"
        "        wrote = False\n"
        "    assert not wrote\n"
    )

    # runaway loop
    (tests_dir / "test_runaway.py").write_text(
        "def test_runaway():\n"
        "    while True:\n"
        "        pass\n"
    )

    # host-only file (outside the clone)
    host_dir = tmp_path / "host_only"
    host_dir.mkdir()
    host_file = host_dir / "secret.txt"
    host_file.write_text("secret")

    (tests_dir / "test_host_file_not_visible.py").write_text(
        f"def test_host_file_not_visible():\n"
        f"    import os\n"
        f"    path = {str(host_file)!r}\n"
        f"    assert not os.path.exists(path)\n"
    )

    # Run positive test
    r = run(str(repo), "tests/test_pass.py", timeout=20)
    assert r["outcome"] == "passed", f"positive passing test failed: {r}"

    # Isolation checks
    r = run(str(repo), "tests/test_network_blocked.py", timeout=20)
    assert r["outcome"] == "passed", f"network blocked test failed: {r}"

    r = run(str(repo), "tests/test_write_outside.py", timeout=20)
    assert r["outcome"] == "passed", f"write outside test failed: {r}"

    r = run(str(repo), "tests/test_host_file_not_visible.py", timeout=20)
    assert r["outcome"] == "passed", f"host file visibility test failed: {r}"

    # Runaway test should be timed out
    r = run(str(repo), "tests/test_runaway.py", timeout=5)
    assert r["outcome"] == "timeout", f"runaway loop should be killed by timeout, got: {r}"

import sys
import subprocess
from pathlib import Path

import pytest

# Ensure `src/` is on sys.path so `exhibit_a` can be imported when tests run from project root.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from exhibit_a.sandbox import run


def docker_available() -> bool:
    from shutil import which

    if which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


@pytest.mark.skipif(not docker_available(), reason="docker is not available")
def test_sandbox_positive_and_isolation(tmp_path: Path):
    """
    Positive case and isolation checks:
      - a simple test passes -> outcome == 'passed'
      - network is blocked
      - writing outside the clone fails
      - host file (outside clone) is not visible
      - runaway loop is killed by timeout -> outcome == 'timeout'
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    tests_dir = repo / "tests"
    tests_dir.mkdir()

    # positive passing test
    (tests_dir / "test_pass.py").write_text("def test_ok():\n    assert True\n")

    # network blocked test
    (tests_dir / "test_network_blocked.py").write_text(
        "def test_no_network():\n"
        "    import socket\n"
        "    try:\n"
        "        socket.create_connection(('1.1.1.1', 80), timeout=2)\n"
        "        connected = True\n"
        "    except Exception:\n"
        "        connected = False\n"
        "    assert not connected\n"
    )

    # write outside clone should fail
    (tests_dir / "test_write_outside.py").write_text(
        "def test_cannot_write_outside():\n"
        "    try:\n"
        "        with open('/out_of_clone_attempt.txt','w') as f:\n"
        "            f.write('x')\n"
        "        wrote = True\n"
        "    except Exception:\n"
        "        wrote = False\n"
        "    assert not wrote\n"
    )

    # runaway loop
    (tests_dir / "test_runaway.py").write_text(
        "def test_runaway():\n"
        "    while True:\n"
        "        pass\n"
    )

    # host-only file (outside the clone)
    host_dir = tmp_path / "host_only"
    host_dir.mkdir()
    host_file = host_dir / "secret.txt"
    host_file.write_text("secret")

    (tests_dir / "test_host_file_not_visible.py").write_text(
        f"def test_host_file_not_visible():\n"
        f"    import os\n"
        f"    path = {str(host_file)!r}\n"
        f"    assert not os.path.exists(path)\n"
    )

    # Run positive test
    r = run(str(repo), "tests/test_pass.py", timeout=20)
    assert r["outcome"] == "passed", f"positive passing test failed: {r}"

    # Isolation checks
    r = run(str(repo), "tests/test_network_blocked.py", timeout=20)
    assert r["outcome"] == "passed", f"network blocked test failed: {r}"

    r = run(str(repo), "tests/test_write_outside.py", timeout=20)
    assert r["outcome"] == "passed", f"write outside test failed: {r}"

    r = run(str(repo), "tests/test_host_file_not_visible.py", timeout=20)
    assert r["outcome"] == "passed", f"host file visibility test failed: {r}"

    # Runaway test should be timed out
    r = run(str(repo), "tests/test_runaway.py", timeout=5)
    assert r["outcome"] == "timeout", f"runaway loop should be killed by timeout, got: {r}"

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import sys

# Ensure `src/` is on sys.path so `exhibit_a` can be imported when tests run from project root.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from exhibit_a import sandbox


def _docker_available():
    if shutil.which("docker") is None:
        return False, "docker-cli-missing"
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True, ""
    except Exception as e:
        return False, f"docker-unavailable: {e}"


@pytest.mark.skipif(not _docker_available()[0], reason=_docker_available()[1])
def test_sandbox_isolated_behavior(tmp_path: Path):
    """
    Verify the sandbox blocks network, cannot write outside the mounted clone,
    does not see host files, and that a runaway loop is killed by the timeout.
    """
    # Prepare a tiny repo clone with pytest tests
    repo = tmp_path / "repo"
    repo.mkdir()
    tests_dir = repo / "tests"
    tests_dir.mkdir()

    # Test file that asserts network is blocked, writing outside clone fails, and host file not visible.
    test_env = tests_dir / "test_env.py"
    test_env.write_text(
        '''
import socket
import os
import pytest

def test_network_blocked():
    # Attempt to open an external TCP connection; expect it to fail inside the sandbox.
    with pytest.raises(OSError):
        s = socket.create_connection(("example.com", 80), timeout=3)
        s.close()

def test_write_outside_clone():
    # Root filesystem is read-only; writing to /etc should fail.
    with pytest.raises(Exception):
        with open("/etc/hosts", "w") as f:
            f.write("x")

def test_host_file_not_visible():
    # The host marker file (created by the test runner) must NOT be visible inside the container.
    assert not os.path.exists("/tmp/EXHIBIT_A_SANDBOX_HOST_MARKER")
'''
    )

    # Runaway test that loops forever
    test_runaway = tests_dir / "test_runaway.py"
    test_runaway.write_text(
        '''
import time

def test_runaway():
    while True:
        time.sleep(0.1)
'''
    )

    # Create a host-only marker file that should not be visible inside the container
    host_marker = Path("/tmp/EXHIBIT_A_SANDBOX_HOST_MARKER")
    try:
        host_marker.write_text("host-only")

        # First, run the environment tests
        res = sandbox.run(str(repo), "tests/test_env.py", timeout=30)
        assert res["outcome"] == "passed", f"env tests did not pass: {res['stderr']}\nstdout:\n{res['stdout']}"

        # Then run the runaway test and expect a timeout outcome
        res2 = sandbox.run(str(repo), "tests/test_runaway.py", timeout=2)
        assert res2["outcome"] == "timeout", "runaway loop should be killed by the sandbox timeout"
    finally:
        try:
            host_marker.unlink()
        except Exception:
            pass
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from exhibit_a.sandbox import run


def docker_available() -> bool:
    return shutil.which("docker") is not None


@pytest.mark.skipif(not docker_available(), reason="docker not available")
def test_sandbox_network_and_fs_and_timeout(tmp_path: Path):
    """
    Integration tests for the sandbox runner. These tests skip cleanly when Docker
    is unavailable.

    The test performs four checks by creating small temporary projects and invoking
    the sandbox runner on each:
      1) network is blocked (a test that expects socket.connect to raise OSError)
      2) writing outside the mounted clone fails with a read-only filesystem error
      3) a runaway loop is killed by the provided timeout (outcome == "timeout")
      4) host files that are not mounted are not visible inside the container
    """
    root = tmp_path / "projects"
    root.mkdir()

    # 0) prepare a host-only secret file (should NOT be visible inside container)
    host_secret_dir = tmp_path / "host_only"
    host_secret_dir.mkdir()
    host_secret = host_secret_dir / "secret.txt"
    host_secret.write_text("top-secret")

    # Helper to make a minimal project with a single test file
    def make_project(name: str, test_code: str) -> Path:
        p = root / name
        p.mkdir()
        tests_dir = p / "tests"
        tests_dir.mkdir()
        (tests_dir / "__init__.py").write_text("")
        (tests_dir / "test_spec.py").write_text(test_code)
        # create a trivial pyproject so pip target installs are less surprising
        (p / "pyproject.toml").write_text("[project]\nname = 'proj'\n")
        return p

    # 1) network blocked
    code_network = """
def test_network_blocked():
    import socket
    s = socket.socket()
    # connecting to an external IP should fail when Docker network is disabled
    try:
        s.connect(("1.1.1.1", 80))
    except OSError:
        return
    finally:
        s.close()
    raise AssertionError("network appears to be available inside the sandbox")
"""
    proj1 = make_project("net", code_network)
    r1 = run(str(proj1), "tests/test_spec.py::test_network_blocked", timeout=20)
    assert r1["outcome"] == "passed", f"network test failed: {r1}"

    # 2) writing outside the clone should fail (read-only root)
    code_write_outside = """
def test_write_outside_clone():
    path = "/outside_canary.txt"
    try:
        with open(path, "w") as f:
            f.write("x")
    except OSError:
        return
    raise AssertionError("was able to write outside the clone; filesystem not read-only")
"""
    proj2 = make_project("write", code_write_outside)
    r2 = run(str(proj2), "tests/test_spec.py::test_write_outside_clone", timeout=20)
    assert r2["outcome"] == "passed", f"write outside test failed: {r2}"

    # 3) runaway loop killed by timeout
    code_runaway = """
def test_runaway():
    import time
    # infinite loop (should be terminated by the sandbox timeout)
    while True:
        time.sleep(0.1)
"""
    proj3 = make_project("runaway", code_runaway)
    r3 = run(str(proj3), "tests/test_spec.py::test_runaway", timeout=3)
    assert r3["outcome"] == "timeout", f"runaway loop was not killed by timeout: {r3}"

    # 4) host files are not visible inside the container
    code_host_visibility = f'''
def test_host_file_not_visible():
    import os
    path = {json.dumps(str(host_secret))}
    if os.path.exists(path):
        raise AssertionError("host file is visible inside the container")
'''
    proj4 = make_project("hostvis", code_host_visibility)
    r4 = run(str(proj4), "tests/test_spec.py::test_host_file_not_visible", timeout=20)
    assert r4["outcome"] == "passed", f"host file visibility test failed: {r4}"

