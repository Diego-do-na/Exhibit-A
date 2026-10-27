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

