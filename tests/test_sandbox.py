import sys
from pathlib import Path
import uuid

import pytest

# Ensure `src/` is on sys.path so `exhibit_a` can be imported when tests run from project root.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from exhibit_a.sandbox import run


def _prepare_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    return repo, tests_dir


def test_positive_pass(tmp_path: Path):
    repo, tests_dir = _prepare_repo(tmp_path)
    (tests_dir / "test_pass.py").write_text("def test_ok():\n    assert True\n")
    r = run(str(repo), "tests/test_pass.py", timeout=20)
    assert r["outcome"] == "passed", r


def test_network_blocked(tmp_path: Path):
    repo, tests_dir = _prepare_repo(tmp_path)
    (tests_dir / "test_network.py").write_text(
        "def test_no_network():\n"
        "    import socket\n"
        "    try:\n"
        "        socket.create_connection(('1.1.1.1', 80), timeout=2)\n"
        "        connected = True\n"
        "    except Exception:\n"
        "        connected = False\n"
        "    assert not connected\n"
    )
    r = run(str(repo), "tests/test_network.py", timeout=20)
    assert r["outcome"] == "passed", r


def test_write_outside_fails(tmp_path: Path):
    repo, tests_dir = _prepare_repo(tmp_path)
    (tests_dir / "test_write.py").write_text(
        "def test_cannot_write_outside():\n"
        "    try:\n"
        "        with open('/outside_canary.txt','w') as f:\n"
        "            f.write('x')\n"
        "        wrote = True\n"
        "    except Exception:\n"
        "        wrote = False\n"
        "    assert not wrote\n"
    )
    r = run(str(repo), "tests/test_write.py", timeout=20)
    assert r["outcome"] == "passed", r


def test_host_file_not_visible(tmp_path: Path):
    repo, tests_dir = _prepare_repo(tmp_path)
    # create host-only file under HOME (Colima shares HOME only); do NOT place it under repo
    host_root = Path.home() / ".cache" / "exhibit_a_host_tests"
    host_root.mkdir(parents=True, exist_ok=True)
    host_file = host_root / f"secret_{uuid.uuid4().hex}.txt"
    host_file.write_text("secret")

    (tests_dir / "test_hostvis.py").write_text(
        f"def test_host_file_not_visible():\n"
        f"    import os\n"
        f"    path = {str(host_file)!r}\n"
        f"    assert not os.path.exists(path)\n"
    )
    r = run(str(repo), "tests/test_hostvis.py", timeout=20)
    assert r["outcome"] == "passed", r
    try:
        host_file.unlink()
    except Exception:
        pass


def test_container_not_root(tmp_path: Path):
    repo, tests_dir = _prepare_repo(tmp_path)
    (tests_dir / "test_not_root.py").write_text(
        "def test_not_root():\n"
        "    import os\n"
        "    assert os.geteuid() != 0\n"
    )
    r = run(str(repo), "tests/test_not_root.py", timeout=20)
    assert r["outcome"] == "passed", r


def test_runaway_timeout(tmp_path: Path):
    repo, tests_dir = _prepare_repo(tmp_path)
    (tests_dir / "test_runaway.py").write_text(
        "def test_runaway():\n"
        "    while True:\n"
        "        pass\n"
    )
    r = run(str(repo), "tests/test_runaway.py", timeout=5)
    assert r["outcome"] == "timeout", r

