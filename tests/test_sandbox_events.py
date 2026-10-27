import subprocess
from pathlib import Path

import pytest

from exhibit_a.sandbox import run

try:
    _DOCKER = subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
except (OSError, subprocess.SubprocessError):
    _DOCKER = False

pytestmark = pytest.mark.skipif(not _DOCKER, reason="Docker is not available")

READER = (
    "import os\n"
    "def read_secret():\n"
    "    return open(os.environ['EXHIBIT_A_CANARY']).read()\n"
    "def test_read():\n"
    "    assert read_secret() == 'TOKEN'\n"
)


def _repo(tmp_path: Path, body: str) -> Path:
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "tests" / "test_x.py").write_text(body)
    return repo


def test_events_are_carried_out(tmp_path: Path):
    repo = _repo(tmp_path, READER)
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    events = tmp_path / "events.jsonl"
    r = run(str(repo), "tests/test_x.py", timeout=60, canary_path=str(canary), events_path=str(events))
    assert r["outcome"] == "passed", r
    assert len(r["oracle_events"]) == 1
    ev = r["oracle_events"][0]
    assert ev["path"] == "/oracle/canary"
    assert any(f["function"] == "read_secret" for f in ev["stack"])
    assert events.read_text().strip()


def test_extra_env_is_passed_and_no_events_without_read(tmp_path: Path):
    repo = _repo(tmp_path, "import os\ndef test_e():\n    assert os.environ['EXHIBIT_A_FOO'] == 'bar'\n")
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    r = run(str(repo), "tests/test_x.py", timeout=60, canary_path=str(canary), env={"EXHIBIT_A_FOO": "bar"})
    assert r["outcome"] == "passed", r
    assert r["oracle_events"] == []


def test_mounts_are_restricted(tmp_path: Path):
    body = (
        "import os\n"
        "def test_ro():\n"
        "    for p in ['/oracle/canary', '/opt/exhibit_a_plugin/exhibit_a_oracle_plugin.py']:\n"
        "        try:\n"
        "            open(p, 'a')\n"
        "            raise AssertionError('writable: ' + p)\n"
        "        except OSError:\n"
        "            pass\n"
        "    assert not os.path.exists('/opt/exhibit_a_plugin/exhibit_a')\n"
    )
    repo = _repo(tmp_path, body)
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    r = run(str(repo), "tests/test_x.py", timeout=60, canary_path=str(canary))
    assert r["outcome"] == "passed", r


def test_non_exhibit_env_is_rejected(tmp_path: Path):
    repo = _repo(tmp_path, "def test_a():\n    pass\n")
    r = run(str(repo), "tests/test_x.py", timeout=60, env={"PATH": "/x"})
    assert r["outcome"] == "env_failure"
