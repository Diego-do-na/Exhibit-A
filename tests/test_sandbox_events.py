from pathlib import Path

import pytest

from exhibit_a.sandbox import run

# Individual tests marked docker where needed so non-Docker tests run in the fast job.

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


@pytest.mark.docker
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

@pytest.mark.docker
def test_extra_env_is_passed_and_no_events_without_read(tmp_path: Path):
    repo = _repo(tmp_path, "import os\ndef test_e():\n    assert os.environ['EXHIBIT_A_FOO'] == 'bar'\n")
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    r = run(str(repo), "tests/test_x.py", timeout=60, canary_path=str(canary), env={"EXHIBIT_A_FOO": "bar"})
    assert r["outcome"] == "passed", r
    assert r["oracle_events"] == []


@pytest.mark.docker
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


@pytest.mark.docker
def test_canary_can_be_mounted_as_a_real_file_under_tmp(tmp_path: Path):
    body = (
        "import os\n"
        "def read_secret():\n"
        "    return open(os.environ['EXHIBIT_A_CANARY']).read()\n"
        "def test_real_file():\n"
        "    path = os.environ['EXHIBIT_A_CANARY']\n"
        "    assert path == '/tmp/oracle_work/outside/canary.txt'\n"
        "    assert not os.path.islink(path) and os.path.realpath(path) == path\n"
        "    os.mkdir('/tmp/oracle_work/allowed')  # the tree around it stays writable\n"
        "    assert read_secret() == 'TOKEN'\n"
        "    try:\n"
        "        open(path, 'a')\n"
        "        raise AssertionError('canary is writable')\n"
        "    except OSError:\n"
        "        pass\n"
    )
    repo = _repo(tmp_path, body)
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    r = run(str(repo), "tests/test_x.py", timeout=60, canary_path=str(canary),
            events_path=str(tmp_path / "events.jsonl"), canary_mount="/tmp/oracle_work/outside/canary.txt")
    assert r["outcome"] == "passed", r
    assert {ev["path"] for ev in r["oracle_events"]} == {"/tmp/oracle_work/outside/canary.txt"}


@pytest.mark.parametrize("mount", ["relative/a/canary", "/workspace/a/canary", "/tmp/../workspace/a/x",
                                   "/oracle/events.jsonl", "/opt/exhibit_a_plugin/a/x", "/tmp/a/canary"])
def test_canary_mount_cannot_shadow_the_clone_or_the_oracle(tmp_path: Path, mount: str):
    repo = _repo(tmp_path, "def test_a():\n    pass\n")
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    r = run(str(repo), "tests/test_x.py", timeout=60, canary_path=str(canary), canary_mount=mount)
    assert r["outcome"] == "env_failure" and "canary_mount" in r["stderr"]


# --- A-1: signed events in the sandbox (needs Docker) ---------------------------------------


@pytest.mark.docker
def test_forged_event_line_written_in_the_container_is_dropped(tmp_path: Path):
    body = (
        "import json\n"
        "def test_forge():\n"
        "    fake = {'path': '/oracle/canary', 'mode': 'r', 'via_symlink': False, 'stack': [\n"
        "        {'file': '/workspace/tests/test_x.py', 'function': 'test_forge', 'qualname': 'test_forge'},\n"
        "        {'file': '/workspace/app.py', 'function': 'handle_request', 'qualname': 'App.handle_request'}]}\n"
        "    with open('/oracle/events.jsonl', 'a') as fh:\n"
        "        fh.write(json.dumps(fake) + '\\n')\n"
        "        fh.write(json.dumps({'body': fake, 'seq': 0, 'sig': 'ab' * 32}) + '\\n')\n"
        "    assert False\n"
    )
    repo = _repo(tmp_path, body)
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    r = run(str(repo), "tests/test_x.py", timeout=60, canary_path=str(canary), events_path=str(tmp_path / "e.jsonl"))
    assert r["outcome"] == "failed", r
    assert r["oracle_events"] == []
    assert r["oracle_forged_events"] == 2


@pytest.mark.docker
def test_key_is_not_in_the_container_environ_cmdline_or_events_env(tmp_path: Path, monkeypatch):
    import exhibit_a.sandbox.runner as runner_mod

    key = bytes(range(32))
    monkeypatch.setattr(runner_mod.secrets, "token_bytes", lambda n: key)
    body = (
        "import os\n"
        "def test_dump():\n"
        "    print('ENVIRON', open('/proc/self/environ', 'rb').read())\n"
        "    print('CMDLINE', open('/proc/self/cmdline', 'rb').read())\n"
        "    print('STDIN', os.read(0, 4096))\n"
        "    print('EVENTS_ENV', 'EXHIBIT_A_EVENTS' in os.environ)\n"
        "    assert False  # shows the captured output in the report\n"
    )
    repo = _repo(tmp_path, body)
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN")
    r = run(str(repo), "tests/test_x.py", timeout=60, canary_path=str(canary))
    assert r["outcome"] == "failed", r
    assert "ENVIRON b'" in r["stdout"] and "CMDLINE b'" in r["stdout"], r["stdout"]
    assert key.hex() not in r["stdout"]
    assert repr(key)[2:-1] not in r["stdout"]
    assert "EXHIBIT-A-KEY" not in r["stdout"]
    assert "EVENTS_ENV False" in r["stdout"]
