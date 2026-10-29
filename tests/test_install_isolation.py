import os
import subprocess
import sys

import pytest


from exhibit_a.install import safe_pip_install


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_install_subprocess_receives_stripped_env(monkeypatch):
    called = {}

    def fake_run(cmd, capture_output, text, env):
        called["cmd"] = cmd
        called["env"] = env
        return FakeProc(returncode=0, stdout="ok\n", stderr="")

    # Populate host env with some API keys / tokens that must not be forwarded.
    monkeypatch.setenv("FOO_API_KEY", "secret")
    monkeypatch.setenv("BAR_TOKEN", "verysecret")
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    monkeypatch.setenv("PYTHONPATH", "/some/path")

    monkeypatch.setattr(subprocess, "run", fake_run)
    safe_pip_install(target="/tmp/target", requirements=["pkg==1.2.3"])

    assert "--only-binary=:all:" in called["cmd"]
    # env must be a dict with minimal keys and must not include any API key or token vars
    assert "FOO_API_KEY" not in called["env"]
    assert "BAR_TOKEN" not in called["env"]
    # PATH and PYTHONDONTWRITEBYTECODE may be present
    assert "PATH" in called["env"]
    assert "PYTHONDONTWRITEBYTECODE" in called["env"]


def test_install_fails_clearly_when_no_wheel(monkeypatch):
    def fake_run(cmd, capture_output, text, env):
        return FakeProc(returncode=1, stdout="", stderr="No matching distribution found for starlette==0.0.0\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError) as exc:
        safe_pip_install(target="/tmp/target", requirements=["starlette==0.0.0"])
    assert "no wheel" in str(exc.value).lower() or "no matching" in str(exc.value).lower()

