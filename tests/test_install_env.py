"""The scrubbed pip environment passes an allowlist of PIP_* settings and no URL credentials."""

import pytest

from exhibit_a.install import _PIP_ALLOWLIST, _minimal_env


def test_allowlisted_settings_pass(monkeypatch):
    for name in _PIP_ALLOWLIST:
        monkeypatch.setenv(name, "https://mirror.example/simple" if name.endswith("URL") else "1")
    env = _minimal_env()
    for name in _PIP_ALLOWLIST:
        assert name in env


def test_other_pip_variables_are_dropped(monkeypatch):
    monkeypatch.setenv("PIP_INDEX_URL", "https://mirror.example/simple")
    monkeypatch.setenv("PIP_CERT", "/tmp/cert.pem")
    monkeypatch.setenv("PIP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("PIP_TRUSTED_HOST", "mirror.example")
    monkeypatch.setenv("PIP_API_TOKEN", "trap")
    env = _minimal_env()
    assert env["PIP_INDEX_URL"] == "https://mirror.example/simple"
    assert not {"PIP_CERT", "PIP_PROXY", "PIP_TRUSTED_HOST", "PIP_API_TOKEN"} & set(env)


@pytest.mark.parametrize("name", ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS"])
@pytest.mark.parametrize("value", [
    "https://user:pass@mirror.example/simple",
    "https://token@mirror.example/simple",
    "https://ok.example/simple https://user:pw@other.example/simple",
])
def test_values_with_url_credentials_are_dropped(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    env = _minimal_env()
    assert name not in env
    assert "pass" not in "".join(env.values()) and "pw@" not in "".join(env.values())


def test_at_sign_outside_the_authority_is_not_userinfo(monkeypatch):
    monkeypatch.setenv("PIP_INDEX_URL", "https://mirror.example/simple/@scope")
    assert _minimal_env()["PIP_INDEX_URL"] == "https://mirror.example/simple/@scope"
