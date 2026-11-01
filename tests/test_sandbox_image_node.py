import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from exhibit_a.sandbox import image_node as node_image_mod
from exhibit_a.sandbox.image import image_tag as python_image_tag
from exhibit_a.sandbox.image_node import (
    BASE_IMAGE,
    INSTALL_DIR,
    TAG_REPOSITORY,
    TSX_VERSION,
    build_node_image,
    dockerfile,
    image_tag,
    node_image_tag,
)


def test_node_tag_is_stable_and_order_insensitive():
    a = node_image_tag(["express@4.19.2", "lodash@4.17.21"])
    assert a == node_image_tag(["lodash@4.17.21", " express@4.19.2 ", ""])
    assert a == image_tag(["express@4.19.2", "lodash@4.17.21"])
    assert a != node_image_tag(["express@4.19.2"])
    assert a.startswith("exhibit-a-sandbox-node:")
    empty = node_image_tag([])
    assert empty.startswith("exhibit-a-sandbox-node:")
    assert empty == node_image_tag(None)


def test_node_rejects_invalid_package_specs():
    # Newlines
    with pytest.raises(ValueError, match="invalid package spec|invalid requirement"):
        node_image_tag(["express\nRUN evil"])
    with pytest.raises(ValueError, match="invalid package spec|invalid requirement"):
        node_image_tag(["express\re evil"])

    # Leading dash (flag / option injection)
    with pytest.raises(ValueError, match="invalid package spec|invalid requirement"):
        node_image_tag(["--save-dev"])
    with pytest.raises(ValueError, match="invalid package spec|invalid requirement"):
        node_image_tag(["-g"])

    # URL specs
    with pytest.raises(ValueError, match="invalid package spec"):
        node_image_tag(["https://example.com/malicious.tgz"])
    with pytest.raises(ValueError, match="invalid package spec"):
        node_image_tag(["http://example.com/pkg.tgz"])
    with pytest.raises(ValueError, match="invalid package spec"):
        node_image_tag(["file:/tmp/evil"])

    # Git specs
    with pytest.raises(ValueError, match="invalid package spec"):
        node_image_tag(["git://github.com/user/repo"])
    with pytest.raises(ValueError, match="invalid package spec"):
        node_image_tag(["git+https://github.com/user/repo.git"])
    with pytest.raises(ValueError, match="invalid package spec"):
        node_image_tag(["git+ssh://git@github.com/user/repo.git"])
    with pytest.raises(ValueError, match="invalid package spec"):
        node_image_tag(["git@github.com:user/repo.git"])
    with pytest.raises(ValueError, match="invalid package spec"):
        node_image_tag(["github:user/repo"])
    with pytest.raises(ValueError, match="invalid package spec"):
        node_image_tag(["user/repo.git"])


def test_node_accepts_valid_package_specs():
    tag = node_image_tag(["@types/node@20.18.0", "express@4.19.2"])
    assert tag.startswith("exhibit-a-sandbox-node:")


def test_node_dockerfile_content_golden():
    expected_empty = (
        "FROM node:22.23.4-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da\n"
        "ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_AUDIT=false\n"
        f"WORKDIR {INSTALL_DIR}\n"
        f"RUN npm install --save-dev --save-exact --ignore-scripts {TSX_VERSION}\n"
        f'ENV PATH="{INSTALL_DIR}/node_modules/.bin:${{PATH}}"\n'
        f'ENV NODE_PATH="{INSTALL_DIR}/node_modules"\n'
    )
    assert dockerfile([]) == expected_empty

    expected_with_pkgs = (
        "FROM node:22.23.4-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da\n"
        "ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_AUDIT=false\n"
        f"WORKDIR {INSTALL_DIR}\n"
        f"RUN npm install --save-dev --save-exact --ignore-scripts {TSX_VERSION}\n"
        "RUN npm install --save-exact --ignore-scripts 'express@4.19.2' 'lodash@4.17.21'\n"
        f'ENV PATH="{INSTALL_DIR}/node_modules/.bin:${{PATH}}"\n'
        f'ENV NODE_PATH="{INSTALL_DIR}/node_modules"\n'
    )
    assert dockerfile(["express@4.19.2", "lodash@4.17.21"]) == expected_with_pkgs


def test_python_tag_unchanged():
    # Python tags for fixed requirements must remain bit-for-bit identical.
    tag_reqs = python_image_tag(["pytest==7.3.2", "requests==2.31.0"])
    assert tag_reqs == "exhibit-a-sandbox:87a4e13f8d9e47b7"

    tag_empty = python_image_tag([])
    assert tag_empty == "exhibit-a-sandbox:497209c3b1ae4986"


def test_build_node_image_once_then_reuse(monkeypatch):
    pkgs: list[str] = []
    tag = node_image_tag(pkgs)

    # Mock _image_exists to return True
    monkeypatch.setattr(node_image_mod, "_image_exists", lambda t: True)

    calls = []
    real_run = subprocess.run

    def spy(cmd, *args, **kwargs):
        calls.append(cmd)
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(node_image_mod.subprocess, "run", spy)
    assert build_node_image(pkgs) == tag
    assert not any(c[:2] == ["docker", "build"] for c in calls)


@pytest.mark.docker
def test_node_sandbox_runs_node_and_typescript_isolated():
    # 1. Build image once
    tag = build_node_image([])
    assert tag == node_image_tag([])

    # 2. Re-building returns the same tag without rebuilding
    tag_again = build_node_image([])
    assert tag_again == tag

    # 3. Execute container with sandbox isolation flags:
    # - --network none
    # - --read-only
    # - --tmpfs /tmp:rw,size=64m,mode=1777
    # - --user non-root (e.g. 1000:1000)
    # - --cap-drop ALL
    # - --security-opt no-new-privileges
    command = (
        'node --version && '
        'echo \'const val: number = 42; console.log("ts_eval=" + val);\' > /tmp/check.ts && '
        'tsx /tmp/check.ts'
    )

    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=64m,mode=1777",
            "--user",
            "1000:1000",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            tag,
            "sh",
            "-c",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, f"docker run failed: stdout={result.stdout}\nstderr={result.stderr}"
    assert "v22." in result.stdout
    assert "ts_eval=42" in result.stdout
