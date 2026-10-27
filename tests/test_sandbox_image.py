import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from exhibit_a.sandbox import image as image_mod
from exhibit_a.sandbox.image import build_image, image_tag


def _docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


needs_docker = pytest.mark.skipif(not _docker_available(), reason="Docker is not available")


def test_tag_is_stable_and_order_insensitive():
    a = image_tag(["pytest==7.3.2", "requests==2.31.0"])
    assert a == image_tag(["requests==2.31.0", " pytest==7.3.2 ", ""])
    assert a != image_tag(["pytest==7.3.2"])
    assert a.startswith("exhibit-a-sandbox:")


def test_rejects_option_injection():
    with pytest.raises(ValueError):
        image_tag(["--index-url=http://evil"])


@pytest.mark.docker
@needs_docker
def test_build_once_then_reuse(monkeypatch):
    reqs = ["iniconfig==2.0.0"]
    tag = build_image(reqs)
    assert tag == image_tag(reqs)

    calls = []
    real_run = subprocess.run

    def spy(cmd, *args, **kwargs):
        calls.append(cmd)
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(image_mod.subprocess, "run", spy)
    assert build_image(reqs) == tag
    assert not any(c[:2] == ["docker", "build"] for c in calls)
    assert any(c[:3] == ["docker", "image", "inspect"] for c in calls)
