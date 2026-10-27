"""
Pinned sandbox image builder.

`build_image(requirements)` builds a Docker image on top of a pinned base with the
given pip requirements baked in, and returns its tag. The tag is derived from a
hash of the base image and the normalized requirements, so the same inputs always
map to the same tag and the image is built only once.

The build step needs the network (pip install). The run step (see runner.py) does not.
"""
from __future__ import annotations

import hashlib
import subprocess

BASE_IMAGE = "python:3.11.9-slim"
TAG_REPOSITORY = "exhibit-a-sandbox"
BUILD_TIMEOUT = 900


def _normalize(requirements: list[str]) -> list[str]:
    """Strip, drop blanks and duplicates, and sort so ordering does not change the tag."""
    cleaned = {r.strip() for r in requirements if r.strip()}
    for req in cleaned:
        if "\n" in req or req.startswith("-"):
            raise ValueError(f"invalid requirement: {req!r}")
    return sorted(cleaned)


def image_tag(requirements: list[str]) -> str:
    """Deterministic tag for a base image plus requirements."""
    payload = "\n".join([BASE_IMAGE, *_normalize(requirements)])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"{TAG_REPOSITORY}:{digest}"


def _dockerfile(requirements: list[str]) -> str:
    lines = [f"FROM {BASE_IMAGE}", "ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1"]
    if requirements:
        # Requirements are passed as quoted pip arguments rather than a copied file.
        quoted = " ".join(_shell_quote(r) for r in requirements)
        lines.append(f"RUN pip install {quoted}")
    return "\n".join(lines) + "\n"


def _shell_quote(arg: str) -> str:
    return "'" + arg.replace("'", "'\"'\"'") + "'"


def _image_exists(tag: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def build_image(requirements: list[str]) -> str:
    """Build (once) and return the tag of the pinned image with `requirements` installed."""
    reqs = _normalize(requirements)
    tag = image_tag(reqs)
    if _image_exists(tag):
        return tag
    # The Dockerfile is sent on stdin with no build context, so no host files are exposed.
    result = subprocess.run(
        ["docker", "build", "--tag", tag, "-"],
        input=_dockerfile(reqs),
        capture_output=True,
        text=True,
        timeout=BUILD_TIMEOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker build failed for {tag}: {result.stderr[-2000:]}")
    return tag
