"""
Pinned Node sandbox image builder.

`build_node_image(packages)` builds a Docker image on top of a pinned official Node
LTS slim base with the given npm packages baked in, and returns its tag. The tag is
derived from a hash of the base image and the normalized packages, so the same inputs
always map to the same tag and the image is built only once.

TypeScript support is installed as a pinned dev dependency (`tsx`).

The build step needs the network (npm install). The run step does not.
"""
from __future__ import annotations

import hashlib
import subprocess

from .image import _image_exists, _normalize, _shell_quote

BASE_IMAGE_TAG = "node:20.18.0-slim"
BASE_IMAGE_DIGEST = "sha256:28fbbb764069c698ead61d6a739a7615e8f0e07a4b8fe1473ceca70c1c3d6aaa"
BASE_IMAGE = f"{BASE_IMAGE_TAG}@{BASE_IMAGE_DIGEST}"
TAG_REPOSITORY = "exhibit-a-sandbox-node"
BUILD_TIMEOUT = 900
INSTALL_DIR = "/opt/sandbox"
TSX_VERSION = "tsx@4.19.2"


def _normalize_packages(packages: list[str]) -> list[str]:
    """Normalize npm package specs and reject invalid specs.

    Reuses `_normalize` from `image.py` (strips whitespace, drops blanks,
    deduplicates, sorts, rejects newlines and leading dashes) and additionally
    rejects carriage returns, URL specifications, and git specifications.
    """
    cleaned = _normalize(packages)
    for pkg in cleaned:
        if "\r" in pkg or "\n" in pkg:
            raise ValueError(f"invalid package spec (newline): {pkg!r}")
        if (
            "://" in pkg
            or pkg.startswith(("git+", "git@", "github:", "file:"))
            or pkg.endswith(".git")
        ):
            raise ValueError(f"invalid package spec (URL or git spec): {pkg!r}")
    return cleaned


def image_tag(packages: list[str] | None = None) -> str:
    """Deterministic tag for the pinned Node base image plus npm packages."""
    pkgs = _normalize_packages(packages or [])
    payload = "\n".join([BASE_IMAGE, *pkgs])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"{TAG_REPOSITORY}:{digest}"


node_image_tag = image_tag


def _dockerfile(packages: list[str]) -> str:
    lines = [
        f"FROM {BASE_IMAGE}",
        "ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_AUDIT=false",
        f"WORKDIR {INSTALL_DIR}",
        f"RUN npm install --save-dev --save-exact --ignore-scripts {TSX_VERSION}",
    ]
    if packages:
        quoted = " ".join(_shell_quote(p) for p in packages)
        lines.append(f"RUN npm install --save-exact --ignore-scripts {quoted}")
    lines.extend([
        f'ENV PATH="{INSTALL_DIR}/node_modules/.bin:${{PATH}}"',
        f'ENV NODE_PATH="{INSTALL_DIR}/node_modules"',
    ])
    return "\n".join(lines) + "\n"


dockerfile = _dockerfile


def build_node_image(packages: list[str] | None = None) -> str:
    """Build (once) and return the tag of the pinned Node image with `packages` installed."""
    pkgs = _normalize_packages(packages or [])
    tag = image_tag(pkgs)
    if _image_exists(tag):
        return tag
    # The Dockerfile is sent on stdin with no build context, so no host files are exposed.
    result = subprocess.run(
        ["docker", "build", "--tag", tag, "-"],
        input=_dockerfile(pkgs),
        capture_output=True,
        text=True,
        timeout=BUILD_TIMEOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker build failed for {tag}: {result.stderr[-2000:]}")
    return tag


build_image = build_node_image

__all__ = [
    "BASE_IMAGE",
    "BASE_IMAGE_DIGEST",
    "BASE_IMAGE_TAG",
    "BUILD_TIMEOUT",
    "INSTALL_DIR",
    "TAG_REPOSITORY",
    "TSX_VERSION",
    "build_image",
    "build_node_image",
    "dockerfile",
    "image_tag",
    "node_image_tag",
    "normalize_packages",
]

normalize_packages = _normalize_packages
