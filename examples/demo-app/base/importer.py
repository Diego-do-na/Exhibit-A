"""Skin-pack importer for a tiny static-site server (DEMO FIXTURE, safe base version).

This directory is a demonstration fixture for Exhibit A's demo kit
(see ``examples/demo-app/README.md``). It is original code written for the
demo: a realistic archive-import endpoint where an uploaded skin pack (a JSON
manifest of ``{"path": ..., "content": ...}`` entries) is installed under the
site's ``skins/`` directory.

This base version confines every member path to the destination directory, so
``..`` segments and absolute paths are rejected before anything is written.
"""

from __future__ import annotations

import json
import os


class SkinPackError(ValueError):
    """Raised when an uploaded skin pack is malformed or escapes its directory."""


def parse_pack(blob: bytes) -> list[dict[str, str]]:
    """Decode an uploaded pack into ``{"path", "content"}`` entries."""
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SkinPackError(f"pack is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise SkinPackError("pack must be an object with an 'entries' list")
    entries: list[dict[str, str]] = []
    for raw in payload["entries"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
            raise SkinPackError("every entry needs a string 'path'")
        if not isinstance(raw.get("content"), str):
            raise SkinPackError("every entry needs a string 'content'")
        entries.append({"path": raw["path"], "content": raw["content"]})
    return entries


def make_pack(entries: list[tuple[str, str]]) -> bytes:
    """Encode ``(path, content)`` pairs into an uploadable pack blob."""
    payload = {"entries": [{"path": path, "content": content} for path, content in entries]}
    return json.dumps(payload).encode("utf-8")


class SkinInstaller:
    """Installs skin-pack entries under one skins directory."""

    def __init__(self, skins_dir: str) -> None:
        self.skins_dir = skins_dir

    def _target(self, name: str) -> str:
        # Safe base: resolve the member path and require it to stay inside the
        # skins directory. Both ".." traversal and absolute paths are rejected.
        root = os.path.realpath(self.skins_dir)
        target = os.path.realpath(os.path.join(root, name))
        if target != root and not target.startswith(root + os.sep):
            raise SkinPackError(f"skin entry escapes skins directory: {name!r}")
        return target

    def install_entry(self, entry: dict[str, str]) -> str:
        """Sink: write one skin file to its confined path."""
        target = self._target(entry["path"])
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(entry["content"])
        return target

    def install_all(self, entries: list[dict[str, str]]) -> list[str]:
        """Install every entry; entries a safer policy rejects are skipped."""
        installed: list[str] = []
        for entry in entries:
            try:
                installed.append(self.install_entry(entry))
            except SkinPackError:
                continue
        return installed


class SiteApp:
    """Small app: POSTing a skin pack installs it into the skins directory."""

    def __init__(self, skins_dir: str) -> None:
        self.installer = SkinInstaller(skins_dir)

    def handle_request(self, method: str, blob: bytes | None = None) -> list[str] | str:
        """Entry point: handle an upload request carrying a skin-pack ``blob``."""
        if method != "POST":
            return "method not allowed"
        if blob is None:
            raise SkinPackError("POST needs a pack body")
        return self.installer.install_all(parse_pack(blob))


def create_app(skins_dir: str) -> SiteApp:
    """Build an app that installs skin packs confined to ``skins_dir``."""
    return SiteApp(skins_dir)
