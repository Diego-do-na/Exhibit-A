"""Multi-file export bundles kept below the exports directory."""

import json
import os

from ..storage.paths import below
from ..util import ids
from .formats import render_html, render_txt


class BundleWriter:
    """Assemble ``.bundle`` directories: one manifest plus one file per part."""

    def __init__(self, exports_dir):
        self.directory = os.path.abspath(exports_dir)
        os.makedirs(self.directory, exist_ok=True)

    def write_bundle(self, document, parts):
        """Store the rendered parts of ``document`` and return the bundle name."""
        name = ids.next_id("bundle")
        folder = below(self.directory, name)
        os.makedirs(folder, exist_ok=True)
        manifest = {"bundle": name, "document": document.id,
                    "title": document.title, "files": []}
        for kind in parts:
            if kind == "txt":
                payload = render_txt(document).encode("utf-8")
                filename = "document.txt"
            elif kind == "html":
                payload = render_html(document).encode("utf-8")
                filename = "document.html"
            else:
                continue
            with open(os.path.join(folder, filename), "wb") as handle:
                handle.write(payload)
            manifest["files"].append(filename)
        with open(os.path.join(folder, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
        return name

    def read_manifest(self, name):
        """The manifest of bundle ``name``, or None."""
        path = below(self.directory, name, "manifest.json")
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def bundles(self):
        """The names of the stored bundles, sorted."""
        return sorted(
            entry
            for entry in os.listdir(self.directory)
            if os.path.isdir(os.path.join(self.directory, entry))
        )
