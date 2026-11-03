"""Build helper: copy ``web/dashboard`` into the wheel as package data.

The UI lives outside ``src/``, so a default setuptools wheel would omit it.
``build_py`` copies the tree into ``exhibit_a/dashboard/web`` after the
package is assembled. An installed copy can then serve the dashboard without
a source checkout. ``MANIFEST.in`` grafts the same tree into the sdist so
isolated builds still see it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _BuildPy

ROOT = Path(__file__).resolve().parent
WEB_SRC = ROOT / "web" / "dashboard"
WEB_REL = Path("exhibit_a") / "dashboard" / "web"


def _copy_web(destination: Path) -> None:
    if not WEB_SRC.is_dir():
        raise FileNotFoundError(f"dashboard UI missing: {WEB_SRC}")
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        WEB_SRC,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
    )
    if not (destination / "index.html").is_file():
        raise FileNotFoundError(f"dashboard UI missing index.html under {destination}")


class build_py(_BuildPy):
    def run(self) -> None:
        super().run()
        _copy_web(Path(self.build_lib) / WEB_REL)


setup(cmdclass={"build_py": build_py})
