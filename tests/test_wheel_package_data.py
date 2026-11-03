"""The installed wheel must ship every non-.py file the runtime opens."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Paths inside the wheel (POSIX). These are the files Path(__file__) / open()
# load at runtime; a setuptools wheel omits them unless package-data lists them.
RUNTIME_DATA_FILES = (
    "exhibit_a/sandbox/seccomp.json",
    "exhibit_a/sandbox/witness/supervisor.py",
    "exhibit_a/graph/js/graph_builder.js",
    "exhibit_a/oracle/js/oracle.cjs",
    "exhibit_a/advisory/symbols.json",
    "exhibit_a/schemas/run_index.schema.json",
    "exhibit_a/schemas/advisory_match.schema.json",
)


def test_wheel_contains_runtime_data_files(tmp_path: Path) -> None:
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(REPO), "--no-deps", "-w", str(tmp_path)],
        check=True,
        cwd=tmp_path,
    )
    wheels = list(tmp_path.glob("exhibit_a-*.whl"))
    assert len(wheels) == 1, wheels
    names = zipfile.ZipFile(wheels[0]).namelist()
    missing = [path for path in RUNTIME_DATA_FILES if path not in names]
    assert missing == [], f"wheel omitted runtime data: {missing}"
