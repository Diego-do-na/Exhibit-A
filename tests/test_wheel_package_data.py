"""The installed wheel must ship every non-.py file the runtime opens."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from exhibit_a.dashboard.server import STATIC_FILES, default_web_dir

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
    "exhibit_a/cli/logo.txt",
)

DASHBOARD_UI_PREFIX = "exhibit_a/dashboard/web/"


def _dashboard_source_files() -> list[Path]:
    web = REPO / "web" / "dashboard"
    return sorted(
        path for path in web.rglob("*")
        if path.is_file() and path.name != ".DS_Store"
    )


def _dashboard_wheel_paths() -> list[str]:
    web = REPO / "web" / "dashboard"
    return [
        DASHBOARD_UI_PREFIX + path.relative_to(web).as_posix()
        for path in _dashboard_source_files()
    ]


@pytest.fixture(scope="module")
def wheel_names(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    tmp_path = tmp_path_factory.mktemp("wheel")
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(REPO), "--no-deps", "-w", str(tmp_path)],
        check=True,
        cwd=tmp_path,
    )
    wheels = list(tmp_path.glob("exhibit_a-*.whl"))
    assert len(wheels) == 1, wheels
    return zipfile.ZipFile(wheels[0]).namelist()


def test_wheel_contains_runtime_data_files(wheel_names: list[str]) -> None:
    missing = [path for path in RUNTIME_DATA_FILES if path not in wheel_names]
    assert missing == [], f"wheel omitted runtime data: {missing}"


def test_wheel_contains_dashboard_ui(wheel_names: list[str]) -> None:
    expected = _dashboard_wheel_paths()
    assert expected, "web/dashboard is empty; the wheel has nothing to ship"
    names = set(wheel_names)
    missing = [path for path in expected if path not in names]
    assert missing == [], f"wheel omitted dashboard UI: {missing[:12]}"
    for name in STATIC_FILES:
        assert DASHBOARD_UI_PREFIX + name in names, name
    assert any(path.startswith(DASHBOARD_UI_PREFIX + "views/") for path in names)
    assert any(path.startswith(DASHBOARD_UI_PREFIX + "fonts/") and path.endswith(".woff2") for path in names)


def test_default_web_dir_points_at_the_ui() -> None:
    web = default_web_dir()
    assert (web / "index.html").is_file()
    assert (web / "dashboard.css").is_file()
    assert (web / "dc-lite.js").is_file()
    for name in STATIC_FILES:
        assert (web / name).is_file(), name
