"""Tests for the live PR demo kit: the demo app, its two patches and scripts/action-demo.sh.

They need no Docker, no network and no secrets. The patches are applied to temporary copies
of the app, never to the working tree.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_REL = Path("examples/action-demo")
APP = REPO_ROOT / APP_REL
SCRIPT = REPO_ROOT / "scripts" / "action-demo.sh"
PATCHES = {
    "traversal": APP / "patches" / "01-path-traversal.patch",
    "refactor": APP / "patches" / "02-harmless-refactor.patch",
}
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, check=True,
                          capture_output=True, text=True)
    return done.stdout.strip()


def _copy_app(dest: Path) -> Path:
    shutil.copytree(APP, dest / APP_REL, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return dest / APP_REL


def _baseline(app_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(app_dir)],
                          cwd=app_dir, capture_output=True, text=True)


def _escape_probe(app_dir: Path, tmp: Path) -> str:
    """Request a file outside the shelf through the app in a fresh interpreter."""
    shelf = tmp / "shelf"
    shelf.mkdir(exist_ok=True)
    (tmp / "outside.txt").write_text("CANARY", encoding="utf-8")
    code = (
        "import sys; from pamphlets import create_app; "
        "print(create_app(sys.argv[1]).handle_request('GET', '/pamphlet', {'name': '../outside.txt'}).body)"
    )
    done = subprocess.run([sys.executable, "-c", code, str(shelf)], cwd=app_dir,
                          capture_output=True, text=True, check=True)
    return done.stdout.strip()


def test_baseline_passes_on_main(tmp_path: Path) -> None:
    done = _baseline(_copy_app(tmp_path))
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("name", sorted(PATCHES))
def test_patches_apply_cleanly_from_the_repo_root(name: str, tmp_path: Path) -> None:
    _copy_app(tmp_path)
    _git(tmp_path, "init", "-q")
    done = subprocess.run(["git", "apply", "--check", "--whitespace=error", str(PATCHES[name])],
                          cwd=tmp_path, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("name", sorted(PATCHES))
def test_patches_touch_only_the_demo_source(name: str) -> None:
    text = PATCHES[name].read_text(encoding="utf-8")
    files = [line.split(" b/", 1)[1] for line in text.splitlines() if line.startswith("diff --git ")]
    assert files == [f"{APP_REL}/pamphlets.py"]


def test_main_confines_requests_to_the_shelf(tmp_path: Path) -> None:
    app_dir = _copy_app(tmp_path)
    assert _escape_probe(app_dir, tmp_path) == "not found"


def test_traversal_patch_introduces_a_real_escape_and_keeps_the_baseline_green(tmp_path: Path) -> None:
    app_dir = _copy_app(tmp_path)
    subprocess.run(["git", "apply", str(PATCHES["traversal"])], cwd=tmp_path, check=True)
    assert _escape_probe(app_dir, tmp_path) == "CANARY"
    done = _baseline(app_dir)
    assert done.returncode == 0, done.stdout + done.stderr


def test_refactor_patch_changes_the_code_but_not_the_behaviour(tmp_path: Path) -> None:
    app_dir = _copy_app(tmp_path)
    before = (app_dir / "pamphlets.py").read_text(encoding="utf-8")
    subprocess.run(["git", "apply", str(PATCHES["refactor"])], cwd=tmp_path, check=True)
    assert (app_dir / "pamphlets.py").read_text(encoding="utf-8") != before
    assert _escape_probe(app_dir, tmp_path) == "not found"
    done = _baseline(app_dir)
    assert done.returncode == 0, done.stdout + done.stderr


def test_demo_files_carry_no_secret_shaped_values() -> None:
    names = [SCRIPT, *PATCHES.values(), *APP.glob("*.py"), APP / "README.md",
             REPO_ROOT / "docs" / "ci" / "live-pr-demo.md"]
    for path in names:
        text = path.read_text(encoding="utf-8")
        for marker in ("ghp_", "github_pat_", "sk-", "BEGIN PRIVATE KEY", "Bearer "):
            assert marker not in text, f"{marker!r} in {path}"


# -- scripts/action-demo.sh ---------------------------------------------------------


def _demo_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    shutil.copytree(APP, repo / APP_REL, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    (repo / "scripts").mkdir()
    shutil.copy(SCRIPT, repo / "scripts" / "action-demo.sh")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "main")
    return repo


def _run_script(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", "scripts/action-demo.sh"], cwd=repo, env=GIT_ENV,
                          capture_output=True, text=True)


def test_script_syntax_and_no_push_commands_are_executed() -> None:
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0
    for line in SCRIPT.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        # Pushes and PR creation may only appear inside the printed heredoc (indented by two).
        if line.startswith("  git push") or line.startswith("  gh pr create"):
            continue
        assert not stripped.startswith(("git push", "gh ")), line


def test_script_creates_both_branches_and_prints_the_commands(tmp_path: Path) -> None:
    repo = _demo_repo(tmp_path)
    head_before = _git(repo, "rev-parse", "main")
    done = _run_script(repo)
    assert done.returncode == 0, done.stderr
    assert "gh pr create --base main --head demo/path-traversal" in done.stdout
    assert "gh pr create --base main --head demo/harmless-refactor" in done.stdout
    assert "git push -u origin demo/path-traversal" in done.stdout
    assert _git(repo, "rev-parse", "main") == head_before
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert _git(repo, "status", "--porcelain") == ""
    vulnerable = _git(repo, "show", f"demo/path-traversal:{APP_REL}/pamphlets.py")
    assert "commonpath" not in vulnerable
    refactored = _git(repo, "show", f"demo/harmless-refactor:{APP_REL}/pamphlets.py")
    assert "commonpath" in refactored and "_not_found" in refactored
    assert _git(repo, "remote") == ""  # nothing to push to, and nothing was configured


def test_script_refuses_to_overwrite_existing_branches(tmp_path: Path) -> None:
    repo = _demo_repo(tmp_path)
    assert _run_script(repo).returncode == 0
    again = _run_script(repo)
    assert again.returncode != 0
    assert "already exists" in again.stderr


def test_script_refuses_a_dirty_tree(tmp_path: Path) -> None:
    repo = _demo_repo(tmp_path)
    (repo / "scratch.txt").write_text("x", encoding="utf-8")
    done = _run_script(repo)
    assert done.returncode != 0
    assert "not clean" in done.stderr
