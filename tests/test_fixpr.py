from pathlib import Path

from exhibit_a.ci.fixpr import build_fix_branch_payload, build_review_comments


def _run_dir(tmp_path: Path, patch: str, test: str = "def test_proof():\n    assert True\n") -> Path:
    package = tmp_path / "packages" / "finding-1"
    package.mkdir(parents=True)
    (package / "fix.patch").write_text(patch, encoding="utf-8")
    (package / "test_exploit.py").write_text(test, encoding="utf-8")
    return tmp_path


def test_fix_hunk_maps_to_suggestion_on_changed_pr_lines(tmp_path):
    run = _run_dir(
        tmp_path,
        "--- a/app.py\n+++ b/app.py\n@@ -2,2 +2,2 @@\n-old()\n+new()\n",
    )
    diff = "diff --git a/app.py b/app.py\n@@ -2,1 +2,1 @@\n-old()\n+new()\n"

    comments = build_review_comments(run, diff)

    assert comments == [{
        "body": "Apply the verified fix:\n\n```suggestion\nnew()\n```",
        "path": "app.py",
        "line": 2,
        "side": "RIGHT",
    }]


def test_fix_hunk_outside_pr_diff_is_an_ordinary_comment(tmp_path):
    run = _run_dir(
        tmp_path,
        "--- a/app.py\n+++ b/app.py\n@@ -8,1 +8,1 @@\n-old()\n+new()\n",
    )

    comments = build_review_comments(run, "diff --git a/other.py b/other.py\n")

    assert "suggestion" not in comments[0]["body"]
    assert comments[0]["path"] == "app.py"
    assert "outside the PR diff" in comments[0]["body"]


def test_fix_branch_contains_patch_and_exact_proof_test(tmp_path):
    test = "def test_proof():\n    assert True\n"
    run = _run_dir(tmp_path, "--- a/app.py\n+++ b/app.py\n", test)

    payload = build_fix_branch_payload(run)

    assert payload["patch"].startswith("--- a/app.py")
    assert payload["test_path"] == "tests/exhibit_a/test_finding_1.py"
    assert payload["test"] == test
    assert payload["files"][1] == {"path": payload["test_path"], "content": test}
