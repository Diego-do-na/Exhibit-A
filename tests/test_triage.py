"""Tests for PR triage (exhibit_a.triage): every rule plus adversarial inputs."""

from __future__ import annotations

import pytest

from exhibit_a import triage
from exhibit_a.ci import gate
from exhibit_a.triage import Decision, Risk, assess
from exhibit_a.triage.diffparse import MAX_DIFF_CHARS, MAX_FILES, parse_diff


def mod(path: str, added: str = "x = 1") -> str:
    return (
        f"diff --git a/{path} b/{path}\nindex 1111111..2222222 100644\n"
        f"--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,1 @@\n-old\n+{added}\n"
    )


def check(paths, diff, level, decision):
    result = assess(paths, diff)
    assert (result.level, result.decision) == (level, decision), result.reasons
    return result


HIGH = [
    ".github/workflows/ci.yml",
    ".github/actions/x/action.yml",
    "action.yml",
    "setup.py",
    "pkg/setup.cfg",
    "conftest.py",
    "tests/sub/conftest.py",
    "evil.pth",
    "src/sitecustomize.py",
    "usercustomize.py",
    "Dockerfile",
    "docker/Dockerfile.dev",
    "docker-compose.yml",
    "install.sh",
    "scripts/postinstall.js",
    "Makefile",
    "lib/native.so",
    "assets/tool.exe",
    "ARCHIVE.ZIP",
]


@pytest.mark.parametrize("path", HIGH)
def test_high_rules_by_path(path):
    check([path], mod(path), Risk.HIGH, Decision.REFUSE)


def test_high_rule_matches_case_insensitively_and_with_dot_slash():
    check(["./.GitHub/Workflows/CI.yml"], None, Risk.HIGH, Decision.REFUSE)
    check(["SETUP.PY"], None, Risk.HIGH, Decision.REFUSE)


@pytest.mark.parametrize(
    "edit",
    [
        "[build-system]\n+requires = ['evil']",
        "build-backend = 'evil.backend'",
        "backend-path = ['.']",
        "[tool.hatch.build.hooks.custom]",
        "requires = ['setuptools']",
        "cmdclass = {}",
    ],
)
def test_pyproject_build_backend_or_hooks_is_high(edit):
    diff = mod("pyproject.toml", edit)
    check(["pyproject.toml"], diff, Risk.HIGH, Decision.REFUSE)


def test_pyproject_dependency_edit_is_medium():
    diff = mod("pyproject.toml", '"requests>=2.0",')
    check(["pyproject.toml"], diff, Risk.MEDIUM, Decision.NEEDS_APPROVAL)


def test_pyproject_without_diff_or_when_added_fails_closed():
    check(["pyproject.toml"], None, Risk.HIGH, Decision.REFUSE)
    added = (
        "diff --git a/pyproject.toml b/pyproject.toml\nnew file mode 100644\n"
        "--- /dev/null\n+++ b/pyproject.toml\n@@ -0,0 +1,1 @@\n+[project]\n"
    )
    check(["pyproject.toml"], added, Risk.HIGH, Decision.REFUSE)


def test_binary_markers_are_high():
    diff = "diff --git a/img/logo.dat b/img/logo.dat\nindex 1..2 100644\nBinary files a/img/logo.dat and b/img/logo.dat differ\n"
    result = check(["img/logo.dat"], diff, Risk.HIGH, Decision.REFUSE)
    assert any("binary" in r for r in result.reasons)
    patch = "diff --git a/d.dat b/d.dat\nGIT binary patch\nliteral 3\nKcmZQz\n\nliteral 0\nHcmV?d00001\n"
    check(["d.dat"], patch, Risk.HIGH, Decision.REFUSE)


def test_nul_byte_in_diff_is_high():
    check(["a.py"], mod("a.py", "x\x00y"), Risk.HIGH, Decision.REFUSE)


def test_symlink_is_high():
    diff = "diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1,1 @@\n+/etc/passwd\n"
    check(["link"], diff, Risk.HIGH, Decision.REFUSE)


@pytest.mark.parametrize(
    "path",
    ["requirements.txt", "requirements-dev.txt", "poetry.lock", "package.json", "uv.lock", "constraints.txt"],
)
def test_dependency_files_are_medium(path):
    check([path], mod(path), Risk.MEDIUM, Decision.NEEDS_APPROVAL)


@pytest.mark.parametrize(
    "path",
    [
        "tests/fixtures/data.json",
        "tests/helpers/db.py",
        "tests/__init__.py",
        "tests/unit/support/factory.py",
        "tox.ini",
        "pytest.ini",
        "noxfile.py",
    ],
)
def test_test_infrastructure_is_medium(path):
    check([path], mod(path), Risk.MEDIUM, Decision.NEEDS_APPROVAL)


def test_new_executable_is_medium():
    diff = "diff --git a/tool b/tool\nnew file mode 100755\n--- /dev/null\n+++ b/tool\n@@ -0,0 +1,1 @@\n+x\n"
    check(["tool"], diff, Risk.MEDIUM, Decision.NEEDS_APPROVAL)


@pytest.mark.parametrize(
    "path",
    ["README.md", "docs/guide.rst", "LICENSE", "src/app/views.py", "tests/test_views.py", "src/exhibit_a/install.py"],
)
def test_docs_and_plain_source_are_low(path):
    check([path], mod(path), Risk.LOW, Decision.RUN)


def test_empty_change_is_low():
    result = check([], "", Risk.LOW, Decision.RUN)
    assert result.reasons == ("low: nothing to analyse",)
    check(None, None, Risk.LOW, Decision.RUN)


def test_highest_level_wins():
    files = ["README.md", "requirements.txt", "conftest.py"]
    diff = "".join(mod(p) for p in files)
    check(files, diff, Risk.HIGH, Decision.REFUSE)


def test_rename_classifies_old_and_new_path():
    diff = (
        "diff --git a/docs/notes.md b/conftest.py\nsimilarity index 90%\n"
        "rename from docs/notes.md\nrename to conftest.py\n"
    )
    check(["conftest.py"], diff, Risk.HIGH, Decision.REFUSE)
    out = (
        "diff --git a/conftest.py b/docs/old.md\nsimilarity index 90%\n"
        "rename from conftest.py\nrename to docs/old.md\n"
    )
    check(["docs/old.md"], out, Risk.HIGH, Decision.REFUSE)


def test_rename_with_spaces_in_path():
    diff = (
        "diff --git a/my docs/a.md b/my docs/b.md\nsimilarity index 100%\n"
        "rename from my docs/a.md\nrename to my docs/b.md\n"
    )
    check(["my docs/b.md"], diff, Risk.LOW, Decision.RUN)


def test_deletion_of_sensitive_file_is_still_high():
    diff = (
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\ndeleted file mode 100644\n"
        "--- a/.github/workflows/ci.yml\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-on: push\n"
    )
    check([".github/workflows/ci.yml"], diff, Risk.HIGH, Decision.REFUSE)


def test_quoted_path_is_decoded():
    diff = 'diff --git "a/s\\303\\251t\\".py" "b/s\\303\\251t\\".py"\n--- "a/s\\303\\251t\\".py"\n+++ "b/s\\303\\251t\\".py"\n@@ -1 +1 @@\n-a\n+b\n'
    parsed = parse_diff(diff)
    assert parsed.files[0].paths == ['sét".py']


@pytest.mark.parametrize(
    "path", ["../../etc/passwd", "src/../../x.py", "/etc/cron.d/x", "C:/Windows/x.py", "a\nb.py", "a\x00b.py", "x" * 2000]
)
def test_unsafe_paths_are_high(path):
    result = check([path], None, Risk.HIGH, Decision.REFUSE)
    assert "\n" not in "".join(result.reasons)


def test_traversal_hidden_in_diff_header_is_caught():
    diff = mod("docs/../.github/workflows/x.yml")
    check(["docs/x.md"], diff, Risk.HIGH, Decision.REFUSE)


def test_diff_file_missing_from_file_list_is_high():
    result = check(["README.md"], mod("README.md") + mod("src/a.py"), Risk.HIGH, Decision.REFUSE)
    assert any("missing from changed-file list" in r for r in result.reasons)


def test_miscounted_hunk_cannot_hide_a_later_file():
    liar = (
        "diff --git a/docs/a.md b/docs/a.md\n--- a/docs/a.md\n+++ b/docs/a.md\n@@ -1,500 +1,500 @@\n-x\n+y\n"
        + mod(".github/workflows/ci.yml")
    )
    check(["docs/a.md", ".github/workflows/ci.yml"], liar, Risk.HIGH, Decision.REFUSE)


def test_huge_diff_is_capped_and_high():
    big = mod("README.md", "a" * (MAX_DIFF_CHARS + 10))
    result = check(["README.md"], big, Risk.HIGH, Decision.REFUSE)
    assert any("exceeds" in r for r in result.reasons)
    check(["README.md"], big.encode(), Risk.HIGH, Decision.REFUSE)


def test_too_many_files_is_high():
    names = [f"src/m{i}.py" for i in range(MAX_FILES + 1)]
    check(names, "".join(mod(n) for n in names), Risk.HIGH, Decision.REFUSE)
    check(names, None, Risk.HIGH, Decision.REFUSE)


def test_reasons_are_bounded():
    names = [f"../x{i}" for i in range(MAX_FILES)]
    assert len(assess(names, None).reasons) <= 51


def test_diff_content_is_never_executed_or_trusted():
    payload = "$(touch /tmp/pwned); __import__('os').system('true')"
    result = check(["src/a.py"], mod("src/a.py", payload), Risk.LOW, Decision.RUN)
    assert payload not in "".join(result.reasons)


def test_invalid_utf8_bytes_diff():
    check(["a.py"], mod("a.py").encode() + b"\xff\xfe", Risk.LOW, Decision.RUN)


def test_decisions_are_deterministic_and_order_independent():
    files = ["README.md", "requirements.txt", "src/a.py", "tests/fixtures/x.json"]
    diff = "".join(mod(p) for p in files)
    first = assess(files, diff)
    assert assess(files, diff) == first
    assert assess(list(reversed(files)), "".join(mod(p) for p in reversed(files))) == first


def test_to_dict_shape():
    assert assess(["README.md"], None).to_dict() == {
        "level": "low", "decision": "run", "reasons": ["low: README.md: documentation"],
    }


def test_level_enum_is_the_gate_enum_and_gate_rules_exist():
    assert triage.Risk is gate.Risk
    reasons = {rule.reason for rule in gate.RULES}
    assert {
        "CI workflow or action definition",
        "container definition",
        "dependency manifest or lock file",
        "documentation",
    } <= reasons
