"""JavaScript/TypeScript corpus: Express download-traversal and command-injection cases.

Four original cases (no third-party code vendored) modelling public advisory
classes for the Node oracle: an Express static-download path traversal
(``canary_read``) and a command injection through a shell-built string
(``canary_exec``), each in JavaScript and TypeScript. Every case ships
vulnerable, fixed and fixed_incomplete trees, a ``node:test`` baseline,
``profile.json``, ``suspicion.json``, ``README``, ``LICENSE.md`` and labelled
``node:test`` exploits.

Without Docker and without the oracle this file checks the manifests, the
``language`` field, the exploit labels, the pinned ``package.json``, that no
tree carries a hint comment, and that every exploit file is non-empty with
valid syntax. Judging the labelled exploits in the real Node sandbox is a
separate task (T136) that runs after the Node oracle (T125) exists.
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from bench.corpus import LANGUAGES, load_corpus
from exhibit_a.schemas import RepoProfile, Suspicion

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "bench" / "corpus"
CASES = {
    "express-download-traversal": CORPUS / "express-download-traversal",
    "express-download-traversal-ts": CORPUS / "express-download-traversal-ts",
    "express-command-injection": CORPUS / "express-command-injection",
    "express-command-injection-ts": CORPUS / "express-command-injection-ts",
}
EFFECT = {
    "express-download-traversal": "canary_read",
    "express-download-traversal-ts": "canary_read",
    "express-command-injection": "canary_exec",
    "express-command-injection-ts": "canary_exec",
}
VULN_CLASS = {
    "express-download-traversal": "path_traversal",
    "express-download-traversal-ts": "path_traversal",
    "express-command-injection": "command_injection",
    "express-command-injection-ts": "command_injection",
}
LANGUAGE = {
    "express-download-traversal": "javascript",
    "express-download-traversal-ts": "typescript",
    "express-command-injection": "javascript",
    "express-command-injection-ts": "typescript",
}
HELD_OUT = {
    "express-download-traversal": False,
    "express-download-traversal-ts": True,
    "express-command-injection": False,
    "express-command-injection-ts": True,
}
ENTRY_POINT = {
    "express-download-traversal": "downloadHandler",
    "express-download-traversal-ts": "downloadHandler",
    "express-command-injection": "lookupHandler",
    "express-command-injection-ts": "lookupHandler",
}
SOURCE = {
    "express-download-traversal": "app.js",
    "express-download-traversal-ts": "app.ts",
    "express-command-injection": "app.js",
    "express-command-injection-ts": "app.ts",
}
BASELINE = {
    "express-download-traversal": "baseline_test.js",
    "express-download-traversal-ts": "baseline_test.ts",
    "express-command-injection": "baseline_test.js",
    "express-command-injection-ts": "baseline_test.ts",
}
TREES = {
    "express-download-traversal": ("vulnerable", "fixed", "fixed_incomplete"),
    "express-download-traversal-ts": ("vulnerable", "fixed", "fixed_incomplete"),
    "express-command-injection": ("vulnerable", "fixed", "fixed_incomplete"),
    "express-command-injection-ts": ("vulnerable", "fixed", "fixed_incomplete"),
}
BYPASS = {
    "express-download-traversal": "exploit_true_percent_encoded_dotdot",
    "express-download-traversal-ts": "exploit_true_percent_encoded_dotdot",
    "express-command-injection": "exploit_true_newline",
    "express-command-injection-ts": "exploit_true_newline",
}
STOPPED_BY_INCOMPLETE = {
    "express-download-traversal": ("exploit_true_dotdot", "exploit_true_nested_dotdot"),
    "express-download-traversal-ts": ("exploit_true_dotdot", "exploit_true_nested_dotdot"),
    "express-command-injection": ("exploit_true_semicolon",),
    "express-command-injection-ts": ("exploit_true_semicolon",),
}
KNOWN_LABELS = {"true-exploit", "benign", "wrong-reason-failure", "cheating", "flaky", "mock-fabricated"}
HINT = re.compile(r"\b(BUG|FIXME|TODO|XXX|HACK)\b|#\s*Fix:|vulnerab", re.IGNORECASE)
#: Environment names a node:test file may mention. The canary entry itself
#: (EXHIBIT_A_CANARY) is never allowed: a real exploit reaches the canary from
#: the allowed directory, mirroring the Python oracle's static guard.
TEST_CONTRACT = frozenset({"EXHIBIT_A_ALLOWED_DIR", "EXHIBIT_A_CANARY_TOKEN"})
ENV_NAME = re.compile(r"EXHIBIT_A_[A-Z_]+")
EXACT_PIN = re.compile(r"^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$")
INSTALL_SCRIPTS = {
    "install", "preinstall", "postinstall", "prepublish", "prepublishOnly",
    "preprepare", "prepare", "postprepare",
}


def manifest(case_id):
    return json.loads((CASES[case_id] / "case.json").read_text(encoding="utf-8"))


def node():
    exe = shutil.which("node")
    if exe is None:
        pytest.skip("node is not installed: syntax check needs it")
    return exe


def node_check_supports_typescript(exe):
    """Whether ``node --check`` in this environment parses TypeScript syntax."""
    probe = Path.cwd() / "exhibit_a_ts_probe.ts"
    try:
        probe.write_text("const x: number = 1;\n", encoding="utf-8")
        proc = subprocess.run([exe, "--check", str(probe)], capture_output=True, text=True)
        return proc.returncode == 0
    finally:
        probe.unlink(missing_ok=True)


# -- corpus loader: the language field ---------------------------------------


def test_corpus_loader_accepts_the_language_field():
    cases = {case.id: case for case in load_corpus(CORPUS) if case.id in CASES}
    assert set(cases) == set(CASES)
    for case_id, case in cases.items():
        assert case.language == LANGUAGE[case_id], case_id
        assert case.language in LANGUAGES


def test_corpus_loader_leaves_existing_cases_on_python():
    for case in load_corpus(CORPUS):
        if case.id not in CASES:
            assert case.language == "python", case.id


@pytest.mark.parametrize("bad", ["ruby", "JavaScript", "", "py"])
def test_corpus_loader_rejects_unknown_languages(tmp_path, bad):
    payload = {
        "cases": [{"id": "x", "kind": "vulnerable", "commit": "", "repo": "", "ground_truth": []}],
        "run": {"effect": "canary_read", "tree": "vulnerable", "language": bad},
    }
    path = tmp_path / "case.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="language"):
        load_corpus(path)


# -- manifests, layout (no Docker, no oracle) ---------------------------------


@pytest.mark.parametrize("case_id", CASES)
def test_case_manifests_match_the_contracts(case_id):
    case_dir = CASES[case_id]
    spec = manifest(case_id)
    cases = load_corpus(case_dir / "case.json")
    assert [c.id for c in cases] == [case_id]
    case = cases[0]
    assert case.kind == "vulnerable"
    assert case.held_out is HELD_OUT[case_id]
    assert spec["held_out"] is HELD_OUT[case_id]
    assert case.language == LANGUAGE[case_id]
    assert spec["language"] == LANGUAGE[case_id]
    assert spec["run"]["language"] == LANGUAGE[case_id]
    assert case.effect == EFFECT[case_id]
    assert case.tree == "vulnerable"
    assert case.baseline_test == BASELINE[case_id]
    assert case.recording == ""
    assert case.requirements == ("express@4.18.2",)
    assert case.source_file == SOURCE[case_id]
    assert (case_dir / case.tree / case.source_file).is_file()
    assert case.ground_truth[0]["class"] == VULN_CLASS[case_id]
    assert (case_dir / case.ground_truth[0]["file"]).is_file()
    assert spec["synthetic"] is True
    assert spec["cwe"]["cwe_id"] and spec["cwe"]["cwe_name"]
    assert spec["run"]["entry_points"] == [ENTRY_POINT[case_id]]
    assert spec["run"]["oracle_entry_point"] == ENTRY_POINT[case_id]
    assert spec["real_world_analog"]["cve"]
    assert spec["real_world_analog"]["advisory"].startswith("https://")
    bypass = spec["run"]["bypass"]
    assert bypass["incomplete_fix"] == "fixed_incomplete"
    assert Path(bypass["exploit"]).stem == BYPASS[case_id]
    assert (case_dir / bypass["exploit"]).is_file()

    profile = RepoProfile.model_validate_json((case_dir / "profile.json").read_text(encoding="utf-8"))
    assert profile.language == LANGUAGE[case_id]
    assert profile.interpreter == "node 22"
    assert profile.dependency_manager == "npm"
    assert BASELINE[case_id] in profile.test_cmd
    assert profile.dependencies[0].name == "express"

    suspicion = Suspicion.model_validate_json((case_dir / "suspicion.json").read_text(encoding="utf-8"))
    assert suspicion.vuln_class == VULN_CLASS[case_id]
    assert suspicion.entry_point == ENTRY_POINT[case_id]
    lines = (case_dir / suspicion.location.file).read_text(encoding="utf-8").splitlines()
    assert 1 <= suspicion.location.line <= len(lines)

    for name in ("README.md", "LICENSE.md", "package.json", BASELINE[case_id]):
        assert (case_dir / name).is_file(), name


@pytest.mark.parametrize("case_id", CASES)
def test_manifest_lists_only_existing_exploits_with_known_labels(case_id):
    spec = manifest(case_id)
    listed = set()
    for entry in spec["run"]["exploits"]:
        assert (CASES[case_id] / entry["file"]).is_file(), entry["file"]
        assert entry["label"] in KNOWN_LABELS, entry["label"]
        listed.add(entry["file"])
    suffix = ".ts" if LANGUAGE[case_id] == "typescript" else ".js"
    on_disk = {f"exploits/{p.name}" for p in (CASES[case_id] / "exploits").glob(f"exploit_*{suffix}")}
    assert listed == on_disk, "every exploit on disk must be labelled in case.json and vice versa"
    assert {entry["label"] for entry in spec["run"]["exploits"]} == KNOWN_LABELS
    assert BYPASS[case_id] in {Path(entry["file"]).stem for entry in spec["run"]["exploits"]}


def _tree_files(tree_dir):
    return {
        p.relative_to(tree_dir).as_posix()
        for p in tree_dir.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }


@pytest.mark.parametrize("case_id", CASES)
def test_trees_differ_only_in_the_source_file(case_id):
    case_dir = CASES[case_id]
    source = manifest(case_id)["run"]["source_file"]
    vulnerable = case_dir / "vulnerable"
    expected = _tree_files(vulnerable)
    for tree in TREES[case_id]:
        if tree == "vulnerable":
            continue
        other = case_dir / tree
        found = _tree_files(other)
        assert found == expected, (case_id, tree, sorted(found ^ expected))
        changed = [
            rel for rel in sorted(expected)
            if (vulnerable / rel).read_bytes() != (other / rel).read_bytes()
        ]
        assert changed == [source], (tree, changed)


# -- package.json: exact pins, no install scripts ------------------------------


def _package(case_id):
    return json.loads((CASES[case_id] / "package.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case_id", CASES)
def test_package_json_pins_exact_versions_with_no_install_scripts(case_id):
    package = _package(case_id)
    deps = dict(package.get("dependencies", {}))
    assert deps, "the case must declare its runtime dependency"
    assert set(deps) | set(package.get("devDependencies", {})) == {"express"}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, spec in package.get(section, {}).items():
            assert EXACT_PIN.match(spec), f"{name}: {spec!r} is not an exact pin"
    for name in package.get("scripts", {}):
        assert name not in INSTALL_SCRIPTS, f"install script {name!r} is forbidden"
    assert deps["express"] in [req.split("@")[-1] for req in manifest(case_id)["run"]["requirements"]]


# -- no hint comments ----------------------------------------------------------


def comments_of(path):
    """Every ``//`` and ``/* */`` comment of a JavaScript/TypeScript file."""
    source = path.read_text(encoding="utf-8")
    found = []
    for match in re.finditer(r"//[^\n]*|/\*.*?\*/", source, re.DOTALL):
        found.append(match.group(0))
    return found


def tree_sources():
    return sorted(
        path
        for case_id, case in CASES.items()
        for tree in TREES[case_id]
        for path in (case / tree).rglob(f"*.{('ts' if LANGUAGE[case_id] == 'typescript' else 'js')}")
    )


def test_the_trees_are_not_empty_and_the_scan_sees_comments(tmp_path):
    assert len(tree_sources()) == 12
    probe = tmp_path / "probe.js"
    probe.write_text("// note\nconst x = 1; // trailing\n", encoding="utf-8")
    assert sorted(comments_of(probe)) == ["// note", "// trailing"]
    probe.write_text("// BUG: here\n", encoding="utf-8")
    assert HINT.search(comments_of(probe)[0])


def test_trees_carry_no_hint_comments():
    """The bug is described only in the case README: no BUG/FIXME/TODO/XXX/HACK
    word or vulnerability hint in any comment of any tree."""
    for path in tree_sources():
        for comment in comments_of(path):
            match = HINT.search(comment)
            assert not match, f"{path.relative_to(CORPUS)}: {match.group(0)!r} in {comment!r}"


# -- exploits: non-empty, guarded env names, valid syntax ----------------------


def exploit_files(suffix=None):
    rows = []
    for case_id in CASES:
        ext = ".ts" if LANGUAGE[case_id] == "typescript" else ".js"
        if suffix is not None and ext != suffix:
            continue
        for path in sorted((CASES[case_id] / "exploits").glob(f"exploit_*{ext}")):
            rows.append((case_id, path))
    return rows


def test_exploit_files_are_non_empty_and_stay_inside_the_test_contract():
    rows = exploit_files()
    assert len(rows) == 34
    for case_id, path in rows:
        source = path.read_text(encoding="utf-8")
        assert source.strip(), f"{path} is empty"
        assert "node:test" in source, f"{path} must be a node:test file"
        for name in set(ENV_NAME.findall(source)):
            assert name in TEST_CONTRACT, f"{path}: {name} is outside the test contract"


def test_javascript_exploits_and_baselines_are_valid_syntax():
    exe = node()
    failures = []
    for case_id, path in exploit_files(".js"):
        proc = subprocess.run([exe, "--check", str(path)], capture_output=True, text=True)
        if proc.returncode != 0:
            failures.append(f"{path}: {proc.stderr.strip().splitlines()[-1]}")
    for case_id in CASES:
        if LANGUAGE[case_id] != "javascript":
            continue
        baseline = CASES[case_id] / BASELINE[case_id]
        proc = subprocess.run([exe, "--check", str(baseline)], capture_output=True, text=True)
        if proc.returncode != 0:
            failures.append(f"{baseline}: {proc.stderr.strip().splitlines()[-1]}")
    assert not failures, "\n".join(failures)


def test_typescript_exploits_and_baselines_are_valid_syntax():
    exe = node()
    if not node_check_supports_typescript(exe):
        pytest.skip(
            "node --check in this environment parses .ts files as plain JavaScript "
            "(no type stripping on the check path) and the Node sandbox image is "
            "unavailable (no Docker), so TypeScript syntax cannot be machine-checked "
            "here; judging the .ts exploits in the real Node sandbox is T136"
        )
    failures = []
    for case_id, path in exploit_files(".ts"):
        proc = subprocess.run([exe, "--check", str(path)], capture_output=True, text=True)
        if proc.returncode != 0:
            failures.append(f"{path}: {proc.stderr.strip().splitlines()[-1]}")
    for case_id in CASES:
        if LANGUAGE[case_id] != "typescript":
            continue
        baseline = CASES[case_id] / BASELINE[case_id]
        proc = subprocess.run([exe, "--check", str(baseline)], capture_output=True, text=True)
        if proc.returncode != 0:
            failures.append(f"{baseline}: {proc.stderr.strip().splitlines()[-1]}")
    assert not failures, "\n".join(failures)
