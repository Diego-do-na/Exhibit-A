import pytest

from exhibit_a.advisory.deps import (
    PinnedDependency,
    Unsupported,
    normalize_name,
    parse_pyproject,
    parse_requirement,
    parse_requirements,
)


def test_normalize_name():
    assert normalize_name("Foo_Bar.baz--Qux") == "foo-bar-baz-qux"


def test_requirements_pins_and_unsupported():
    text = """
# comment line
Fictional_WebKit==2.3.0  # trailing comment
fictional-yamlish[fast, cli] == 1.4.2 ; python_version >= "3.11"
fictional-exact===1.0.0-weird
fictional-hashed==1.0 \\
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000
fictional-range>=1.0
fictional-wild==1.*
fictional-multi>=1.0,<2
fictional-bare
fictional-url @ https://files.example.invalid/pkg.whl
-r other.txt
-c constraints.txt
-e ./local
--index-url https://index.example.invalid/simple
git+https://code.example.invalid/x.git#egg=x
./vendor/pkg
not a requirement !!!
"""
    result = parse_requirements(text, "requirements.txt")
    pins = {d.name: d for d in result.dependencies}
    assert set(pins) == {"fictional-webkit", "fictional-yamlish", "fictional-exact",
                         "fictional-hashed"}
    assert pins["fictional-webkit"] == PinnedDependency(
        "fictional-webkit", "2.3.0", "requirements.txt:3")
    yam = pins["fictional-yamlish"]
    assert yam.version == "1.4.2"
    assert yam.extras == ("fast", "cli")
    assert yam.marker == 'python_version >= "3.11"'
    assert pins["fictional-exact"].version == "1.0.0-weird"
    assert pins["fictional-hashed"].source == "requirements.txt:6"
    reasons = [u.reason for u in result.unsupported]
    assert len(result.unsupported) == 12
    assert all(isinstance(u, Unsupported) for u in result.unsupported)
    assert any("not an exact pin" in r for r in reasons)
    assert any("wildcard" in r for r in reasons)
    assert any("unpinned" in r for r in reasons)
    assert any("direct URL" in r for r in reasons)
    assert any("include/constraint" in r for r in reasons)
    assert any("editable" in r for r in reasons)
    assert any("pip option" in r for r in reasons)
    assert any("URL, VCS or local path" in r for r in reasons)


def test_invalid_version_in_double_equals_is_unsupported():
    result = parse_requirement("pkg==not.a.version!", "x")
    assert isinstance(result, Unsupported)
    assert "invalid PEP 440" in result.reason


def test_parenthesized_legacy_spec():
    result = parse_requirement("pkg (==1.2)", "x")
    assert isinstance(result, PinnedDependency) and result.version == "1.2"


def test_pyproject_pep621_groups_and_poetry():
    text = """
[project]
name = "demo"
dependencies = ["fictional-webkit==2.3.0", "fictional-range>=1"]
[project.optional-dependencies]
extra = ["fictional-tiny==0.1.0"]

[dependency-groups]
dev = ["fictional-dev==9.9", {include-group = "other"}]

[tool.poetry.dependencies]
python = "^3.11"
fictional-poetry = "1.2.3"
fictional-poetry-eq = "==1.2.4"
fictional-caret = "^1.2"
fictional-table = {version = "2.0.0", extras = ["x"]}
fictional-git = {git = "https://code.example.invalid/x.git"}

[tool.poetry.group.test.dependencies]
fictional-test = "0.5"
"""
    result = parse_pyproject(text)
    pins = {d.name: d for d in result.dependencies}
    assert {n: d.version for n, d in pins.items()} == {
        "fictional-webkit": "2.3.0",
        "fictional-tiny": "0.1.0",
        "fictional-dev": "9.9",
        "fictional-poetry": "1.2.3",
        "fictional-poetry-eq": "1.2.4",
        "fictional-table": "2.0.0",
        "fictional-test": "0.5",
    }
    assert pins["fictional-tiny"].source == "pyproject.toml:project.optional-dependencies.extra"
    assert pins["fictional-test"].source == "pyproject.toml:tool.poetry.group.test.dependencies"
    texts = " | ".join(f"{u.text} -> {u.reason}" for u in result.unsupported)
    assert "fictional-range" in texts
    assert "include-group" in texts
    assert "fictional-caret" in texts and "poetry range" in texts
    assert "fictional-git" in texts and "path/git/url" in texts
    assert "python" not in [d.name for d in result.dependencies]


def test_pyproject_dynamic_dependencies_reported():
    result = parse_pyproject('[project]\nname = "x"\ndynamic = ["dependencies"]\n')
    assert result.dependencies == []
    assert result.unsupported[0].reason == "dynamic dependencies are not resolved"


def test_pyproject_invalid_toml_raises():
    import tomllib

    with pytest.raises(tomllib.TOMLDecodeError):
        parse_pyproject("[project\n")


def test_repo_pyproject_has_no_exact_pins():
    # Exhibit A's own pyproject only uses ranges; all of them are reported as unsupported.
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    result = parse_pyproject(text)
    assert result.dependencies == []
    assert result.unsupported
