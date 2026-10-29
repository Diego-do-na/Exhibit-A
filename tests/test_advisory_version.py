import pytest

from exhibit_a.advisory.version import InvalidVersion, Version, semver_key, upgrade_kind

V = Version.parse

# Ascending order, adapted by hand from the ordering rules in PEP 440.
ORDERED = [
    "1.0.dev456",
    "1.0a1",
    "1.0a2.dev456",
    "1.0a12.dev456",
    "1.0a12",
    "1.0b1.dev456",
    "1.0b2",
    "1.0b2.post345.dev456",
    "1.0b2.post345",
    "1.0rc1.dev456",
    "1.0rc1",
    "1.0",
    "1.0+abc.5",
    "1.0+abc.7",
    "1.0+5",
    "1.0.post456.dev34",
    "1.0.post456",
    "1.0.15",
    "1.1.dev1",
    "2!0.1",
]


def test_total_order():
    parsed = [V(s) for s in ORDERED]
    for a, b in zip(parsed, parsed[1:]):
        assert a < b, (a.text, b.text)
    assert sorted(reversed(parsed)) == parsed


@pytest.mark.parametrize(
    "a,b",
    [
        ("1.0", "1.0.0"),
        ("1.0", "v1.0"),
        ("1.0a1", "1.0alpha1"),
        ("1.0b", "1.0b0"),
        ("1.0c1", "1.0rc1"),
        ("1.0pre1", "1.0rc1"),
        ("1.0preview2", "1.0rc2"),
        ("1.0-rc.1", "1.0rc1"),
        ("1.0.post", "1.0.post0"),
        ("1.0-1", "1.0.post1"),
        ("1.0rev2", "1.0.post2"),
        ("1.0r3", "1.0.post3"),
        ("1.0.DEV", "1.0.dev0"),
        ("0!1.0", "1.0"),
        ("1.0+ABC", "1.0+abc"),
        ("1.0+a-b_c", "1.0+a.b.c"),
    ],
)
def test_normalized_spellings_are_equal(a, b):
    assert V(a) == V(b)
    assert hash(V(a)) == hash(V(b))


def test_epoch_dominates():
    assert V("1!0.1") > V("99.0")
    assert V("2!1.0") > V("1!9.9")


def test_dev_of_final_is_before_prereleases_but_dev_of_post_is_after_final():
    assert V("1.0.dev1") < V("1.0a1")
    assert V("1.0") < V("1.0.post1.dev1") < V("1.0.post1")


def test_local_versions():
    assert V("1.0") < V("1.0+local")
    assert V("1.0+abc") < V("1.0+1")  # alphanumeric segments sort before numeric
    assert V("1.0+1") < V("1.0+1.1")


def test_prerelease_flag_and_str():
    assert V("1.0rc1").is_prerelease
    assert V("1.0.dev0").is_prerelease
    assert not V("1.0.post1").is_prerelease
    assert str(V("1!1.0-RC.1.post2.DEV3+Ubuntu-1")) == "1!1.0rc1.post2.dev3+ubuntu.1"


@pytest.mark.parametrize("bad", ["", "abc", "1.0.", "1..0", "1.0+", "1.0-", "==1.0", "1.0 2", "1.*"])
def test_invalid_versions(bad):
    with pytest.raises(InvalidVersion):
        V(bad)


def test_non_string_rejected():
    with pytest.raises(InvalidVersion):
        V(1.0)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "installed,target,kind",
    [
        ("2.3.0", "2.3.1", "patch"),
        ("2.3", "2.3.0.post1", "patch"),
        ("2.3.0", "2.4.1", "minor"),
        ("2.3.0", "3.0.0", "major"),
        ("1.0", "1!1.0", "major"),
        ("1.0.0rc1", "1.0.0", "patch"),
    ],
)
def test_upgrade_kind(installed, target, kind):
    assert upgrade_kind(V(installed), V(target)) == kind


def test_semver_order():
    ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
               "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "2.0.0"]
    keys = [semver_key(s) for s in ordered]
    assert keys == sorted(keys)
    assert semver_key("1.0.0+build.5") == semver_key("1.0.0")
    with pytest.raises(InvalidVersion):
        semver_key("1.0")
    with pytest.raises(InvalidVersion):
        semver_key("01.0.0")
