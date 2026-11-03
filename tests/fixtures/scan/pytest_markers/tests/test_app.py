import pytest


@pytest.mark.skip(reason="fixture only names the marker")
def test_ping():
    assert True
