from types import SimpleNamespace

import pytest

from dvc_ssh.client import InteractiveSSHClient


@pytest.mark.parametrize(
    "password,expected",
    [("secret", NotImplemented), (None, "")],
)
def test_kbdint_auth_requested(password, expected):
    client = InteractiveSSHClient()
    client._conn = SimpleNamespace(_options=SimpleNamespace(password=password))

    result = client.kbdint_auth_requested()

    if expected is NotImplemented:
        assert result is NotImplemented
    else:
        assert result == expected
