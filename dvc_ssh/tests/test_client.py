from types import SimpleNamespace

import pytest

import dvc_ssh.client
from dvc_ssh import SSHFileSystem
from dvc_ssh.client import InteractiveSSHClient
from dvc_ssh.tests.cloud import TEST_SSH_USER


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


def test_password_auth_uses_configured_password(ssh_server, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

    async def fail_getpass(*args, **kwargs):
        raise AssertionError("_getpass should not be called")

    monkeypatch.setattr(dvc_ssh.client, "_getpass", fail_getpass)

    fs = SSHFileSystem(
        host=ssh_server["host"],
        port=ssh_server["port"],
        user=TEST_SSH_USER,
        password="password",
    )

    assert fs.fs_args["preferred_auth"] == ["password", "keyboard-interactive"]
    assert fs.exists("/tmp")
