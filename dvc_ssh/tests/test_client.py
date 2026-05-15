import dvc_ssh.client
from dvc_ssh import SSHFileSystem
from dvc_ssh.tests.cloud import TEST_SSH_USER


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

    assert fs.fs_args["preferred_auth"] == ["keyboard-interactive", "password"]
    assert fs.exists("/tmp")
