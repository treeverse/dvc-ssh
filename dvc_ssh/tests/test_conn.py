from dvc_ssh import SSHFileSystem

from .cloud import TEST_SSH_KEY_PATH


def test_keyfile_set(ssh_server, mocker):
    f = SSHFileSystem(
        host=ssh_server["host"],
        port=ssh_server["port"],
        user="user",
        keyfile=TEST_SSH_KEY_PATH,
    )

    assert f.fs


def test_password_set(ssh_server, mocker):
    # make sure that we don't open a password prompt if password is set
    # this would let the test fail with a timeout
    f = SSHFileSystem(
        host=ssh_server["host"],
        port=ssh_server["port"],
        # see config in tests/docker-compose.yml, can't use environment variable here
        # because it is not passed to the test process
        user="user",
        password="password",
    )

    assert f.fs


def test_password_prompt(ssh_server, mocker):
    f = SSHFileSystem(
        host=ssh_server["host"],
        port=ssh_server["port"],
        user="user",
        ask_password=True,
    )

    mock_getpass = mocker.patch(
        "dvc_ssh.ask_password",
    )
    mock_getpass.return_value = "password"

    assert f.fs
