# pylint: disable=W0212,W0613
import os

import pytest

from dvc_ssh import SSHFileSystem


def test_get_kwargs_from_urls():
    user = "test"
    host = "123.45.67.89"
    port = 1234
    path = "/path/to/dir"

    # URL ssh://[user@]host.xz[:port]/path
    url = f"ssh://{user}@{host}:{port}{path}"

    assert SSHFileSystem._get_kwargs_from_urls(url) == {
        "username": user,
        "host": host,
        "port": port,
    }

    # SCP-like URL ssh://[user@]host.xz:/absolute/path
    url = f"ssh://{user}@{host}:{path}"

    assert SSHFileSystem._get_kwargs_from_urls(url) == {
        "username": user,
        "host": host,
    }


def test_init():
    fs = SSHFileSystem(
        user="test",
        host="12.34.56.78",
        port="1234",
        password="xxx",
        passphrase="yyy",
    )
    assert fs.fs_args["username"] == "test"
    assert fs.fs_args["host"] == "12.34.56.78"
    assert fs.fs_args["port"] == "1234"
    assert fs.fs_args["password"] == "xxx"
    assert fs.fs_args["passphrase"] == "yyy"
    assert fs.fs_args["preferred_auth"] == [
        "publickey",
        "keyboard-interactive",
        "password",
    ]


@pytest.mark.parametrize(
    "option,expected_auth",
    [
        ("password", ["keyboard-interactive", "password"]),
        ("passphrase", ["publickey"]),
    ],
)
def test_ssh_ask_password(mocker, option, expected_auth):
    mocker.patch("dvc_ssh.ask_password", return_value="fish")
    args = {f"ask_{option}": True}
    fs = SSHFileSystem(user="test", host="2.2.2.2", **args)
    assert fs.fs_args[option] == "fish"
    assert fs.fs_args["preferred_auth"] == expected_auth


@pytest.mark.parametrize("password", [None, "foo"])
@pytest.mark.parametrize("passphrase", [None, "bar"])
def test_passphrase(mocker, password, passphrase):
    connect = mocker.patch("asyncssh.connect")

    kwargs = {"password": password, "passphrase": passphrase}
    _ = SSHFileSystem(host="foo", **kwargs).fs

    assert connect.call_args[1]["password"] == password
    assert connect.call_args[1]["passphrase"] == passphrase

    expected_preferred_auth = []
    if passphrase is not None:
        expected_preferred_auth.append("publickey")
    if password is not None:
        expected_preferred_auth.extend(("keyboard-interactive", "password"))

    assert connect.call_args[1].get("preferred_auth") == (
        expected_preferred_auth or None
    )


def test_ssh_user():
    fs = SSHFileSystem(host="example.com", user="test")
    assert fs.fs_args["username"] == "test"


def test_ssh_port():
    fs = SSHFileSystem(host="example.com", port=4321)
    assert fs.fs_args["port"] == 4321


@pytest.mark.parametrize(
    "config,expected_keyfile",
    [
        ({"host": "example.com", "keyfile": "dvc_config.key"}, ["dvc_config.key"]),
        ({"host": "example.com"}, None),
    ],
)
def test_ssh_keyfile(config, expected_keyfile):
    fs = SSHFileSystem(**config)
    expected_keyfiles = (
        [os.path.expanduser(path) for path in expected_keyfile]
        if expected_keyfile
        else expected_keyfile
    )
    assert fs.fs_args.get("client_keys") == expected_keyfiles


@pytest.mark.parametrize(
    "config,expected_preferred_auth",
    [
        ({"host": "example.com"}, None),
        (
            {"host": "example.com", "password": "secret"},
            ["keyboard-interactive", "password"],
        ),
        ({"host": "example.com", "keyfile": "id_test"}, ["publickey"]),
        (
            {"host": "example.com", "keyfile": "id_test", "password": "secret"},
            ["publickey", "keyboard-interactive", "password"],
        ),
    ],
)
def test_ssh_preferred_auth(config, expected_preferred_auth):
    fs = SSHFileSystem(**config)
    assert fs.fs_args.get("preferred_auth") == expected_preferred_auth


@pytest.mark.parametrize(
    "config,expected_gss_auth",
    [
        ({"host": "example.com", "gss_auth": True}, True),
        ({"host": "example.com", "gss_auth": False}, False),
        ({"host": "not_in_ssh_config.com"}, False),
    ],
)
def test_ssh_gss_auth(config, expected_gss_auth):
    fs = SSHFileSystem(**config)
    assert fs.fs_args["gss_auth"] == expected_gss_auth


@pytest.mark.parametrize(
    "config,path,expected_path",
    [
        ({"host": "example.com"}, "path", "ssh://example.com/path"),
        ({"host": "example.com"}, "/path", "ssh://example.com/path"),
        ({"host": "example.com", "port": 1234}, "path", "ssh://example.com:1234/path"),
        ({"host": "example.com", "port": 1234}, "/path", "ssh://example.com:1234/path"),
    ],
)
def test_unstrip_protocol(mocker, config, path, expected_path):
    fs = SSHFileSystem(**config, fs=mocker.MagicMock())
    assert fs.unstrip_protocol(path) == expected_path
