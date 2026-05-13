import getpass
import os.path
import threading
from typing import ClassVar

from funcy import memoize, wrap_prop, wrap_with

from dvc.utils.objects import cached_property
from dvc_objects.fs.base import FileSystem
from dvc_objects.fs.utils import as_atomic


@wrap_with(threading.Lock())
@memoize
def ask_password(host, user, port, desc):
    prompt = f"Enter a {desc} for"
    if user:
        prompt += f" {user}@{host}"
    else:
        prompt += f" {host}"
    if port:
        prompt += f":{port}"
    prompt += ":\n"

    try:
        return getpass.getpass(prompt)
    except EOFError:
        return None


class SSHFileSystem(FileSystem):
    protocol = "ssh"
    REQUIRES: ClassVar[dict[str, str]] = {"sshfs": "sshfs"}
    PARAM_CHECKSUM = "md5"

    @classmethod
    def _strip_protocol(cls, path: str) -> str:
        from fsspec.utils import infer_storage_options

        return infer_storage_options(path)["path"]

    def unstrip_protocol(self, path: str) -> str:
        host = self.fs_args["host"]
        port = self.fs_args.get("port")
        path = path.lstrip("/")

        url = f"ssh://{host}"
        if port:
            url += f":{port}"
        url += f"/{path}"
        return url

    def _prepare_credentials(self, **config):
        from .client import InteractiveSSHClient

        self.CAN_TRAVERSE = True

        login_info = {}
        login_info["client_factory"] = config.get(
            "client_factory", InteractiveSSHClient
        )
        login_info["host"] = config["host"]
        if username := (config.get("user") or config.get("username")):
            login_info["username"] = username
        if port := config.get("port"):
            login_info["port"] = port

        for option in ("password", "passphrase"):
            login_info[option] = config.get(option)

            if config.get(f"ask_{option}") and login_info[option] is None:
                login_info[option] = ask_password(
                    login_info["host"],
                    login_info.get("username"),
                    login_info.get("port"),
                    option,
                )

        if keyfile := config.get("keyfile"):
            login_info["client_keys"] = [os.path.expanduser(keyfile)]

        # Limit auth attempts to methods backed by configured credentials.
        # This avoids prompting for unrelated default keys while preserving
        # keyboard-interactive fallback for password-based logins.
        preferred_auth = []
        if login_info.get("client_keys") or login_info.get("passphrase") is not None:
            preferred_auth.append("publickey")
        if login_info.get("password") is not None:
            preferred_auth.extend(("keyboard-interactive", "password"))
        if preferred_auth:
            login_info["preferred_auth"] = preferred_auth

        login_info["timeout"] = config.get("timeout", 1800)

        # These two settings fine tune the asyncssh to use the
        # fastest encryption algorithm and disable compression
        # altogether (since it blocking, it is slowing down
        # the transfers in a considerable rate, and even for
        # compressible data it is making it extremely slow).
        # See: https://github.com/ronf/asyncssh/issues/374
        login_info["encryption_algs"] = [
            "aes128-gcm@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
        ]
        login_info["compression_algs"] = None

        login_info["gss_auth"] = config.get("gss_auth", False)
        login_info["agent_forwarding"] = config.get("agent_forwarding", True)

        if "max_sessions" in config:
            login_info["max_sessions"] = config["max_sessions"]
        return login_info

    @wrap_prop(threading.Lock())
    @cached_property
    def fs(self):
        from . import spec

        return spec.SSHFileSystem(**self.fs_args)

    # Ensure that if an interrupt happens during the transfer, we don't
    # pollute the cache.

    def upload_fobj(self, fobj, to_info, **kwargs):
        with as_atomic(self, to_info) as tmp_file:
            super().upload_fobj(fobj, tmp_file, **kwargs)
