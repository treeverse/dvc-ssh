import os
import uuid

from funcy import cached_property

from dvc.testing.cloud import Cloud
from dvc.testing.path_info import URLInfo

TEST_SSH_USER = "user"
TEST_SSH_PASSWORD = "password"
TEST_SSH_KEY_PATH = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), f"{TEST_SSH_USER}.key"
)


class SSH(Cloud, URLInfo):
    @staticmethod
    def get_url(host, port):  # pylint: disable=arguments-differ
        return f"ssh://{host}:{port}/tmp/data/{uuid.uuid4()}"

    @property
    def config(self):
        return {
            "url": self.url,
            "user": TEST_SSH_USER,
            "keyfile": TEST_SSH_KEY_PATH,
        }

    @cached_property
    def _ssh(self):
        from sshfs import SSHFileSystem

        return SSHFileSystem(
            host=self.host,
            port=self.port,
            username=TEST_SSH_USER,
            client_keys=[TEST_SSH_KEY_PATH],
        )

    def is_file(self):
        return self._ssh.isfile(self.path)

    def is_dir(self):
        return self._ssh.isdir(self.path)

    def exists(self):
        return self._ssh.exists(self.path)

    def mkdir(self, mode=0o777, parents=False, exist_ok=False):
        assert mode == 0o777
        assert parents

        self._ssh.makedirs(self.path, exist_ok=exist_ok)

    def write_bytes(self, contents):
        assert isinstance(contents, bytes)
        with self._ssh.open(self.path, "wb") as fobj:
            fobj.write(contents)

    def read_bytes(self):
        with self._ssh.open(self.path, "rb") as fobj:
            return fobj.read()

    def unlink(self, missing_ok: bool = False) -> None:
        raise NotImplementedError

    def rmdir(self, recursive: bool = True) -> None:
        raise NotImplementedError

    @property
    def fs_path(self):
        return self.path
