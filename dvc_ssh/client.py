import asyncio
import os
import sys
from getpass import getpass
from typing import TYPE_CHECKING, Optional, cast

from asyncssh import (
    KeyEncryptionError,
    KeyImportError,
    SSHClient,
    read_private_key,
    read_public_key,
)
from asyncssh.public_key import _DEFAULT_KEY_FILES, SSHLocalKeyPair

if TYPE_CHECKING:
    from collections.abc import Sequence

    from asyncssh import SSHClientConnection, SSHKey
    from asyncssh.auth import KbdIntPrompts, KbdIntResponse
    from asyncssh.misc import FilePath
    from asyncssh.public_key import KeyPairListArg


async def _getpass(*args, **kwargs) -> str:
    return await asyncio.to_thread(getpass, *args, **kwargs)


class InteractiveSSHClient(SSHClient):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._conn: Optional[SSHClientConnection] = None
        self._keys_to_try: Optional[list[FilePath]] = None
        self._passphrases: dict[str, str] = {}

    def connection_made(self, conn: "SSHClientConnection") -> None:
        self._conn = conn
        self._keys_to_try = None

    def connection_lost(self, _exc: Optional[Exception]) -> None:
        self._conn = None

    async def public_key_auth_requested(
        self,
    ) -> Optional["KeyPairListArg"]:
        assert self._conn is not None
        if self._keys_to_try is None:
            self._keys_to_try = []
            options = self._conn._options
            config = options.config
            client_keys = cast("Sequence[FilePath]", config.get("IdentityFile", ()))
            if not client_keys:
                client_keys = [
                    os.path.expanduser(os.path.join("~", ".ssh", path))
                    for path, cond in _DEFAULT_KEY_FILES
                    if cond
                ]
            for key_to_load in client_keys:
                try:
                    read_private_key(key_to_load, passphrase=options.passphrase)
                except KeyImportError as exc:
                    if str(exc).startswith("Passphrase"):
                        self._keys_to_try.append(key_to_load)
                except OSError:
                    pass

        while self._keys_to_try:
            key_to_load = self._keys_to_try.pop()
            pubkey_to_load = str(key_to_load) + ".pub"
            try:
                key = await self._read_private_key_interactive(key_to_load)
            except KeyImportError:
                continue
            try:
                pubkey: Optional[SSHKey] = read_public_key(pubkey_to_load)
            except (OSError, KeyImportError):
                pubkey = None
            return SSHLocalKeyPair(key, pubkey, cert=None, enc_key=None)
        return None

    async def _read_private_key_interactive(self, path: "FilePath") -> "SSHKey":
        path = str(path)
        passphrase = self._passphrases.get(path)
        if passphrase:
            return read_private_key(path, passphrase=passphrase)

        for _ in range(3):
            passphrase = await _getpass(f"Enter passphrase for key {path!r}: ")
            if passphrase:
                try:
                    key = read_private_key(path, passphrase=passphrase)
                    self._passphrases[path] = passphrase
                    return key
                except (KeyImportError, KeyEncryptionError):
                    pass
        raise KeyImportError("Incorrect passphrase")

    def kbdint_auth_requested(self):
        # Let asyncssh handle password-backed keyboard-interactive auth so it
        # can reuse a configured password instead of triggering our prompt path.
        if self._conn._options.password is not None:
            return NotImplemented

        return ""

    async def kbdint_challenge_received(
        self,
        name: str,
        instructions: str,
        _lang: str,
        prompts: "KbdIntPrompts",
    ) -> Optional["KbdIntResponse"]:
        assert self._conn is not None
        options = self._conn._options
        prompt_prefix = ""
        addr = "@".join(filter(None, (options.username, options.host)))
        if addr:
            prompt_prefix = f"({addr}) "
        if name:
            prompt_prefix += f"({name}) "

        # NOTE: we write an extra line otherwise the prompt will be written on
        # the same line as any active tqdm progress bars
        sys.stderr.write(os.linesep)
        if instructions:
            sys.stderr.write(f"{instructions}{os.linesep}")

        response: list[str] = []
        for prompt, _echo in prompts:
            p = await _getpass(f"{prompt_prefix}{prompt}")
            response.append(p.rstrip())
        return response

    async def password_auth_requested(self) -> str:
        assert self._conn is not None
        options = self._conn._options
        prompt = "Password: "
        addr = "@".join(filter(None, (options.username, options.host)))
        if addr:
            prompt = f"{addr}'s password: "

        # NOTE: we write an extra line otherwise the prompt will be written on
        # the same line as any active tqdm progress bars
        sys.stderr.write(os.linesep)
        return await _getpass(prompt)
