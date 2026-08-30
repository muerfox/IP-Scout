"""SSH connectivity/discovery/reading for monitored servers (spec sections
7, 9, 43).

Every method is one explicit, backend-constructed operation
(test_connection / discover_logs / poll_log) - there is no "run arbitrary
command" entry point, and no argument here is ever interpolated from
untrusted input (log paths come from discovery itself or from the
Server.log_search_paths admin-only field).
"""
from __future__ import annotations

import io
import posixpath
import shlex
import stat as stat_module
from dataclasses import dataclass

import paramiko
from django.conf import settings

from .models import Server

DEFAULT_LOG_DIR = "/var/log/nginx/"

_KEY_CLASSES = (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey)


class SSHConnectionError(Exception):
    """Raised when a connection or one of the explicit SSH operations fails."""


@dataclass
class ConnectionTestResult:
    success: bool
    os_name: str | None = None
    nginx_found: bool = False
    nginx_version: str | None = None
    error: str | None = None


@dataclass
class DiscoveredLogFile:
    path: str
    size: int
    mtime: int


@dataclass
class LogChunk:
    """Result of one incremental poll (spec section 9)."""

    inode: int
    size: int
    mtime: int
    offset: int  # byte offset `data` starts at
    data: bytes  # newly read bytes, b"" if nothing new
    rotated: bool  # True if the file's inode changed since the last known one


class SSHService:
    def __init__(self, server: Server):
        self.server = server

    # -- explicit operations -------------------------------------------------

    def test_connection(self) -> ConnectionTestResult:
        """Verify SSH connectivity, that the remote OS is Linux, and whether
        nginx is installed."""
        try:
            with self._client() as client:
                os_name = self._exec(client, ["uname", "-s"]).strip()
                if os_name.lower() != "linux":
                    return ConnectionTestResult(
                        success=False,
                        os_name=os_name or None,
                        error=f"Unsupported OS: {os_name or 'unknown'} (Linux required).",
                    )
                nginx_path = self._exec(client, ["command", "-v", "nginx"]).strip()
                nginx_version = None
                if nginx_path:
                    nginx_version = self._exec(client, ["nginx", "-v"], combine_stderr=True).strip()
                return ConnectionTestResult(
                    success=True,
                    os_name=os_name,
                    nginx_found=bool(nginx_path),
                    nginx_version=nginx_version or None,
                )
        except SSHConnectionError as exc:
            return ConnectionTestResult(success=False, error=str(exc))

    def discover_logs(self, extra_paths: list[str] | None = None) -> list[DiscoveredLogFile]:
        """List candidate log files via SFTP stat - no shell/glob parsing."""
        directories = [DEFAULT_LOG_DIR, *(extra_paths or [])]
        discovered: list[DiscoveredLogFile] = []
        seen: set[str] = set()
        with self._client() as client:
            sftp = client.open_sftp()
            try:
                for directory in directories:
                    for entry in self._list_directory(sftp, directory):
                        if entry.path in seen:
                            continue
                        seen.add(entry.path)
                        discovered.append(entry)
            finally:
                sftp.close()
        return discovered

    def poll_log(self, path: str, known_inode: int | None, known_offset: int | None) -> LogChunk | None:
        """One incremental read cycle: stat the file (for its inode - the
        SFTP protocol doesn't expose inode numbers, so this part uses a
        fixed `stat` command instead), detect rotation, and read any new
        bytes via an SFTP range read (not a full download). All within a
        single SSH connection.

        `known_inode=None` means this file has never been polled before;
        rather than backfilling potentially huge historical content, the
        first poll establishes a baseline at the current end of file and
        starts tailing from there (spec sections 9 and 47).

        Returns None if the file doesn't exist (e.g. not created yet, or
        removed).
        """
        with self._client() as client:
            stat_output = self._exec_with_status(client, ["stat", "-c", "%i %s %Y", path])
            if stat_output is None:
                return None
            inode_str, size_str, mtime_str = stat_output.split()
            inode, size, mtime = int(inode_str), int(size_str), int(mtime_str)

            if known_inode is None:
                read_offset = size
                rotated = False
            else:
                rotated = inode != known_inode
                read_offset = 0 if rotated else min(known_offset or 0, size)

            data = b""
            if size > read_offset:
                sftp = client.open_sftp()
                try:
                    with sftp.open(path, "r") as remote_file:
                        remote_file.seek(read_offset)
                        data = remote_file.read(size - read_offset)
                finally:
                    sftp.close()

        return LogChunk(inode=inode, size=size, mtime=mtime, offset=read_offset, data=data, rotated=rotated)

    # -- internals -------------------------------------------------------------

    def _connect_kwargs(self) -> dict:
        kwargs: dict = {
            "hostname": self.server.hostname,
            "port": self.server.ssh_port,
            "username": self.server.ssh_username,
            "timeout": settings.SSH_CONNECT_TIMEOUT,
        }
        if self.server.ssh_auth_type == Server.AuthType.SSH_KEY:
            kwargs["pkey"] = self._load_private_key(self.server.ssh_private_key)
        else:
            if not self.server.ssh_private_key:
                raise SSHConnectionError("No SSH password configured for this server.")
            kwargs["password"] = self.server.ssh_private_key
        return kwargs

    @staticmethod
    def _load_private_key(key_data: str) -> paramiko.PKey:
        if not key_data:
            raise SSHConnectionError("No SSH private key configured for this server.")
        last_error: Exception | None = None
        for key_cls in _KEY_CLASSES:
            try:
                return key_cls.from_private_key(io.StringIO(key_data))
            except paramiko.SSHException as exc:
                last_error = exc
        raise SSHConnectionError(f"Unable to parse SSH private key: {last_error}")

    def _client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        # No interactive host-key prompt is possible from a Celery task and
        # there's no host-key-pinning UI yet - accept-and-record is the
        # pragmatic default for this phase.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(**self._connect_kwargs())
        except SSHConnectionError:
            raise
        except (paramiko.SSHException, OSError) as exc:
            raise SSHConnectionError(str(exc)) from exc
        return client

    @staticmethod
    def _exec(client: paramiko.SSHClient, argv: list[str], combine_stderr: bool = False) -> str:
        """Run one fixed, backend-constructed argv - never user input."""
        command = " ".join(shlex.quote(part) for part in argv)
        _, stdout, stderr = client.exec_command(command, timeout=settings.SSH_CONNECT_TIMEOUT)
        output = stdout.read().decode(errors="replace")
        if combine_stderr:
            output += stderr.read().decode(errors="replace")
        return output

    @staticmethod
    def _exec_with_status(client: paramiko.SSHClient, argv: list[str]) -> str | None:
        """Like _exec, but returns None on a non-zero exit status instead
        of whatever partial stdout there was (used for `stat`, where a
        non-zero exit means "no such file")."""
        command = " ".join(shlex.quote(part) for part in argv)
        _, stdout, _stderr = client.exec_command(command, timeout=settings.SSH_CONNECT_TIMEOUT)
        output = stdout.read().decode(errors="replace")
        if stdout.channel.recv_exit_status() != 0:
            return None
        return output

    @staticmethod
    def _list_directory(sftp: paramiko.SFTPClient, directory: str) -> list[DiscoveredLogFile]:
        try:
            entries = sftp.listdir_attr(directory)
        except FileNotFoundError:
            return []
        results = []
        for entry in entries:
            if stat_module.S_ISDIR(entry.st_mode or 0):
                continue
            results.append(
                DiscoveredLogFile(
                    path=posixpath.join(directory, entry.filename),
                    size=entry.st_size or 0,
                    mtime=entry.st_mtime or 0,
                )
            )
        return results
