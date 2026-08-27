import unittest
from unittest.mock import MagicMock, patch

import paramiko

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.common.locks import LockHeldError
from apps.users.models import AuditLogEntry

from .forms import ServerForm
from .models import Server
from .services import ConnectionTestResult, SSHConnectionError, SSHService

User = get_user_model()


def make_server(**overrides) -> Server:
    defaults = dict(
        name="edge-1",
        hostname="edge1.example.com",
        ssh_port=22,
        ssh_username="deploy",
        ssh_auth_type=Server.AuthType.PASSWORD,
    )
    if "ssh_private_key" not in overrides:
        defaults["ssh_private_key"] = "s3cr3t"
    defaults.update(overrides)
    return Server(**defaults)


class ServerConnectionStatusTests(unittest.TestCase):
    """Pure property logic - no DB needed (unsaved instances)."""

    def test_disabled_wins_over_everything(self):
        self.assertEqual(make_server(enabled=False, last_error="x").connection_status, "disabled")

    def test_error_when_last_error_set(self):
        self.assertEqual(make_server(enabled=True, last_error="boom").connection_status, "error")

    def test_unknown_when_never_connected(self):
        self.assertEqual(make_server(enabled=True).connection_status, "unknown")

    def test_ok_when_connected_without_error(self):
        server = make_server(enabled=True, last_connected_at=timezone.now())
        self.assertEqual(server.connection_status, "ok")


def _mock_exec_command_factory(responses: dict[str, tuple[bytes, bytes]]):
    def _exec(command, timeout=None):
        stdout_data, stderr_data = responses.get(command, (b"", b""))
        stdout = MagicMock()
        stdout.read.return_value = stdout_data
        stderr = MagicMock()
        stderr.read.return_value = stderr_data
        return (MagicMock(), stdout, stderr)

    return _exec


class SSHServiceTests(unittest.TestCase):
    """SSHService against a mocked paramiko client - no network, no DB."""

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_test_connection_success(self, mock_client_cls):
        client = MagicMock()
        client.__enter__.return_value = client
        client.exec_command.side_effect = _mock_exec_command_factory(
            {
                "uname -s": (b"Linux\n", b""),
                "command -v nginx": (b"/usr/sbin/nginx\n", b""),
                "nginx -v": (b"", b"nginx version: nginx/1.24.0\n"),
            }
        )
        mock_client_cls.return_value = client

        result = SSHService(make_server()).test_connection()

        self.assertTrue(result.success)
        self.assertEqual(result.os_name, "Linux")
        self.assertTrue(result.nginx_found)
        self.assertIn("1.24.0", result.nginx_version)

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_test_connection_rejects_non_linux(self, mock_client_cls):
        client = MagicMock()
        client.__enter__.return_value = client
        client.exec_command.side_effect = _mock_exec_command_factory({"uname -s": (b"Darwin\n", b"")})
        mock_client_cls.return_value = client

        result = SSHService(make_server()).test_connection()

        self.assertFalse(result.success)
        self.assertIn("Unsupported OS", result.error)

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_test_connection_nginx_not_found(self, mock_client_cls):
        client = MagicMock()
        client.__enter__.return_value = client
        client.exec_command.side_effect = _mock_exec_command_factory({"uname -s": (b"Linux\n", b"")})
        mock_client_cls.return_value = client

        result = SSHService(make_server()).test_connection()

        self.assertTrue(result.success)
        self.assertFalse(result.nginx_found)

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_test_connection_auth_failure_is_caught(self, mock_client_cls):
        client = MagicMock()
        client.connect.side_effect = paramiko.AuthenticationException("bad credentials")
        mock_client_cls.return_value = client

        result = SSHService(make_server()).test_connection()

        self.assertFalse(result.success)
        self.assertIn("bad credentials", result.error)

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_discover_logs_skips_directories_and_dedupes(self, mock_client_cls):
        client = MagicMock()
        client.__enter__.return_value = client
        sftp = MagicMock()
        client.open_sftp.return_value = sftp

        file_entry = MagicMock(filename="access.log", st_size=1024, st_mtime=1_700_000_000)
        file_entry.st_mode = 0o100644  # regular file
        dir_entry = MagicMock(filename="archive", st_size=0, st_mtime=0)
        dir_entry.st_mode = 0o040755  # directory
        sftp.listdir_attr.return_value = [file_entry, dir_entry]
        mock_client_cls.return_value = client

        server = make_server(ssh_auth_type=Server.AuthType.SSH_KEY, ssh_private_key="")
        with patch.object(SSHService, "_load_private_key", return_value=MagicMock()):
            files = SSHService(server).discover_logs()

        self.assertEqual([f.path for f in files], ["/var/log/nginx/access.log"])
        sftp.close.assert_called_once()

    def test_load_private_key_empty_raises(self):
        with self.assertRaises(SSHConnectionError):
            SSHService._load_private_key("")

    def test_load_private_key_garbage_raises(self):
        with self.assertRaises(SSHConnectionError):
            SSHService._load_private_key("this is not a valid PEM key")

    def test_password_auth_requires_password(self):
        server = make_server(ssh_auth_type=Server.AuthType.PASSWORD, ssh_private_key="")
        with self.assertRaises(SSHConnectionError):
            SSHService(server)._connect_kwargs()


def _mock_poll_client(stat_output: bytes, exit_status: int, file_content: bytes = b""):
    """A mocked paramiko.SSHClient for poll_log: `exec_command` answers the
    fixed `stat -c '%i %s %Y'` call, `open_sftp().open(...)` answers the
    SFTP range read."""
    client = MagicMock()
    client.__enter__.return_value = client

    stdout = MagicMock()
    stdout.read.return_value = stat_output
    stdout.channel.recv_exit_status.return_value = exit_status
    client.exec_command.return_value = (MagicMock(), stdout, MagicMock())

    remote_file = MagicMock()
    remote_file.__enter__.return_value = remote_file
    remote_file.__exit__.return_value = False
    remote_file.read.side_effect = lambda size: file_content[:size]

    sftp = MagicMock()
    sftp.open.return_value = remote_file
    client.open_sftp.return_value = sftp

    return client, remote_file, sftp


class SSHServicePollLogTests(unittest.TestCase):
    """poll_log against a mocked paramiko client - no network, no DB."""

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_first_poll_skips_to_end_of_file(self, mock_client_cls):
        client, remote_file, sftp = _mock_poll_client(b"111 500 1700000000\n", 0)
        mock_client_cls.return_value = client

        chunk = SSHService(make_server()).poll_log("/var/log/nginx/access.log", None, None)

        self.assertEqual(chunk.inode, 111)
        self.assertEqual(chunk.size, 500)
        self.assertEqual(chunk.offset, 500)
        self.assertEqual(chunk.data, b"")
        self.assertFalse(chunk.rotated)
        client.open_sftp.assert_not_called()  # nothing to read on a fresh baseline

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_reads_new_bytes_from_known_offset(self, mock_client_cls):
        content = b"x" * 100
        client, remote_file, sftp = _mock_poll_client(b"111 500 1700000000\n", 0, content)
        mock_client_cls.return_value = client

        chunk = SSHService(make_server()).poll_log("/var/log/nginx/access.log", 111, 400)

        self.assertEqual(chunk.offset, 400)
        self.assertEqual(chunk.data, content)
        self.assertFalse(chunk.rotated)
        remote_file.seek.assert_called_once_with(400)

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_rotation_reads_from_start_of_new_file(self, mock_client_cls):
        content = b"y" * 50
        client, remote_file, sftp = _mock_poll_client(b"222 50 1700000000\n", 0, content)
        mock_client_cls.return_value = client

        chunk = SSHService(make_server()).poll_log("/var/log/nginx/access.log", 111, 999)

        self.assertTrue(chunk.rotated)
        self.assertEqual(chunk.offset, 0)
        self.assertEqual(chunk.data, content)
        remote_file.seek.assert_called_once_with(0)

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_truncated_file_clamps_offset_without_reading(self, mock_client_cls):
        client, remote_file, sftp = _mock_poll_client(b"111 200 1700000000\n", 0)
        mock_client_cls.return_value = client

        chunk = SSHService(make_server()).poll_log("/var/log/nginx/access.log", 111, 1000)

        self.assertFalse(chunk.rotated)
        self.assertEqual(chunk.offset, 200)
        self.assertEqual(chunk.data, b"")
        client.open_sftp.assert_not_called()

    @patch("apps.servers.services.paramiko.SSHClient")
    def test_missing_file_returns_none(self, mock_client_cls):
        client, remote_file, sftp = _mock_poll_client(b"", 1)  # `stat` exits non-zero
        mock_client_cls.return_value = client

        chunk = SSHService(make_server()).poll_log("/var/log/nginx/gone.log", 111, 0)

        self.assertIsNone(chunk)
        client.open_sftp.assert_not_called()


class ServerFormTests(TestCase):
    def test_new_server_requires_credential(self):
        form = ServerForm(
            data={
                "name": "edge-2",
                "hostname": "edge2.example.com",
                "ip_address": "",
                "ssh_port": 22,
                "ssh_username": "deploy",
                "ssh_auth_type": Server.AuthType.SSH_KEY,
                "enabled": True,
                "ssh_private_key": "",
                "log_search_paths_text": "",
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("ssh_private_key", form.errors)

    def test_valid_form_parses_extra_paths_and_encrypts_key(self):
        form = ServerForm(
            data={
                "name": "edge-3",
                "hostname": "edge3.example.com",
                "ip_address": "",
                "ssh_port": 22,
                "ssh_username": "deploy",
                "ssh_auth_type": Server.AuthType.SSH_KEY,
                "enabled": True,
                "ssh_private_key": "-----BEGIN KEY-----\nabc\n-----END KEY-----",
                "log_search_paths_text": "/var/log/nginx-alt/\n/var/log/nginx-alt2/",
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        server = form.save()
        self.assertEqual(server.log_search_paths, ["/var/log/nginx-alt/", "/var/log/nginx-alt2/"])
        # The field decrypts transparently on refresh from DB.
        server.refresh_from_db()
        self.assertIn("BEGIN KEY", server.ssh_private_key)

    def test_editing_without_new_key_keeps_existing_credential(self):
        server = make_server(name="edge-4")
        server.save()
        original_key = server.ssh_private_key

        form = ServerForm(
            data={
                "name": "edge-4",
                "hostname": server.hostname,
                "ip_address": "",
                "ssh_port": 22,
                "ssh_username": "deploy",
                "ssh_auth_type": Server.AuthType.PASSWORD,
                "enabled": True,
                "ssh_private_key": "",
                "log_search_paths_text": "",
            },
            instance=server,
        )
        self.assertTrue(form.is_valid(), form.errors)
        updated = form.save()
        self.assertEqual(updated.ssh_private_key, original_key)


class ServerViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_list_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("servers:list"))
        self.assertEqual(response.status_code, 302)

    def test_create_server(self):
        response = self.client.post(
            reverse("servers:create"),
            {
                "name": "edge-5",
                "hostname": "edge5.example.com",
                "ip_address": "",
                "ssh_port": 22,
                "ssh_username": "deploy",
                "ssh_auth_type": Server.AuthType.SSH_KEY,
                "enabled": True,
                "ssh_private_key": "-----BEGIN KEY-----\nabc\n-----END KEY-----",
                "log_search_paths_text": "",
            },
        )
        server = Server.objects.get(name="edge-5")
        self.assertRedirects(response, reverse("servers:detail", args=[server.pk]))

    def test_toggle_enabled(self):
        server = make_server(name="edge-6")
        server.save()
        response = self.client.post(reverse("servers:toggle-enabled", args=[server.pk]))
        server.refresh_from_db()
        self.assertFalse(server.enabled)
        self.assertEqual(response.status_code, 302)

    def test_delete_server(self):
        server = make_server(name="edge-7")
        server.save()
        response = self.client.post(reverse("servers:delete", args=[server.pk]))
        self.assertRedirects(response, reverse("servers:list"))
        self.assertFalse(Server.objects.filter(pk=server.pk).exists())

    @patch("apps.servers.views.test_server_connection")
    def test_test_connection_enqueues_task(self, mock_task):
        server = make_server(name="edge-8")
        server.save()
        self.client.post(reverse("servers:test-connection", args=[server.pk]))
        mock_task.delay.assert_called_once_with(server.id, user_id=self.user.id)


class TestServerConnectionTaskTests(TestCase):
    """`apps.servers.tasks.test_server_connection` - the Celery task behind
    the "Test Connection" button. SSHService is mocked at the boundary
    (real SSH behavior is covered separately, see
    apps.servers.tests.SSHServiceTests and this project's manual
    rootless-sshd verification, see README); this class covers the
    task's own DB/audit-log/locking logic, previously untested."""

    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.server = make_server(name="edge-conn")
        self.server.save()

    def test_missing_server_returns_silently(self):
        from .tasks import test_server_connection

        test_server_connection(999999)  # must not raise

    @patch("apps.servers.tasks.SSHService")
    def test_success_updates_server_and_records_audit_log(self, mock_service_cls):
        from .tasks import test_server_connection

        mock_service_cls.return_value.test_connection.return_value = ConnectionTestResult(
            success=True, os_name="Linux", nginx_found=True, nginx_version="1.18.0"
        )

        test_server_connection(self.server.id, user_id=self.user.id)

        self.server.refresh_from_db()
        self.assertEqual(self.server.last_error, "")
        self.assertIsNotNone(self.server.last_connected_at)

        entry = AuditLogEntry.objects.get(action="server.test_connection")
        self.assertEqual(entry.result, AuditLogEntry.Result.SUCCESS)
        self.assertEqual(entry.user_id, self.user.id)
        self.assertEqual(entry.metadata["os_name"], "Linux")
        self.assertTrue(entry.metadata["nginx_found"])

    @patch("apps.servers.tasks.SSHService")
    def test_failure_sets_last_error_and_records_audit_log(self, mock_service_cls):
        from .tasks import test_server_connection

        mock_service_cls.return_value.test_connection.return_value = ConnectionTestResult(
            success=False, error="Connection refused"
        )

        test_server_connection(self.server.id)

        self.server.refresh_from_db()
        self.assertEqual(self.server.last_error, "Connection refused")

        entry = AuditLogEntry.objects.get(action="server.test_connection")
        self.assertEqual(entry.result, AuditLogEntry.Result.FAILURE)
        self.assertIsNone(entry.user_id)

    @patch("apps.servers.tasks.SSHService")
    def test_failure_without_error_message_falls_back_to_generic_text(self, mock_service_cls):
        from .tasks import test_server_connection

        mock_service_cls.return_value.test_connection.return_value = ConnectionTestResult(success=False, error=None)

        test_server_connection(self.server.id)

        self.server.refresh_from_db()
        self.assertEqual(self.server.last_error, "Unknown SSH error")

    @patch("apps.servers.tasks.redis_lock")
    def test_lock_held_is_skipped_silently(self, mock_lock):
        from .tasks import test_server_connection

        mock_lock.side_effect = LockHeldError(f"ssh:test:{self.server.id}")
        test_server_connection(self.server.id)  # must not raise
        self.server.refresh_from_db()
        self.assertEqual(self.server.last_error, "")  # untouched - task returned before doing anything
        self.assertFalse(AuditLogEntry.objects.filter(action="server.test_connection").exists())
