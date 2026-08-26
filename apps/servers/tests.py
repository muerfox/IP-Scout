import unittest
from unittest.mock import MagicMock, patch

import paramiko

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .forms import ServerForm
from .models import Server
from .services import SSHConnectionError, SSHService

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
