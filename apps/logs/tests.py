import unittest
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.servers.models import Server

from .models import LogSource

User = get_user_model()


class LogSourceReaderStatusTests(unittest.TestCase):
    """Pure property logic - no DB needed (unsaved instances)."""

    def test_disabled(self):
        self.assertEqual(LogSource(enabled=False).reader_status, "disabled")

    def test_pending_when_never_read(self):
        self.assertEqual(LogSource(enabled=True).reader_status, "pending")

    def test_error_when_last_error_set(self):
        self.assertEqual(LogSource(enabled=True, last_error="boom").reader_status, "error")

    def test_running_once_read(self):
        log_source = LogSource(enabled=True, last_read_at=timezone.now())
        self.assertEqual(log_source.reader_status, "running")


class LogSourceViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        self.server = Server.objects.create(
            name="edge-1",
            hostname="edge1.example.com",
            ssh_username="deploy",
            ssh_auth_type=Server.AuthType.PASSWORD,
            ssh_private_key="pw",
        )
        self.log_source = LogSource.objects.create(
            server=self.server, name="access.log", path="/var/log/nginx/access.log"
        )

    def test_list_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("logs:list"))
        self.assertEqual(response.status_code, 302)

    def test_list_shows_log_source(self):
        response = self.client.get(reverse("logs:list"))
        self.assertContains(response, "/var/log/nginx/access.log")

    def test_toggle_enabled(self):
        self.assertFalse(self.log_source.enabled)
        response = self.client.post(reverse("logs:toggle-enabled", args=[self.log_source.pk]))
        self.log_source.refresh_from_db()
        self.assertTrue(self.log_source.enabled)
        self.assertEqual(response.status_code, 302)

    def test_toggle_enabled_htmx_returns_partial(self):
        response = self.client.post(
            reverse("logs:toggle-enabled", args=[self.log_source.pk]), HTTP_HX_REQUEST="true"
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Monitoring")


class DiscoverServerLogsTaskTests(TestCase):
    def setUp(self):
        self.server = Server.objects.create(
            name="edge-2",
            hostname="edge2.example.com",
            ssh_username="deploy",
            ssh_auth_type=Server.AuthType.PASSWORD,
            ssh_private_key="pw",
        )

    @patch("apps.servers.tasks.SSHService")
    def test_discovery_creates_disabled_log_sources(self, mock_service_cls):
        from apps.servers.services import DiscoveredLogFile
        from apps.servers.tasks import discover_server_logs

        mock_service_cls.return_value.discover_logs.return_value = [
            DiscoveredLogFile(path="/var/log/nginx/access.log", size=10, mtime=0),
            DiscoveredLogFile(path="/var/log/nginx/error.log", size=5, mtime=0),
        ]

        discover_server_logs(self.server.id)

        sources = LogSource.objects.filter(server=self.server).order_by("path")
        self.assertEqual([s.path for s in sources], ["/var/log/nginx/access.log", "/var/log/nginx/error.log"])
        self.assertTrue(all(not s.enabled for s in sources))
        self.server.refresh_from_db()
        self.assertEqual(self.server.last_error, "")
        self.assertIsNotNone(self.server.last_connected_at)

    @patch("apps.servers.tasks.SSHService")
    def test_discovery_does_not_duplicate_existing_sources(self, mock_service_cls):
        from apps.servers.services import DiscoveredLogFile
        from apps.servers.tasks import discover_server_logs

        existing = LogSource.objects.create(
            server=self.server, name="access.log", path="/var/log/nginx/access.log", enabled=True
        )
        mock_service_cls.return_value.discover_logs.return_value = [
            DiscoveredLogFile(path="/var/log/nginx/access.log", size=10, mtime=0),
        ]

        discover_server_logs(self.server.id)

        self.assertEqual(LogSource.objects.filter(server=self.server).count(), 1)
        existing.refresh_from_db()
        self.assertTrue(existing.enabled)  # discovery must not clobber an already-enabled source
