import unittest
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.servers.models import Server
from apps.servers.services import LogChunk

from .models import LogSource
from .services import NginxLogReader

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


class NginxLogReaderTests(TestCase):
    """SSHService is mocked so these test the reader's own logic (line
    splitting, 503 filtering, IP dedup, offset/state bookkeeping) in
    isolation from real SSH/paramiko behavior (covered separately in
    apps.servers.tests.SSHServicePollLogTests)."""

    def setUp(self):
        self.server = Server.objects.create(
            name="edge-reader",
            hostname="edge-reader.example.com",
            ssh_username="deploy",
            ssh_auth_type=Server.AuthType.PASSWORD,
            ssh_private_key="pw",
        )
        self.log_source = LogSource.objects.create(
            server=self.server, name="access.log", path="/var/log/nginx/access.log", enabled=True
        )

    @patch("apps.logs.services.SSHService")
    def test_creates_request_event_for_503_only_and_leaves_partial_line_unconsumed(self, mock_ssh_cls):
        complete = [
            b'1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 503 10 "-" "-"',
            b'5.6.7.8 - - [26/Aug/2026:04:30:01 +0000] "GET /b HTTP/1.1" 200 20 "-" "-"',
        ]
        complete_bytes = b"\n".join(complete) + b"\n"
        partial = b"1.1.1.1 - - [26/Aug/2026:04:30:02 +0000"  # no closing bracket, no newline
        data = complete_bytes + partial
        mock_ssh_cls.return_value.poll_log.return_value = LogChunk(
            inode=111, size=len(data), mtime=0, offset=0, data=data, rotated=False
        )

        summary = NginxLogReader(self.log_source).poll()

        self.assertEqual(summary.events_created, 1)
        self.assertEqual(summary.lines_read, 2)
        self.assertEqual(RequestEvent.objects.count(), 1)
        event = RequestEvent.objects.get()
        self.assertEqual(event.status, 503)
        self.assertEqual(IPAddress.objects.count(), 1)
        self.assertEqual(IPAddress.objects.get().address, "1.2.3.4")

        self.log_source.refresh_from_db()
        self.assertEqual(self.log_source.byte_offset, len(complete_bytes))  # partial line not consumed
        self.assertEqual(self.log_source.inode, 111)
        self.assertIsNotNone(self.log_source.last_read_at)
        self.assertIsNotNone(self.log_source.last_event_at)
        self.assertEqual(self.log_source.last_error, "")

    @patch("apps.logs.services.SSHService")
    def test_dedupes_ip_seen_twice_in_one_batch(self, mock_ssh_cls):
        lines = [
            b'1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 503 10 "-" "-"',
            b'1.2.3.4 - - [26/Aug/2026:04:30:05 +0000] "GET /b HTTP/1.1" 503 10 "-" "-"',
        ]
        data = b"\n".join(lines) + b"\n"
        mock_ssh_cls.return_value.poll_log.return_value = LogChunk(
            inode=111, size=len(data), mtime=0, offset=0, data=data, rotated=False
        )

        NginxLogReader(self.log_source).poll()

        self.assertEqual(IPAddress.objects.count(), 1)
        self.assertEqual(RequestEvent.objects.count(), 2)

    @patch("apps.logs.services.SSHService")
    def test_counts_parse_errors_and_records_last_error(self, mock_ssh_cls):
        data = b"garbage one\ngarbage two\n"
        mock_ssh_cls.return_value.poll_log.return_value = LogChunk(
            inode=111, size=len(data), mtime=0, offset=0, data=data, rotated=False
        )

        summary = NginxLogReader(self.log_source).poll()

        self.assertEqual(summary.parse_errors, 2)
        self.assertEqual(summary.events_created, 0)
        self.log_source.refresh_from_db()
        self.assertIn("2 line(s)", self.log_source.last_error)

    @patch("apps.logs.services.SSHService")
    def test_missing_file_sets_last_error(self, mock_ssh_cls):
        mock_ssh_cls.return_value.poll_log.return_value = None

        summary = NginxLogReader(self.log_source).poll()

        self.assertTrue(summary.file_missing)
        self.log_source.refresh_from_db()
        self.assertIn("not found", self.log_source.last_error)


class PollLogSourceTaskTests(TestCase):
    def setUp(self):
        self.server = Server.objects.create(
            name="edge-task",
            hostname="edge-task.example.com",
            ssh_username="deploy",
            ssh_auth_type=Server.AuthType.PASSWORD,
            ssh_private_key="pw",
        )
        self.log_source = LogSource.objects.create(
            server=self.server, name="access.log", path="/var/log/nginx/access.log", enabled=True
        )

    @patch("apps.logs.tasks.NginxLogReader")
    def test_skips_when_log_source_disabled(self, mock_reader_cls):
        self.log_source.enabled = False
        self.log_source.save()
        from .tasks import poll_log_source

        poll_log_source(self.log_source.id)
        mock_reader_cls.assert_not_called()

    @patch("apps.logs.tasks.NginxLogReader")
    def test_skips_when_server_disabled(self, mock_reader_cls):
        self.server.enabled = False
        self.server.save()
        from .tasks import poll_log_source

        poll_log_source(self.log_source.id)
        mock_reader_cls.assert_not_called()

    @patch("apps.logs.tasks.NginxLogReader")
    def test_polls_when_enabled(self, mock_reader_cls):
        from .services import PollSummary
        from .tasks import poll_log_source

        mock_reader_cls.return_value.poll.return_value = PollSummary(
            events_created=0, parse_errors=0, lines_read=0, rotated=False
        )

        poll_log_source(self.log_source.id)
        mock_reader_cls.assert_called_once()

    @patch("apps.logs.tasks.redis_lock")
    @patch("apps.logs.tasks.NginxLogReader")
    def test_lock_held_skips_poll(self, mock_reader_cls, mock_lock):
        from apps.common.locks import LockHeldError

        from .tasks import poll_log_source

        mock_lock.side_effect = LockHeldError("logreader:x:y")

        poll_log_source(self.log_source.id)  # must not raise
        mock_reader_cls.assert_not_called()
