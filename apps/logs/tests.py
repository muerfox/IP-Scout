import unittest
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.common.locks import LockHeldError
from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.servers.models import Server
from apps.servers.services import LogChunk, SSHConnectionError

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

    def test_readers_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("logs:readers"))
        self.assertEqual(response.status_code, 302)

    def test_readers_shows_incremental_state(self):
        self.log_source.inode = 12345
        self.log_source.byte_offset = 9876
        self.log_source.save()
        response = self.client.get(reverse("logs:readers"))
        self.assertContains(response, "12345")
        self.assertContains(response, "9876")

    @patch("apps.logs.tasks.poll_log_source.delay")
    def test_poll_now_queues_task_and_redirects(self, mock_delay):
        response = self.client.post(reverse("logs:poll-now", args=[self.log_source.pk]))
        mock_delay.assert_called_once_with(self.log_source.id)
        self.assertRedirects(response, reverse("logs:readers"))

    @patch("apps.logs.tasks.poll_log_source.delay")
    def test_poll_now_requires_post(self, mock_delay):
        response = self.client.get(reverse("logs:poll-now", args=[self.log_source.pk]))
        self.assertEqual(response.status_code, 405)
        mock_delay.assert_not_called()


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

    def test_missing_server_returns_silently(self):
        from apps.servers.tasks import discover_server_logs

        discover_server_logs(999999)  # must not raise

    @patch("apps.servers.tasks.SSHService")
    def test_ssh_connection_error_sets_last_error_and_records_failure(self, mock_service_cls):
        from apps.servers.tasks import discover_server_logs
        from apps.users.models import AuditLogEntry

        mock_service_cls.return_value.discover_logs.side_effect = SSHConnectionError("auth failed")

        discover_server_logs(self.server.id)

        self.server.refresh_from_db()
        self.assertEqual(self.server.last_error, "auth failed")
        self.assertEqual(LogSource.objects.filter(server=self.server).count(), 0)

        entry = AuditLogEntry.objects.get(action="server.discover_logs")
        self.assertEqual(entry.result, AuditLogEntry.Result.FAILURE)
        self.assertEqual(entry.metadata["error"], "auth failed")

    @patch("apps.servers.tasks.redis_lock")
    def test_lock_held_is_skipped_silently(self, mock_lock):
        from apps.servers.tasks import discover_server_logs

        mock_lock.side_effect = LockHeldError(f"ssh:discover:{self.server.id}")
        discover_server_logs(self.server.id)  # must not raise
        self.assertEqual(LogSource.objects.filter(server=self.server).count(), 0)


class NginxLogReaderTests(TestCase):
    """SSHService is mocked so these test the reader's own logic (line
    splitting, IP dedup, offset/state bookkeeping) in isolation from real
    SSH/paramiko behavior (covered separately in
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
    def test_creates_request_event_for_every_status_and_leaves_partial_line_unconsumed(self, mock_ssh_cls):
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

        self.assertEqual(summary.events_created, 2)
        self.assertEqual(summary.lines_read, 2)
        self.assertEqual(RequestEvent.objects.count(), 2)
        statuses = set(RequestEvent.objects.values_list("status", flat=True))
        self.assertEqual(statuses, {503, 200})
        self.assertEqual(IPAddress.objects.count(), 2)
        self.assertEqual(
            set(IPAddress.objects.values_list("address", flat=True)), {"1.2.3.4", "5.6.7.8"}
        )

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

    def test_missing_log_source_returns_silently(self):
        from .tasks import poll_log_source

        poll_log_source(999999)  # must not raise

    @patch("apps.logs.tasks.NginxLogReader")
    def test_polls_and_logs_rotation(self, mock_reader_cls):
        from .services import PollSummary
        from .tasks import poll_log_source

        mock_reader_cls.return_value.poll.return_value = PollSummary(
            events_created=0, parse_errors=0, lines_read=0, rotated=True
        )

        poll_log_source(self.log_source.id)  # must not raise; exercises the rotated-log branch

    @patch("apps.logs.tasks.NginxLogReader")
    def test_polls_and_logs_events_created(self, mock_reader_cls):
        from .services import PollSummary
        from .tasks import poll_log_source

        mock_reader_cls.return_value.poll.return_value = PollSummary(
            events_created=5, parse_errors=0, lines_read=10, rotated=False
        )

        poll_log_source(self.log_source.id)  # must not raise; exercises the events-created branch


class PollAllLogSourcesTaskTests(TestCase):
    def setUp(self):
        self.server = Server.objects.create(
            name="edge-fanout",
            hostname="edge-fanout.example.com",
            ssh_username="deploy",
            ssh_auth_type=Server.AuthType.PASSWORD,
            ssh_private_key="pw",
        )

    @patch("apps.logs.tasks.poll_log_source.delay")
    def test_dispatches_one_task_per_enabled_source(self, mock_delay):
        from .tasks import poll_all_log_sources

        enabled = LogSource.objects.create(
            server=self.server, name="access.log", path="/var/log/nginx/access.log", enabled=True
        )
        LogSource.objects.create(
            server=self.server, name="disabled.log", path="/var/log/nginx/disabled.log", enabled=False
        )

        poll_all_log_sources()

        mock_delay.assert_called_once_with(enabled.id)

    @patch("apps.logs.tasks.poll_log_source.delay")
    def test_skips_sources_on_disabled_server(self, mock_delay):
        from .tasks import poll_all_log_sources

        self.server.enabled = False
        self.server.save()
        LogSource.objects.create(
            server=self.server, name="access.log", path="/var/log/nginx/access.log", enabled=True
        )

        poll_all_log_sources()

        mock_delay.assert_not_called()


class ManualLogUploadServiceTests(TestCase):
    def test_ingest_records_every_status_and_creates_manual_server(self):
        from apps.servers.models import Server

        from .services import MANUAL_UPLOAD_SERVER_NAME, ManualLogUploadService

        text = "\n".join(
            [
                '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 503 10 "-" "-"',
                '5.6.7.8 - - [26/Aug/2026:04:30:01 +0000] "GET /b HTTP/1.1" 200 20 "-" "-"',
                "garbage line that will not parse",
            ]
        )

        summary = ManualLogUploadService.ingest(text, "combined", label="test-upload")

        self.assertEqual(summary.lines_read, 3)
        self.assertEqual(summary.events_created, 2)
        self.assertEqual(summary.parse_errors, 1)
        self.assertEqual(summary.new_ips, 2)
        self.assertFalse(summary.truncated)

        self.assertEqual(RequestEvent.objects.count(), 2)
        self.assertEqual(
            set(RequestEvent.objects.values_list("status", flat=True)), {503, 200}
        )

        server = Server.objects.get(name=MANUAL_UPLOAD_SERVER_NAME)
        self.assertFalse(server.enabled)
        log_source = LogSource.objects.get(server=server, name="test-upload")
        self.assertEqual(log_source.format, "combined")
        self.assertFalse(log_source.enabled)
        self.assertEqual(log_source.last_error, "1 line(s) failed to parse")

    def test_ingest_reuses_the_same_manual_server_across_uploads(self):
        from apps.servers.models import Server

        from .services import ManualLogUploadService

        ManualLogUploadService.ingest(
            '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"', "combined"
        )
        ManualLogUploadService.ingest(
            '5.6.7.8 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"', "combined"
        )

        self.assertEqual(Server.objects.filter(name="Manual Uploads").count(), 1)
        self.assertEqual(LogSource.objects.filter(server__name="Manual Uploads").count(), 2)

    def test_ingest_does_not_duplicate_an_ip_seen_twice(self):
        from .services import ManualLogUploadService

        text = "\n".join(
            [
                '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"',
                '1.2.3.4 - - [26/Aug/2026:04:30:05 +0000] "GET /b HTTP/1.1" 200 1 "-" "-"',
            ]
        )

        summary = ManualLogUploadService.ingest(text, "combined")

        self.assertEqual(summary.new_ips, 1)
        self.assertEqual(IPAddress.objects.count(), 1)
        self.assertEqual(RequestEvent.objects.count(), 2)

    def test_ingest_truncates_at_max_lines(self):
        from . import services

        with patch.object(services, "MAX_UPLOAD_LINES", 1):
            text = "\n".join(
                [
                    '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"',
                    '5.6.7.8 - - [26/Aug/2026:04:30:00 +0000] "GET /b HTTP/1.1" 200 1 "-" "-"',
                ]
            )
            summary = services.ManualLogUploadService.ingest(text, "combined")

        self.assertTrue(summary.truncated)
        self.assertEqual(summary.lines_read, 1)
        self.assertEqual(RequestEvent.objects.count(), 1)

    def test_ingest_with_no_parseable_lines_creates_no_events(self):
        from .services import ManualLogUploadService

        summary = ManualLogUploadService.ingest("garbage\nmore garbage", "combined")

        self.assertEqual(summary.events_created, 0)
        self.assertEqual(summary.parse_errors, 2)
        self.assertEqual(RequestEvent.objects.count(), 0)


class LogUploadViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="uploader", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("logs:upload"))
        self.assertEqual(response.status_code, 302)

    def test_get_renders_form(self):
        response = self.client.get(reverse("logs:upload"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Upload Log")

    def test_post_pasted_text_creates_events(self):
        response = self.client.post(
            reverse("logs:upload"),
            {
                "format": "combined",
                "label": "my-upload",
                "logtext": '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"',
            },
        )
        self.assertEqual(RequestEvent.objects.count(), 1)
        self.assertEqual(IPAddress.objects.get().address, "1.2.3.4")
        log_source = LogSource.objects.get()
        self.assertRedirects(response, reverse("logs:upload-results", args=[log_source.pk]))

    def test_post_empty_shows_error_and_creates_nothing(self):
        response = self.client.post(reverse("logs:upload"), {"format": "combined", "logtext": "   "})
        self.assertRedirects(response, reverse("logs:upload"))
        self.assertEqual(RequestEvent.objects.count(), 0)

    def test_post_file_upload_creates_events(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        content = b'9.9.9.9 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 503 1 "-" "-"'
        upload = SimpleUploadedFile("access.log", content)

        response = self.client.post(
            reverse("logs:upload"), {"format": "combined", "logfile": upload}
        )
        self.assertEqual(RequestEvent.objects.count(), 1)
        log_source = LogSource.objects.get()
        self.assertEqual(log_source.name, "access.log")
        self.assertRedirects(response, reverse("logs:upload-results", args=[log_source.pk]))

    def test_post_no_lines_match_format_shows_warning(self):
        response = self.client.post(
            reverse("logs:upload"), {"format": "combined", "logtext": "not a real log line"}
        )
        response = self.client.get(response.url)
        self.assertContains(response, "No lines matched format")
        self.assertEqual(RequestEvent.objects.count(), 0)

    def test_post_truncated_shows_warning(self):
        from . import services

        with patch.object(services, "MAX_UPLOAD_LINES", 1):
            response = self.client.post(
                reverse("logs:upload"),
                {
                    "format": "combined",
                    "logtext": "\n".join(
                        [
                            '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"',
                            '5.6.7.8 - - [26/Aug/2026:04:30:00 +0000] "GET /b HTTP/1.1" 200 1 "-" "-"',
                        ]
                    ),
                },
            )
            response = self.client.get(response.url)
        self.assertContains(response, "were processed (upload was larger)")

    def test_post_truncated_but_no_events_created_stays_on_upload_page(self):
        from . import services

        with patch.object(services, "MAX_UPLOAD_LINES", 1):
            response = self.client.post(
                reverse("logs:upload"),
                {"format": "combined", "logtext": "garbage one\ngarbage two"},
            )
        self.assertRedirects(response, reverse("logs:upload"))


class LogUploadResultsViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="results-viewer", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        server = Server.objects.create(
            name="edge-r", hostname="r.example.com", ssh_username="deploy",
            ssh_auth_type=Server.AuthType.PASSWORD, ssh_private_key="pw",
        )
        log_source = LogSource.objects.create(server=server, name="x", path="manual-upload://x")
        response = self.client.get(reverse("logs:upload-results", args=[log_source.pk]))
        self.assertEqual(response.status_code, 302)

    def test_404_for_unknown_log_source(self):
        response = self.client.get(reverse("logs:upload-results", args=[999999]))
        self.assertEqual(response.status_code, 404)

    def test_shows_extracted_ips_and_iran_count(self):
        from .services import ManualLogUploadService

        text = "\n".join(
            [
                '1.2.3.4 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"',
                '5.6.7.8 - - [26/Aug/2026:04:30:01 +0000] "GET /b HTTP/1.1" 200 1 "-" "-"',
            ]
        )
        summary = ManualLogUploadService.ingest(text, "combined", label="test")
        IPAddress.objects.filter(address="1.2.3.4").update(is_iran=True, country_code="IR")

        response = self.client.get(reverse("logs:upload-results", args=[summary.log_source_id]))

        self.assertContains(response, "1.2.3.4")
        self.assertContains(response, "5.6.7.8")
        self.assertContains(response, "1 Iranian")

    def test_only_shows_ips_from_this_upload(self):
        from .services import ManualLogUploadService

        summary_a = ManualLogUploadService.ingest(
            '1.1.1.1 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"', "combined"
        )
        ManualLogUploadService.ingest(
            '2.2.2.2 - - [26/Aug/2026:04:30:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "-"', "combined"
        )

        response = self.client.get(reverse("logs:upload-results", args=[summary_a.log_source_id]))

        self.assertContains(response, "1.1.1.1")
        self.assertNotContains(response, "2.2.2.2")
