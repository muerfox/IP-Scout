import hashlib
import shutil
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.common.locks import LockHeldError
from apps.ips.models import IPAddress

from .models import WhoisRecord
from .services import WhoisLookupResult, WhoisService
from .tasks import _guess_whois_server, _inetnum_to_cidr, _parse_asn, _run_lookup

User = get_user_model()

FAKE_WHOIS_SCRIPT = """#!/usr/bin/env python3
import sys, time
ip = sys.argv[1] if len(sys.argv) > 1 else ""
if ip == "9.9.9.9":
    print("inetnum: 9.9.9.0 - 9.9.9.255")
    print("netname: TEST-NET")
    print("country: US")
    print("origin: AS64500")
    sys.exit(0)
if ip == "0.0.0.0":
    sys.exit(1)
if ip == "8.8.8.8":
    time.sleep(5)
    sys.exit(0)
sys.exit(1)
"""


def _write_fake_whois(directory: str) -> Path:
    path = Path(directory) / "whois"
    path.write_text(FAKE_WHOIS_SCRIPT)
    path.chmod(0o755)
    return path


class WhoisServiceTests(unittest.TestCase):
    """Real subprocess execution against a fake `whois` script written at
    test time - no network, no real registry, no DB."""

    fake_whois: Path

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tmpdir = tempfile.mkdtemp()
        cls.fake_whois = _write_fake_whois(cls.tmpdir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        super().tearDownClass()

    def _service(self, timeout: int = 1) -> WhoisService:
        return WhoisService(binary=str(self.fake_whois), timeout=timeout)

    def test_successful_lookup(self):
        result = self._service().lookup("9.9.9.9")
        self.assertTrue(result.success)
        self.assertIn("TEST-NET", result.raw_response)
        self.assertEqual(result.error, "")

    def test_empty_response_is_a_non_retryable_failure(self):
        result = self._service().lookup("0.0.0.0")
        self.assertFalse(result.success)
        self.assertFalse(result.retryable)

    def test_timeout_is_retryable(self):
        result = self._service(timeout=1).lookup("8.8.8.8")
        self.assertFalse(result.success)
        self.assertTrue(result.retryable)
        self.assertIn("timed out", result.error)

    def test_invalid_ip_is_rejected_before_exec(self):
        result = self._service().lookup("not-an-ip")
        self.assertFalse(result.success)
        self.assertFalse(result.retryable)
        self.assertIn("Invalid IP", result.error)

    @patch("apps.whois.services.shutil.which", return_value=None)
    def test_missing_binary_with_no_path_fallback(self, mock_which):
        result = WhoisService(binary="/nonexistent/whois", timeout=1).lookup("9.9.9.9")
        self.assertFalse(result.success)
        self.assertIn("not found", result.error)

    @patch("apps.whois.services.shutil.which")
    def test_resolve_binary_falls_back_to_path_lookup(self, mock_which):
        mock_which.return_value = str(self.fake_whois)
        service = WhoisService(binary="/nonexistent/whois", timeout=1)
        self.assertEqual(service.binary, str(self.fake_whois))

    @patch("apps.whois.services.subprocess.run", side_effect=OSError("permission denied"))
    def test_oserror_spawning_binary_is_retryable(self, mock_run):
        result = self._service().lookup("9.9.9.9")
        self.assertFalse(result.success)
        self.assertTrue(result.retryable)
        self.assertIn("permission denied", result.error)

    def test_response_hash_is_deterministic_sha256(self):
        text = "hello whois"
        self.assertEqual(WhoisService.response_hash(text), hashlib.sha256(text.encode()).hexdigest())


class ParseAsnTests(unittest.TestCase):
    def test_extracts_number_from_as_prefixed_string(self):
        self.assertEqual(_parse_asn("AS12880"), 12880)

    def test_case_insensitive(self):
        self.assertEqual(_parse_asn("as64500"), 64500)

    def test_no_match_returns_none(self):
        self.assertIsNone(_parse_asn("not an asn"))


class InetnumToCidrTests(unittest.TestCase):
    def test_already_cidr_notation(self):
        self.assertEqual(_inetnum_to_cidr("1.2.3.0/24"), "1.2.3.0/24")

    def test_power_of_two_range_summarizes_exactly(self):
        self.assertEqual(_inetnum_to_cidr("5.1.0.0 - 5.1.3.255"), "5.1.0.0/22")

    def test_garbage_returns_none(self):
        self.assertIsNone(_inetnum_to_cidr("not a range"))

    def test_range_with_invalid_endpoint_returns_none(self):
        self.assertIsNone(_inetnum_to_cidr("5.1.0.0 - not-an-ip"))


class GuessWhoisServerTests(unittest.TestCase):
    def test_returns_first_matching_referral_key(self):
        generic = {"whois": ["whois.ripe.net"], "netname": ["TEST-NET"]}
        self.assertEqual(_guess_whois_server(generic), "whois.ripe.net")

    def test_no_referral_key_returns_empty_string(self):
        self.assertEqual(_guess_whois_server({"netname": ["TEST-NET"]}), "")


class PerformWhoisLookupTaskTests(TestCase):
    def setUp(self):
        self.ip = IPAddress.objects.create(
            address="9.9.9.9", version=4, first_seen_at=timezone.now(), last_seen_at=timezone.now()
        )
        self.tmpdir = tempfile.mkdtemp()
        self.fake_whois = _write_fake_whois(self.tmpdir)
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def test_successful_lookup_populates_ip_and_creates_record(self):
        from .tasks import perform_whois_lookup

        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(self.ip.id)

        self.ip.refresh_from_db()
        self.assertEqual(self.ip.whois_status, IPAddress.WhoisStatus.OK)
        self.assertEqual(self.ip.whois_country, "US")
        self.assertEqual(self.ip.network, "TEST-NET")
        self.assertEqual(self.ip.asn, 64500)
        self.assertIsNotNone(self.ip.whois_next_check_at)
        self.assertEqual(WhoisRecord.objects.filter(ip=self.ip).count(), 1)

    @patch("apps.iran.tasks.classify_ip.delay")
    def test_successful_lookup_redispatches_iran_classification(self, mock_classify_delay):
        from .tasks import perform_whois_lookup

        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(self.ip.id)

        mock_classify_delay.assert_called_once_with(self.ip.id)

    def test_skips_when_fresh_and_not_forced(self):
        self.ip.whois_next_check_at = timezone.now() + timedelta(days=1)
        self.ip.save()
        from .tasks import perform_whois_lookup

        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(self.ip.id)

        self.assertEqual(WhoisRecord.objects.count(), 0)

    def test_force_bypasses_freshness_gate(self):
        self.ip.whois_next_check_at = timezone.now() + timedelta(days=1)
        self.ip.save()
        from .tasks import perform_whois_lookup

        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(self.ip.id, force=True)

        self.assertEqual(WhoisRecord.objects.count(), 1)

    def test_permanent_failure_sets_error_status_and_backs_off(self):
        self.ip.address = "0.0.0.0"
        self.ip.save()
        from .tasks import perform_whois_lookup

        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(self.ip.id)

        self.ip.refresh_from_db()
        self.assertEqual(self.ip.whois_status, IPAddress.WhoisStatus.ERROR)
        self.assertTrue(self.ip.whois_error)
        self.assertIsNotNone(self.ip.whois_next_check_at)
        self.assertEqual(WhoisRecord.objects.count(), 0)

    def test_missing_ip_returns_silently(self):
        from .tasks import perform_whois_lookup

        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(999999)

    @patch("apps.whois.tasks.redis_lock")
    def test_lock_held_is_skipped_silently(self, mock_lock):
        from .tasks import perform_whois_lookup

        mock_lock.side_effect = LockHeldError(f"whois:{self.ip.address}")
        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(self.ip.id)  # must not raise
        self.assertEqual(WhoisRecord.objects.count(), 0)

    @patch("apps.whois.tasks.WhoisService")
    def test_retryable_failure_schedules_a_retry(self, mock_service_cls):
        mock_service_cls.return_value.lookup.return_value = WhoisLookupResult(
            success=False, error="whois timed out after 5s", retryable=True
        )
        mock_task = Mock()
        mock_task.request.retries = 0
        mock_task.retry.side_effect = RuntimeError("retry-triggered")

        with self.assertRaises(RuntimeError):
            _run_lookup(mock_task, self.ip)

        mock_task.retry.assert_called_once()
        self.assertEqual(mock_task.retry.call_args.kwargs["countdown"], 30)
        self.assertEqual(WhoisRecord.objects.count(), 0)


class ForceWhoisViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        self.ip = IPAddress.objects.create(
            address="9.9.9.9", version=4, first_seen_at=timezone.now(), last_seen_at=timezone.now()
        )

    def test_requires_login(self):
        self.client.logout()
        response = self.client.post(reverse("ips:force-whois", args=[self.ip.pk]))
        self.assertEqual(response.status_code, 302)

    @patch("apps.whois.tasks.perform_whois_lookup.delay")
    def test_enqueues_forced_lookup_and_redirects(self, mock_delay):
        response = self.client.post(reverse("ips:force-whois", args=[self.ip.pk]))
        mock_delay.assert_called_once_with(self.ip.id, force=True)
        self.assertRedirects(response, reverse("ips:detail", args=[self.ip.pk]))

    @patch("apps.whois.tasks.perform_whois_lookup.delay")
    def test_htmx_request_returns_partial(self, mock_delay):
        response = self.client.post(
            reverse("ips:force-whois", args=[self.ip.pk]), HTTP_HX_REQUEST="true"
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "whois-cell")


class PurgeOldWhoisRecordsTaskTests(TestCase):
    def test_deletes_only_records_older_than_retention(self):
        from .tasks import purge_old_whois_records

        now = timezone.now()
        ip = IPAddress.objects.create(address="1.1.1.1", version=4, first_seen_at=now, last_seen_at=now)
        old_record = WhoisRecord.objects.create(
            ip=ip, queried_at=now - timedelta(days=200), raw_response="old", parsed_data={}
        )
        recent_record = WhoisRecord.objects.create(
            ip=ip, queried_at=now - timedelta(days=1), raw_response="recent", parsed_data={}
        )

        count = purge_old_whois_records()

        self.assertEqual(count, 1)
        remaining = set(WhoisRecord.objects.values_list("id", flat=True))
        self.assertEqual(remaining, {recent_record.id})
        self.assertNotIn(old_record.id, remaining)


class WhoisListViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        now = timezone.now()
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now)
        self.other_ip = IPAddress.objects.create(
            address="9.9.9.9", version=4, first_seen_at=now, last_seen_at=now
        )
        self.record = WhoisRecord.objects.create(
            ip=self.ip, queried_at=now, whois_server="whois.example", raw_response="raw text", parsed_data={}
        )
        WhoisRecord.objects.create(ip=self.other_ip, queried_at=now, raw_response="other", parsed_data={})

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("whois:list"))
        self.assertEqual(response.status_code, 302)

    def test_lists_all_records(self):
        response = self.client.get(reverse("whois:list"))
        self.assertEqual(response.context["page_obj"].paginator.count, 2)

    def test_filters_by_ip(self):
        response = self.client.get(reverse("whois:list"), {"ip": "5.1.1.1"})
        results = list(response.context["page_obj"].object_list)
        self.assertEqual(results, [self.record])


class WhoisDetailViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        now = timezone.now()
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now)
        self.record = WhoisRecord.objects.create(
            ip=self.ip,
            queried_at=now,
            whois_server="whois.example",
            raw_response="inetnum: 5.1.1.0 - 5.1.1.255",
            parsed_data={"country": "IR"},
        )

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("whois:detail", args=[self.record.pk]))
        self.assertEqual(response.status_code, 302)

    def test_shows_raw_response_and_parsed_data(self):
        response = self.client.get(reverse("whois:detail", args=[self.record.pk]))
        self.assertContains(response, "inetnum: 5.1.1.0 - 5.1.1.255")
        self.assertContains(response, "IR")
