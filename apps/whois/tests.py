import hashlib
import shutil
import subprocess
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.common.locks import LockHeldError
from apps.ips.models import IPAddress

from .models import ProxyEndpoint, WhoisRecord
from .services import WhoisLookupResult, WhoisService
from .tasks import MAX_RETRIES, _guess_whois_server, _inetnum_to_cidr, _parse_asn, _run_lookup

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
if ip == "5.1.1.1":
    print("inetnum: 5.1.0.0 - 5.1.3.255")
    print("netname: IRAN-NET")
    print("country: IR")
    print("origin: AS12880")
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

    @patch("apps.whois.services.shutil.which")
    @patch("apps.whois.services.subprocess.run")
    def test_lookup_with_proxy_wraps_via_proxychains(self, mock_run, mock_which):
        mock_which.return_value = "/usr/bin/proxychains4"
        captured = {}

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["conf"] = Path(argv[2]).read_text()
            return subprocess.CompletedProcess(argv, 0, stdout="inetnum: 1.2.3.0/24\n", stderr="")

        mock_run.side_effect = fake_run
        proxy = ProxyEndpoint(scheme="socks5", host="10.0.0.5", port=1080, username="u", password="p")

        result = self._service().lookup("9.9.9.9", proxy=proxy)

        self.assertTrue(result.success)
        argv = captured["argv"]
        self.assertEqual(argv[0], "/usr/bin/proxychains4")
        self.assertEqual(argv[1], "-f")
        self.assertEqual(argv[3], "-q")
        self.assertEqual(argv[4:], [str(self.fake_whois), "9.9.9.9"])
        self.assertIn("socks5 10.0.0.5 1080 u p", captured["conf"])
        self.assertFalse(Path(argv[2]).exists())  # conf file cleaned up after the call

    @patch("apps.whois.services.shutil.which")
    def test_lookup_with_proxy_and_no_proxychains_binary_errors(self, mock_which):
        mock_which.return_value = None
        proxy = ProxyEndpoint(scheme="socks5", host="10.0.0.5", port=1080)

        result = self._service().lookup("9.9.9.9", proxy=proxy)

        self.assertFalse(result.success)
        self.assertIn("proxychains", result.error)
        self.assertFalse(result.retryable)

    def test_write_proxychains_conf_socks5h_enables_proxy_dns(self):
        proxy = ProxyEndpoint(scheme="socks5h", host="proxy.example.com", port=1080)
        conf_path = WhoisService._write_proxychains_conf(proxy)
        try:
            content = conf_path.read_text()
            self.assertIn("proxy_dns", content)
            self.assertIn("socks5 proxy.example.com 1080", content)  # socks5h -> socks5 proxy type
            self.assertEqual(conf_path.stat().st_mode & 0o777, 0o600)
        finally:
            conf_path.unlink(missing_ok=True)

    def test_write_proxychains_conf_without_auth_omits_credentials(self):
        proxy = ProxyEndpoint(scheme="socks4", host="proxy.example.com", port=9050)
        conf_path = WhoisService._write_proxychains_conf(proxy)
        try:
            content = conf_path.read_text()
            self.assertIn("socks4 proxy.example.com 9050\n", content)
        finally:
            conf_path.unlink(missing_ok=True)


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


class ProxyPoolTests(TestCase):
    def test_pick_returns_none_when_no_proxies(self):
        from .proxies import ProxyPool

        self.assertIsNone(ProxyPool.pick())

    def test_pick_ignores_disabled_proxies(self):
        from .proxies import ProxyPool

        ProxyEndpoint.objects.create(host="p1", port=1080, enabled=False)

        self.assertIsNone(ProxyPool.pick())

    def test_pick_returns_least_recently_used(self):
        from .proxies import ProxyPool

        older = ProxyEndpoint.objects.create(
            host="p1", port=1080, last_used_at=timezone.now() - timedelta(hours=1)
        )
        ProxyEndpoint.objects.create(host="p2", port=1080, last_used_at=timezone.now())

        self.assertEqual(ProxyPool.pick(), older)

    def test_pick_prefers_never_used_proxy(self):
        from .proxies import ProxyPool

        ProxyEndpoint.objects.create(host="p1", port=1080, last_used_at=timezone.now())
        never_used = ProxyEndpoint.objects.create(host="p2", port=1080, last_used_at=None)

        self.assertEqual(ProxyPool.pick(), never_used)

    def test_record_result_success_resets_failure_count(self):
        from .proxies import ProxyPool

        proxy = ProxyEndpoint.objects.create(host="p1", port=1080, consecutive_failures=2)

        ProxyPool.record_result(proxy, success=True)

        proxy.refresh_from_db()
        self.assertEqual(proxy.consecutive_failures, 0)
        self.assertIsNotNone(proxy.last_success_at)
        self.assertEqual(proxy.total_uses, 1)
        self.assertTrue(proxy.enabled)

    def test_record_result_failure_increments_count(self):
        from .proxies import ProxyPool

        proxy = ProxyEndpoint.objects.create(host="p1", port=1080)

        ProxyPool.record_result(proxy, success=False, error="connection refused")

        proxy.refresh_from_db()
        self.assertEqual(proxy.consecutive_failures, 1)
        self.assertEqual(proxy.last_error, "connection refused")
        self.assertTrue(proxy.enabled)

    @override_settings(WHOIS_PROXY_MAX_FAILURES=2)
    def test_record_result_disables_after_max_failures(self):
        from .proxies import ProxyPool

        proxy = ProxyEndpoint.objects.create(host="p1", port=1080)

        ProxyPool.record_result(proxy, success=False, error="timeout")
        ProxyPool.record_result(proxy, success=False, error="timeout")

        proxy.refresh_from_db()
        self.assertEqual(proxy.consecutive_failures, 2)
        self.assertFalse(proxy.enabled)


class RunLookupProxyWiringTests(TestCase):
    """_run_lookup's use of ProxyPool, isolated from the real WhoisService
    subprocess call (covered separately in WhoisServiceTests)."""

    def setUp(self):
        self.ip = IPAddress.objects.create(
            address="9.9.9.9", version=4, first_seen_at=timezone.now(), last_seen_at=timezone.now()
        )

    @patch("apps.whois.tasks.ProxyPool")
    @patch("apps.whois.tasks.WhoisService")
    def test_no_proxy_configured_calls_lookup_without_one(self, mock_service_cls, mock_pool):
        mock_pool.pick.return_value = None
        mock_service_cls.return_value.lookup.return_value = WhoisLookupResult(
            success=False, error="whois exited 1 with no output"
        )
        mock_task = Mock()
        mock_task.request.retries = MAX_RETRIES

        _run_lookup(mock_task, self.ip)

        mock_service_cls.return_value.lookup.assert_called_once_with(self.ip.address, proxy=None)
        mock_pool.record_result.assert_not_called()

    @patch("apps.whois.tasks.ProxyPool")
    @patch("apps.whois.tasks.WhoisService")
    def test_proxy_configured_is_used_and_result_recorded(self, mock_service_cls, mock_pool):
        proxy = ProxyEndpoint(host="p1", port=1080)
        mock_pool.pick.return_value = proxy
        mock_service_cls.return_value.lookup.return_value = WhoisLookupResult(
            success=False, error="proxy connection refused"
        )
        mock_task = Mock()
        mock_task.request.retries = MAX_RETRIES

        _run_lookup(mock_task, self.ip)

        mock_service_cls.return_value.lookup.assert_called_once_with(self.ip.address, proxy=proxy)
        mock_pool.record_result.assert_called_once_with(proxy, False, "proxy connection refused")


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

    def test_successful_lookup_records_observed_network(self):
        from .models import ObservedNetwork
        from .tasks import perform_whois_lookup

        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(self.ip.id)

        network = ObservedNetwork.objects.get(cidr="9.9.9.0/24")
        self.assertEqual(network.country_code, "US")
        self.assertEqual(network.network, "TEST-NET")
        self.assertEqual(network.asn, 64500)
        self.assertEqual(network.hit_count, 1)

    def test_repeated_lookup_increments_hit_count_on_same_network(self):
        from .models import ObservedNetwork
        from .tasks import perform_whois_lookup

        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(self.ip.id, force=True)
            perform_whois_lookup(self.ip.id, force=True)

        network = ObservedNetwork.objects.get(cidr="9.9.9.0/24")
        self.assertEqual(network.hit_count, 2)

    def test_iran_whois_country_mirrors_cidr_into_country_networks(self):
        from apps.iran.models import CountryNetwork

        from .tasks import perform_whois_lookup

        iran_ip = IPAddress.objects.create(
            address="5.1.1.1", version=4, first_seen_at=timezone.now(), last_seen_at=timezone.now()
        )
        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(iran_ip.id)

        row = CountryNetwork.objects.get(country_code="IR", cidr="5.1.0.0/22")
        self.assertEqual(row.source, "whois")
        self.assertTrue(row.enabled)

        iran_ip.refresh_from_db()
        self.assertTrue(iran_ip.is_iran)  # classify_ip re-dispatch should pick up the new CIDR row too

    def test_iran_mirror_does_not_override_an_existing_manual_entry(self):
        from apps.iran.models import CountryNetwork

        from .tasks import perform_whois_lookup

        CountryNetwork.objects.create(
            country_code="IR", cidr="5.1.0.0/22", source="manual", enabled=False
        )
        iran_ip = IPAddress.objects.create(
            address="5.1.1.1", version=4, first_seen_at=timezone.now(), last_seen_at=timezone.now()
        )
        with self.settings(WHOIS_BINARY=str(self.fake_whois)):
            perform_whois_lookup(iran_ip.id)

        row = CountryNetwork.objects.get(country_code="IR", cidr="5.1.0.0/22")
        self.assertEqual(row.source, "manual")  # untouched - whois never overrides another source
        self.assertFalse(row.enabled)

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


class NetworkIntelServiceTests(TestCase):
    def test_record_creates_new_network(self):
        from .models import ObservedNetwork
        from .network_intel import NetworkIntelService

        now = timezone.now()
        obj = NetworkIntelService.record(
            "1.2.3.0/24",
            country_code="US",
            organization="Example Org",
            network="EXAMPLE-NET",
            asn=64500,
            seen_at=now,
        )

        self.assertEqual(obj.hit_count, 1)
        self.assertEqual(ObservedNetwork.objects.count(), 1)

    def test_record_updates_existing_network_and_increments_hit_count(self):
        from .network_intel import NetworkIntelService

        first_seen = timezone.now() - timedelta(days=1)
        NetworkIntelService.record(
            "1.2.3.0/24", country_code="US", organization="", network="", asn=None, seen_at=first_seen
        )

        second_seen = timezone.now()
        obj = NetworkIntelService.record(
            "1.2.3.0/24",
            country_code="US",
            organization="Example Org",
            network="EXAMPLE-NET",
            asn=64500,
            seen_at=second_seen,
        )

        self.assertEqual(obj.hit_count, 2)
        self.assertEqual(obj.organization, "Example Org")
        self.assertEqual(obj.first_seen_at, first_seen)
        self.assertEqual(obj.last_seen_at, second_seen)

    def test_record_does_not_touch_country_networks_for_non_iran(self):
        from apps.iran.models import CountryNetwork

        from .network_intel import NetworkIntelService

        NetworkIntelService.record(
            "1.2.3.0/24", country_code="US", organization="", network="", asn=None, seen_at=timezone.now()
        )

        self.assertEqual(CountryNetwork.objects.count(), 0)


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


class NetworkListViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("whois:networks"))
        self.assertEqual(response.status_code, 302)

    def test_empty_state(self):
        response = self.client.get(reverse("whois:networks"))
        self.assertContains(response, "No networks observed yet")

    def test_lists_and_filters_by_country(self):
        from .network_intel import NetworkIntelService

        NetworkIntelService.record(
            "5.1.0.0/22", country_code="IR", organization="", network="IRAN-NET", asn=None,
            seen_at=timezone.now(),
        )
        NetworkIntelService.record(
            "9.9.9.0/24", country_code="US", organization="", network="TEST-NET", asn=None,
            seen_at=timezone.now(),
        )

        response = self.client.get(reverse("whois:networks"))
        self.assertContains(response, "5.1.0.0/22")
        self.assertContains(response, "9.9.9.0/24")

        response = self.client.get(reverse("whois:networks"), {"country": "ir"})
        self.assertContains(response, "5.1.0.0/22")
        self.assertNotContains(response, "9.9.9.0/24")


class ProxyListViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("whois:proxies"))
        self.assertEqual(response.status_code, 302)

    def test_empty_state(self):
        response = self.client.get(reverse("whois:proxies"))
        self.assertContains(response, "No proxies configured")

    def test_lists_configured_proxy(self):
        ProxyEndpoint.objects.create(label="edge-proxy", host="10.0.0.5", port=1080)
        response = self.client.get(reverse("whois:proxies"))
        self.assertContains(response, "edge-proxy")
        self.assertContains(response, "10.0.0.5")


class ProxyCreateViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("whois:proxy-add"))
        self.assertEqual(response.status_code, 302)

    def test_get_renders_form(self):
        response = self.client.get(reverse("whois:proxy-add"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Add Proxy")

    def test_post_creates_proxy(self):
        response = self.client.post(
            reverse("whois:proxy-add"),
            {
                "label": "edge-proxy",
                "scheme": "socks5",
                "host": "10.0.0.5",
                "port": 1080,
                "username": "",
                "password": "",
                "enabled": "on",
            },
        )
        self.assertRedirects(response, reverse("whois:proxies"))
        proxy = ProxyEndpoint.objects.get(label="edge-proxy")
        self.assertEqual(proxy.host, "10.0.0.5")
        self.assertEqual(proxy.port, 1080)

    def test_post_invalid_missing_host_reshows_form(self):
        response = self.client.post(
            reverse("whois:proxy-add"),
            {"label": "bad", "scheme": "socks5", "host": "", "port": 1080},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ProxyEndpoint.objects.count(), 0)


class ProxyToggleEnabledViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        self.proxy = ProxyEndpoint.objects.create(host="10.0.0.5", port=1080, enabled=True)

    def test_disable_then_enable_resets_failure_count(self):
        self.proxy.consecutive_failures = 3
        self.proxy.save()

        response = self.client.post(reverse("whois:proxy-toggle-enabled", args=[self.proxy.pk]))
        self.proxy.refresh_from_db()
        self.assertFalse(self.proxy.enabled)
        self.assertEqual(response.status_code, 302)

        self.client.post(reverse("whois:proxy-toggle-enabled", args=[self.proxy.pk]))
        self.proxy.refresh_from_db()
        self.assertTrue(self.proxy.enabled)
        self.assertEqual(self.proxy.consecutive_failures, 0)

    def test_htmx_request_returns_partial(self):
        response = self.client.post(
            reverse("whois:proxy-toggle-enabled", args=[self.proxy.pk]), HTTP_HX_REQUEST="true"
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Disabled")
