import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import IPAddress
from .services import IPIntelligenceService, normalize_ip

User = get_user_model()


class NormalizeIpTests(unittest.TestCase):
    """Pure function - no DB needed."""

    def test_ipv4_passthrough(self):
        self.assertEqual(normalize_ip("1.2.3.4"), "1.2.3.4")

    def test_ipv6_compressed(self):
        self.assertEqual(normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1")

    def test_strips_whitespace(self):
        self.assertEqual(normalize_ip("  1.2.3.4  "), "1.2.3.4")

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            normalize_ip("not-an-ip")


class NeedsWhoisCheckTests(unittest.TestCase):
    """Pure function against an in-memory (unsaved) IPAddress - no DB needed."""

    def test_never_checked_needs_check(self):
        ip = IPAddress(whois_next_check_at=None)
        self.assertTrue(IPIntelligenceService.needs_whois_check(ip))

    def test_expired_needs_check(self):
        ip = IPAddress(whois_next_check_at=timezone.now() - timedelta(days=1))
        self.assertTrue(IPIntelligenceService.needs_whois_check(ip))

    def test_fresh_does_not_need_check(self):
        ip = IPAddress(whois_next_check_at=timezone.now() + timedelta(days=1))
        self.assertFalse(IPIntelligenceService.needs_whois_check(ip))

    def test_exactly_at_boundary_needs_check(self):
        now = timezone.now()
        ip = IPAddress(whois_next_check_at=now)
        with patch("apps.ips.services.timezone.now", return_value=now):
            self.assertTrue(IPIntelligenceService.needs_whois_check(ip))


T0 = datetime(2026, 8, 26, 4, 30, tzinfo=UTC)


class IPIntelligenceServiceTests(TestCase):
    def setUp(self):
        # Isolate dedup/bookkeeping tests from the process_new_ip task
        # pipeline (CELERY_TASK_ALWAYS_EAGER runs .delay() in-process in
        # tests) - dispatch behavior itself is covered separately below.
        patcher = patch("apps.ips.tasks.process_new_ip.delay")
        self.mock_delay = patcher.start()
        self.addCleanup(patcher.stop)

    def test_creates_new_ip_on_first_sighting(self):
        ip_obj = IPIntelligenceService.record_sighting("1.2.3.4", T0)
        self.assertEqual(ip_obj.address, "1.2.3.4")
        self.assertEqual(ip_obj.version, 4)
        self.assertEqual(ip_obj.first_seen_at, T0)
        self.assertEqual(ip_obj.last_seen_at, T0)
        self.assertEqual(IPAddress.objects.count(), 1)

    def test_second_sighting_updates_last_seen_not_first_seen(self):
        IPIntelligenceService.record_sighting("1.2.3.4", T0)
        later = T0 + timedelta(hours=1)
        ip_obj = IPIntelligenceService.record_sighting("1.2.3.4", later)

        self.assertEqual(IPAddress.objects.count(), 1)
        self.assertEqual(ip_obj.first_seen_at, T0)
        self.assertEqual(ip_obj.last_seen_at, later)

    def test_earlier_sighting_does_not_regress_last_seen(self):
        later = T0 + timedelta(hours=1)
        IPIntelligenceService.record_sighting("1.2.3.4", later)
        ip_obj = IPIntelligenceService.record_sighting("1.2.3.4", T0)

        ip_obj.refresh_from_db()
        self.assertEqual(ip_obj.last_seen_at, later)

    def test_bulk_dedupes_same_ip_within_one_batch(self):
        sightings = [("1.2.3.4", T0), ("1.2.3.4", T0 + timedelta(minutes=5))]
        result = IPIntelligenceService.record_sightings_bulk(sightings)

        self.assertEqual(IPAddress.objects.count(), 1)
        self.assertEqual(result["1.2.3.4"].last_seen_at, T0 + timedelta(minutes=5))

    def test_bulk_creates_multiple_distinct_ips(self):
        sightings = [("1.2.3.4", T0), ("5.6.7.8", T0), ("::1", T0)]
        result = IPIntelligenceService.record_sightings_bulk(sightings)

        self.assertEqual(IPAddress.objects.count(), 3)
        self.assertEqual(set(result.keys()), {"1.2.3.4", "5.6.7.8", "::1"})
        self.assertEqual(result["::1"].version, 6)

    def test_empty_batch_returns_empty_dict(self):
        self.assertEqual(IPIntelligenceService.record_sightings_bulk([]), {})

    def test_dispatches_process_new_ip_for_new_ip_only(self):
        IPIntelligenceService.record_sighting("1.2.3.4", T0)
        self.mock_delay.assert_called_once()
        ip = IPAddress.objects.get(address="1.2.3.4")
        self.mock_delay.assert_called_once_with(ip.id)

        self.mock_delay.reset_mock()
        IPIntelligenceService.record_sighting("1.2.3.4", T0 + timedelta(hours=1))
        self.mock_delay.assert_not_called()

    def test_dispatches_once_per_new_ip_in_a_batch(self):
        IPIntelligenceService.record_sightings_bulk([("1.2.3.4", T0), ("5.6.7.8", T0)])
        self.assertEqual(self.mock_delay.call_count, 2)


class WhoisPendingQuerysetTests(TestCase):
    def test_includes_never_checked_and_expired_excludes_fresh(self):
        IPAddress.objects.create(address="1.1.1.1", version=4, first_seen_at=T0, last_seen_at=T0)
        IPAddress.objects.create(
            address="2.2.2.2",
            version=4,
            first_seen_at=T0,
            last_seen_at=T0,
            whois_next_check_at=timezone.now() - timedelta(days=1),
        )
        IPAddress.objects.create(
            address="3.3.3.3",
            version=4,
            first_seen_at=T0,
            last_seen_at=T0,
            whois_next_check_at=timezone.now() + timedelta(days=1),
        )

        pending = set(IPIntelligenceService.whois_pending_queryset().values_list("address", flat=True))
        self.assertEqual(pending, {"1.1.1.1", "2.2.2.2"})


class ProcessNewIpTaskTests(TestCase):
    def setUp(self):
        self.ip = IPAddress.objects.create(
            address="1.2.3.4", version=4, first_seen_at=T0, last_seen_at=T0
        )

    def test_runs_without_error_when_check_needed(self):
        from .tasks import process_new_ip

        process_new_ip(self.ip.id)  # whois_next_check_at is None -> needs check; must not raise

    def test_missing_ip_returns_silently(self):
        from .tasks import process_new_ip

        process_new_ip(999999)

    @patch("apps.ips.tasks.redis_lock")
    def test_lock_held_is_skipped_silently(self, mock_lock):
        from apps.common.locks import LockHeldError

        from .tasks import process_new_ip

        mock_lock.side_effect = LockHeldError(f"ip:process:{self.ip.address}")
        process_new_ip(self.ip.id)

    @patch("apps.iran.tasks.classify_ip.delay")
    def test_dispatches_iran_classification_unconditionally(self, mock_classify_delay):
        from .tasks import process_new_ip

        process_new_ip(self.ip.id)
        # Dispatched directly here, and (in this eager-task test setup)
        # a second time from apps.whois.tasks._run_lookup once the
        # parallel WHOIS lookup completes and sets whois_country - see
        # IranCIDRService.classify's whois fallback. Either way it must
        # run at least once with this IP.
        mock_classify_delay.assert_any_call(self.ip.id)


class IpListViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("ips:list"))
        self.assertEqual(response.status_code, 302)

    def test_lists_ip(self):
        IPAddress.objects.create(address="1.2.3.4", version=4, first_seen_at=T0, last_seen_at=T0)
        response = self.client.get(reverse("ips:list"))
        self.assertContains(response, "1.2.3.4")

    def test_search_filters_by_address(self):
        IPAddress.objects.create(address="1.2.3.4", version=4, first_seen_at=T0, last_seen_at=T0)
        IPAddress.objects.create(address="5.6.7.8", version=4, first_seen_at=T0, last_seen_at=T0)
        response = self.client.get(reverse("ips:list"), {"q": "1.2.3"})
        self.assertContains(response, "1.2.3.4")
        self.assertNotContains(response, "5.6.7.8")

    def test_is_iran_filter(self):
        IPAddress.objects.create(
            address="1.2.3.4", version=4, first_seen_at=T0, last_seen_at=T0, is_iran=True
        )
        IPAddress.objects.create(address="5.6.7.8", version=4, first_seen_at=T0, last_seen_at=T0)
        response = self.client.get(reverse("ips:list"), {"is_iran": "true"})
        self.assertContains(response, "1.2.3.4")
        self.assertNotContains(response, "5.6.7.8")

    def test_cidr_filter(self):
        IPAddress.objects.create(address="1.2.3.4", version=4, first_seen_at=T0, last_seen_at=T0)
        IPAddress.objects.create(address="9.9.9.9", version=4, first_seen_at=T0, last_seen_at=T0)
        response = self.client.get(reverse("ips:list"), {"cidr": "1.2.3.0/24"})
        self.assertContains(response, "1.2.3.4")
        self.assertNotContains(response, "9.9.9.9")

    def test_asn_filter(self):
        IPAddress.objects.create(address="1.2.3.4", version=4, first_seen_at=T0, last_seen_at=T0, asn=64500)
        IPAddress.objects.create(address="9.9.9.9", version=4, first_seen_at=T0, last_seen_at=T0, asn=64501)
        response = self.client.get(reverse("ips:list"), {"asn": "64500"})
        self.assertContains(response, "1.2.3.4")
        self.assertNotContains(response, "9.9.9.9")

    def test_non_numeric_asn_is_ignored(self):
        IPAddress.objects.create(address="1.2.3.4", version=4, first_seen_at=T0, last_seen_at=T0)
        response = self.client.get(reverse("ips:list"), {"asn": "not-a-number"})
        self.assertContains(response, "1.2.3.4")


class WhoisStatusCellViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=T0, last_seen_at=T0)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("ips:whois-status-cell", args=[self.ip.pk]))
        self.assertEqual(response.status_code, 302)

    def test_renders_partial(self):
        response = self.client.get(reverse("ips:whois-status-cell", args=[self.ip.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "ips/partials/whois_status.html")


class IranStatusCellViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=T0, last_seen_at=T0)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("ips:iran-status-cell", args=[self.ip.pk]))
        self.assertEqual(response.status_code, 302)

    def test_renders_partial(self):
        response = self.client.get(reverse("ips:iran-status-cell", args=[self.ip.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "ips/partials/iran_status.html")


class RecalculateIranViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=T0, last_seen_at=T0)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.post(reverse("ips:recalculate-iran", args=[self.ip.pk]))
        self.assertEqual(response.status_code, 302)

    @patch("apps.iran.tasks.classify_ip.delay")
    def test_enqueues_and_redirects(self, mock_delay):
        response = self.client.post(reverse("ips:recalculate-iran", args=[self.ip.pk]))
        mock_delay.assert_called_once_with(self.ip.id)
        self.assertRedirects(response, reverse("ips:detail", args=[self.ip.pk]))

    @patch("apps.iran.tasks.classify_ip.delay")
    def test_htmx_request_returns_partial(self, mock_delay):
        response = self.client.post(
            reverse("ips:recalculate-iran", args=[self.ip.pk]), HTTP_HX_REQUEST="true"
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "iran-cell")


class IpDetailViewTests(TestCase):
    def setUp(self):
        from apps.incidents.models import RequestEvent
        from apps.logs.models import LogSource
        from apps.servers.models import Server

        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=T0, last_seen_at=T0)
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
        RequestEvent.objects.create(
            server=self.server,
            log_source=self.log_source,
            ip=self.ip,
            timestamp=T0,
            host="example.com",
            method="GET",
            uri="/api",
            status=503,
            bytes=10,
            raw_line="raw",
        )

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("ips:detail", args=[self.ip.pk]))
        self.assertEqual(response.status_code, 302)

    def test_shows_address_and_event(self):
        response = self.client.get(reverse("ips:detail", args=[self.ip.pk]))
        self.assertContains(response, "5.1.1.1")
        self.assertContains(response, "/api")

    def test_stats_reflect_event_count(self):
        response = self.client.get(reverse("ips:detail", args=[self.ip.pk]))
        self.assertEqual(response.context["stats"]["count"], 1)

    def test_server_filter(self):
        from apps.servers.models import Server

        other_server = Server.objects.create(
            name="edge-2",
            hostname="edge2.example.com",
            ssh_username="deploy",
            ssh_auth_type=Server.AuthType.PASSWORD,
            ssh_private_key="pw",
        )
        response = self.client.get(reverse("ips:detail", args=[self.ip.pk]), {"server": other_server.pk})
        self.assertEqual(len(response.context["page_obj"].object_list), 0)

    def test_host_filter(self):
        response = self.client.get(reverse("ips:detail", args=[self.ip.pk]), {"host": "other.example.com"})
        self.assertEqual(len(response.context["page_obj"].object_list), 0)


class CountryListViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("ips:countries"))
        self.assertEqual(response.status_code, 302)

    def test_groups_by_country_and_counts_iran(self):
        IPAddress.objects.create(
            address="5.1.1.1", version=4, first_seen_at=T0, last_seen_at=T0,
            country_code="IR", country_name="Iran", is_iran=True,
        )
        IPAddress.objects.create(
            address="5.1.1.2", version=4, first_seen_at=T0, last_seen_at=T0,
            country_code="IR", country_name="Iran", is_iran=True,
        )
        IPAddress.objects.create(
            address="9.9.9.9", version=4, first_seen_at=T0, last_seen_at=T0,
            country_code="US", country_name="United States",
        )
        # No country resolved yet - must not appear as a blank row.
        IPAddress.objects.create(address="1.1.1.1", version=4, first_seen_at=T0, last_seen_at=T0)

        response = self.client.get(reverse("ips:countries"))
        rows = {row["country_code"]: row for row in response.context["countries"]}
        self.assertEqual(set(rows), {"IR", "US"})
        self.assertEqual(rows["IR"]["total"], 2)
        self.assertEqual(rows["IR"]["iran_count"], 2)
        self.assertEqual(rows["US"]["total"], 1)
        self.assertEqual(rows["US"]["iran_count"], 0)


class AsnListViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("ips:asns"))
        self.assertEqual(response.status_code, 302)

    def test_groups_by_asn_despite_organization_text_variance(self):
        IPAddress.objects.create(
            address="5.1.1.1", version=4, first_seen_at=T0, last_seen_at=T0,
            asn=12880, organization="Telecommunication Company of Iran",
        )
        IPAddress.objects.create(
            address="5.1.1.2", version=4, first_seen_at=T0, last_seen_at=T0,
            asn=12880, organization="Telecommunication Company of Iran PJS",
        )
        # No ASN resolved yet - must not appear as a blank row.
        IPAddress.objects.create(address="1.1.1.1", version=4, first_seen_at=T0, last_seen_at=T0)

        response = self.client.get(reverse("ips:asns"))
        rows = list(response.context["asns"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["asn"], 12880)
        self.assertEqual(rows[0]["total"], 2)
