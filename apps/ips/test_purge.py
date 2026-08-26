from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.incidents.models import RequestEvent
from apps.iran.models import IPCountryHistory
from apps.logs.models import LogSource
from apps.servers.models import Server

from .models import IPAddress
from .tasks import purge_old_data, purge_stale_ips

OLD = timezone.now() - timedelta(days=400)  # older than the default 365-day IP_RETENTION_DAYS
RECENT = timezone.now() - timedelta(days=1)


def _make_server() -> Server:
    return Server.objects.create(
        name="edge-1",
        hostname="edge1.example.com",
        ssh_username="deploy",
        ssh_auth_type=Server.AuthType.PASSWORD,
        ssh_private_key="pw",
    )


class PurgeStaleIpsTests(TestCase):
    def test_deletes_a_genuinely_stale_ip(self):
        IPAddress.objects.create(address="1.1.1.1", version=4, first_seen_at=OLD, last_seen_at=OLD)
        count = purge_stale_ips()
        self.assertEqual(count, 1)
        self.assertFalse(IPAddress.objects.filter(address="1.1.1.1").exists())

    def test_keeps_recently_seen_ip(self):
        IPAddress.objects.create(address="1.1.1.1", version=4, first_seen_at=OLD, last_seen_at=RECENT)
        count = purge_stale_ips()
        self.assertEqual(count, 0)
        self.assertTrue(IPAddress.objects.filter(address="1.1.1.1").exists())

    def test_keeps_currently_iranian_ip(self):
        IPAddress.objects.create(
            address="1.1.1.1", version=4, first_seen_at=OLD, last_seen_at=OLD, is_iran=True
        )
        count = purge_stale_ips()
        self.assertEqual(count, 0)
        self.assertTrue(IPAddress.objects.filter(address="1.1.1.1").exists())

    def test_keeps_ip_with_request_events(self):
        server = _make_server()
        log_source = LogSource.objects.create(
            server=server, name="access.log", path="/var/log/nginx/access.log"
        )
        ip = IPAddress.objects.create(address="1.1.1.1", version=4, first_seen_at=OLD, last_seen_at=OLD)
        RequestEvent.objects.create(
            server=server,
            log_source=log_source,
            ip=ip,
            timestamp=OLD,
            status=503,
            bytes=1,
            raw_line="raw",
        )
        count = purge_stale_ips()
        self.assertEqual(count, 0)
        self.assertTrue(IPAddress.objects.filter(address="1.1.1.1").exists())

    def test_keeps_ip_with_closed_iran_history_even_though_currently_not_iran(self):
        """The critical case: an IP that WAS Iranian (is_iran now False,
        but a closed IPCountryHistory row exists) must never be purged -
        IPCountryHistory.ip is a CASCADE FK, so deleting the IP would
        silently destroy spec section 22's "keep indefinitely" history.
        """
        ip = IPAddress.objects.create(
            address="1.1.1.1", version=4, first_seen_at=OLD, last_seen_at=OLD, is_iran=False
        )
        IPCountryHistory.objects.create(
            ip=ip,
            country_code="IR",
            source="manual",
            cidr="1.1.1.0/24",
            valid_from=OLD,
            valid_until=OLD + timedelta(days=1),
        )
        count = purge_stale_ips()
        self.assertEqual(count, 0)
        self.assertTrue(IPAddress.objects.filter(address="1.1.1.1").exists())
        self.assertEqual(IPCountryHistory.objects.filter(ip_id=ip.id).count(), 1)

    def test_deletes_only_the_eligible_ip_among_several(self):
        IPAddress.objects.create(address="1.1.1.1", version=4, first_seen_at=OLD, last_seen_at=OLD)
        IPAddress.objects.create(address="2.2.2.2", version=4, first_seen_at=OLD, last_seen_at=RECENT)
        IPAddress.objects.create(
            address="3.3.3.3", version=4, first_seen_at=OLD, last_seen_at=OLD, is_iran=True
        )
        count = purge_stale_ips()
        self.assertEqual(count, 1)
        self.assertEqual(
            set(IPAddress.objects.values_list("address", flat=True)), {"2.2.2.2", "3.3.3.3"}
        )


class PurgeOldDataOrchestratorTests(TestCase):
    def test_returns_counts_for_all_three(self):
        IPAddress.objects.create(address="1.1.1.1", version=4, first_seen_at=OLD, last_seen_at=OLD)
        result = purge_old_data()
        self.assertEqual(set(result.keys()), {"request_events", "whois_records", "ips"})
        self.assertEqual(result["ips"], 1)
