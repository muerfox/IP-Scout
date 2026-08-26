import unittest
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from django.utils import timezone

from apps.ips.models import IPAddress

from .providers import GeoResult, MaxMindGeoIPProvider, NullGeoIPProvider, get_provider
from .services import GeoIPService

User = get_user_model()


class GeoResultTests(unittest.TestCase):
    def test_defaults(self):
        result = GeoResult()
        self.assertEqual(result.country_code, "")
        self.assertIsNone(result.latitude)


class NullGeoIPProviderTests(unittest.TestCase):
    def test_always_returns_none(self):
        self.assertIsNone(NullGeoIPProvider().lookup("1.2.3.4"))


class GetProviderTests(unittest.TestCase):
    def test_null_by_name(self):
        self.assertIsInstance(get_provider("null"), NullGeoIPProvider)

    def test_unknown_raises(self):
        with self.assertRaises(ImproperlyConfigured):
            get_provider("not-a-real-provider")

    def test_maxmind_without_database_path_raises(self):
        with self.assertRaises(ImproperlyConfigured):
            get_provider("maxmind")


class MaxMindGeoIPProviderTests(unittest.TestCase):
    def test_requires_database_path(self):
        with self.assertRaises(ImproperlyConfigured):
            MaxMindGeoIPProvider(database_path="")

    def test_lookup_without_geoip2_installed_raises_improperly_configured(self):
        # geoip2 genuinely isn't installed in this sandbox - this exercises
        # the real guard, not a simulated one.
        provider = MaxMindGeoIPProvider(database_path="/tmp/does-not-matter.mmdb")
        with self.assertRaises(ImproperlyConfigured):
            provider.lookup("1.2.3.4")


class GeoIPServiceTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now)

    @patch("apps.geo.services.get_provider")
    def test_enrich_persists_result(self, mock_get_provider):
        mock_get_provider.return_value.lookup.return_value = GeoResult(
            country_code="IR", country_name="Iran", continent="AS", latitude=35.7, longitude=51.4
        )

        GeoIPService.enrich(self.ip)

        self.ip.refresh_from_db()
        self.assertEqual(self.ip.country_code, "IR")
        self.assertEqual(self.ip.country_name, "Iran")
        self.assertEqual(self.ip.continent, "AS")
        self.assertEqual(self.ip.latitude, 35.7)
        self.assertEqual(self.ip.longitude, 51.4)

    @patch("apps.geo.services.get_provider")
    def test_none_result_leaves_existing_data_untouched(self, mock_get_provider):
        self.ip.country_code = "IR"
        self.ip.latitude = 35.7
        self.ip.save()
        mock_get_provider.return_value.lookup.return_value = None

        GeoIPService.enrich(self.ip)

        self.ip.refresh_from_db()
        self.assertEqual(self.ip.country_code, "IR")
        self.assertEqual(self.ip.latitude, 35.7)


class EnrichIpTaskTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now)

    def test_runs_without_error(self):
        from .tasks import enrich_ip

        enrich_ip(self.ip.id)  # NullGeoIPProvider by default - no-op, must not raise

    def test_missing_ip_returns_silently(self):
        from .tasks import enrich_ip

        enrich_ip(999999)

    @patch("apps.geo.tasks.redis_lock")
    def test_lock_held_is_skipped_silently(self, mock_lock):
        from apps.common.locks import LockHeldError
        from .tasks import enrich_ip

        mock_lock.side_effect = LockHeldError(f"geo:{self.ip.address}")
        enrich_ip(self.ip.id)
