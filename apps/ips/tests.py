import unittest
from datetime import datetime, timedelta, timezone as dt_timezone

from django.test import TestCase

from .models import IPAddress
from .services import IPIntelligenceService, normalize_ip


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


T0 = datetime(2026, 8, 26, 4, 30, tzinfo=dt_timezone.utc)


class IPIntelligenceServiceTests(TestCase):
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
