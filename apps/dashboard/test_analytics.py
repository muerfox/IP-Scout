import unittest
from datetime import timedelta

from django.test import SimpleTestCase
from django.utils import timezone

from .analytics import PERIOD_DELTAS, _bucket_trunc, resolve_period


class ResolvePeriodTests(unittest.TestCase):
    def test_named_period_returns_now_minus_delta(self):
        start, end = resolve_period("6h")
        self.assertAlmostEqual((end - start).total_seconds(), PERIOD_DELTAS["6h"].total_seconds(), delta=1)

    def test_unknown_period_falls_back_to_default(self):
        start, end = resolve_period("not-a-real-period")
        self.assertAlmostEqual((end - start).total_seconds(), PERIOD_DELTAS["24h"].total_seconds(), delta=1)

    def test_custom_period_with_valid_aware_bounds(self):
        custom_start = "2026-01-01T00:00:00+00:00"
        custom_end = "2026-01-02T00:00:00+00:00"
        start, end = resolve_period("custom", custom_start, custom_end)
        self.assertEqual(start.isoformat(), custom_start)
        self.assertEqual(end.isoformat(), custom_end)

    def test_custom_period_with_naive_bounds_is_made_aware(self):
        start, end = resolve_period("custom", "2026-01-01T00:00:00", "2026-01-02T00:00:00")
        self.assertTrue(timezone.is_aware(start))
        self.assertTrue(timezone.is_aware(end))

    def test_custom_period_missing_end_falls_back_to_default(self):
        start, end = resolve_period("custom", "2026-01-01T00:00:00+00:00", None)
        self.assertAlmostEqual((end - start).total_seconds(), PERIOD_DELTAS["24h"].total_seconds(), delta=1)

    def test_custom_period_unparseable_falls_back_to_default(self):
        start, end = resolve_period("custom", "not-a-date", "also-not-a-date")
        self.assertAlmostEqual((end - start).total_seconds(), PERIOD_DELTAS["24h"].total_seconds(), delta=1)


class BucketTruncTests(SimpleTestCase):
    def test_short_window_uses_minute_buckets(self):
        from django.db.models.functions import TruncMinute

        now = timezone.now()
        self.assertIs(_bucket_trunc(now - timedelta(minutes=30), now), TruncMinute)

    def test_medium_window_uses_hour_buckets(self):
        from django.db.models.functions import TruncHour

        now = timezone.now()
        self.assertIs(_bucket_trunc(now - timedelta(hours=24), now), TruncHour)

    def test_long_window_uses_day_buckets(self):
        from django.db.models.functions import TruncDay

        now = timezone.now()
        self.assertIs(_bucket_trunc(now - timedelta(days=30), now), TruncDay)
