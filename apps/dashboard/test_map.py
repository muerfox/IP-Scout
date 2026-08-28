import unittest
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.ips.models import IPAddress

from .map import MapAggregationService, filtered_queryset


class FilteredQuerysetTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.iran_ip = IPAddress.objects.create(
            address="5.1.1.1",
            version=4,
            first_seen_at=now,
            last_seen_at=now,
            latitude=35.7,
            longitude=51.4,
            is_iran=True,
            iran_checked_at=now,
        )
        self.non_iran_ip = IPAddress.objects.create(
            address="9.9.9.9",
            version=4,
            first_seen_at=now,
            last_seen_at=now,
            latitude=1.0,
            longitude=1.0,
            is_iran=False,
            iran_checked_at=now,
        )
        self.unknown_ip = IPAddress.objects.create(
            address="8.8.8.8",
            version=4,
            first_seen_at=now,
            last_seen_at=now,
            latitude=2.0,
            longitude=2.0,
            is_iran=False,
            iran_checked_at=None,
        )
        self.start = now - timedelta(hours=1)
        self.end = now + timedelta(hours=1)

    def test_non_iran_status_excludes_iran_and_unknown(self):
        result = filtered_queryset("non_iran", self.start, self.end)
        self.assertEqual(set(result.values_list("id", flat=True)), {self.non_iran_ip.id})

    def test_unknown_status_excludes_checked_ips(self):
        result = filtered_queryset("unknown", self.start, self.end)
        self.assertEqual(set(result.values_list("id", flat=True)), {self.unknown_ip.id})


class GridSizeForZoomTests(unittest.TestCase):
    def test_decreases_as_zoom_increases(self):
        sizes = [MapAggregationService.grid_size_for_zoom(z) for z in range(0, 8)]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_floored_at_half_a_degree(self):
        self.assertEqual(MapAggregationService.grid_size_for_zoom(20), 0.5)

    def test_negative_zoom_does_not_exceed_zoom_zero_size(self):
        self.assertEqual(MapAggregationService.grid_size_for_zoom(-5), MapAggregationService.grid_size_for_zoom(0))
