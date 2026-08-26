import unittest

from .map import MapAggregationService


class GridSizeForZoomTests(unittest.TestCase):
    def test_decreases_as_zoom_increases(self):
        sizes = [MapAggregationService.grid_size_for_zoom(z) for z in range(0, 8)]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_floored_at_half_a_degree(self):
        self.assertEqual(MapAggregationService.grid_size_for_zoom(20), 0.5)

    def test_negative_zoom_does_not_exceed_zoom_zero_size(self):
        self.assertEqual(MapAggregationService.grid_size_for_zoom(-5), MapAggregationService.grid_size_for_zoom(0))
