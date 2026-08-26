from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.ips.models import IPAddress

User = get_user_model()


class DashboardDataViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_auth(self):
        self.client.logout()
        response = self.client.get(reverse("api:dashboard"))
        self.assertIn(response.status_code, (401, 403))

    def test_returns_expected_keys(self):
        response = self.client.get(reverse("api:dashboard"), {"period": "24h"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        for key in (
            "requests_over_time",
            "unique_ips_over_time",
            "countries",
            "iran_split",
            "top_iranian_ips",
            "top_iranian_cidrs",
            "top_countries",
        ):
            self.assertIn(key, data)

    def test_iran_split_has_all_three_buckets(self):
        response = self.client.get(reverse("api:dashboard"))
        split = response.json()["iran_split"]
        self.assertEqual(set(split.keys()), {"iran", "other", "unknown"})


class MapDataViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        now = timezone.now()
        IPAddress.objects.create(
            address="5.1.1.1",
            version=4,
            first_seen_at=now,
            last_seen_at=now,
            is_iran=True,
            latitude=35.7,
            longitude=51.4,
        )

    def test_requires_auth(self):
        self.client.logout()
        response = self.client.get(reverse("api:map"))
        self.assertIn(response.status_code, (401, 403))

    def test_default_status_is_503(self):
        response = self.client.get(reverse("api:map"))
        self.assertEqual(response.json()["status"], "503")

    def test_invalid_status_falls_back_to_503(self):
        response = self.client.get(reverse("api:map"), {"status": "bogus"})
        self.assertEqual(response.json()["status"], "503")

    def test_iran_filter_returns_point_at_high_zoom(self):
        response = self.client.get(reverse("api:map"), {"status": "iran", "zoom": 10})
        points = response.json()["points"]
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["address"], "5.1.1.1")

    def test_low_zoom_returns_clustered_point_without_address(self):
        response = self.client.get(reverse("api:map"), {"status": "iran", "zoom": 1})
        points = response.json()["points"]
        self.assertEqual(len(points), 1)
        self.assertNotIn("address", points[0])
        self.assertEqual(points[0]["count"], 1)
