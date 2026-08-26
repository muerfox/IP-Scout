from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

User = get_user_model()


class DashboardIndexTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_index_renders_stat_cards_with_real_counts(self):
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "503 Requests")
        self.assertContains(response, "Iranian IPs")
        self.assertContains(response, "WHOIS Queue")
        # No data seeded in this test - every card should read a real 0,
        # not a "pending" placeholder (all six models exist as of Phase 6).
        self.assertNotContains(response, "pending")


class WorldMapViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("dashboard:map"))
        self.assertEqual(response.status_code, 302)

    def test_renders(self):
        response = self.client.get(reverse("dashboard:map"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "map-container")
