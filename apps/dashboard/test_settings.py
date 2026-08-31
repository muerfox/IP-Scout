from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

User = get_user_model()


class SettingsPagesTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_whois_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("dashboard:settings-whois"))
        self.assertEqual(response.status_code, 302)

    def test_whois_renders_config(self):
        response = self.client.get(reverse("dashboard:settings-whois"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/usr/bin/whois")

    def test_retention_renders_config(self):
        response = self.client.get(reverse("dashboard:settings-retention"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "30 days")  # REQUEST_RETENTION_DAYS default

    def test_geoip_renders_null_provider_note(self):
        response = self.client.get(reverse("dashboard:settings-geoip"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "null")

    @override_settings(GEOIP_PROVIDER="unknown-provider")
    def test_geoip_surfaces_provider_misconfiguration(self):
        response = self.client.get(reverse("dashboard:settings-geoip"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unknown GEOIP_PROVIDER")

    def test_iran_sources_renders_config(self):
        response = self.client.get(reverse("dashboard:settings-iran-sources"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "static")

    @override_settings(IRAN_CIDR_SOURCE="ripencc")
    def test_iran_sources_renders_ripencc_note(self):
        response = self.client.get(reverse("dashboard:settings-iran-sources"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "RIPE NCC")

    def test_users_redirects_to_admin(self):
        response = self.client.get(reverse("dashboard:settings-users"))
        self.assertRedirects(response, "/admin/users/user/", fetch_redirect_response=False)

    @patch("apps.ips.tasks.purge_old_data.delay")
    def test_run_purge_now_enqueues_and_redirects(self, mock_delay):
        response = self.client.post(reverse("dashboard:settings-retention-purge"))
        mock_delay.assert_called_once()
        self.assertRedirects(response, reverse("dashboard:settings-retention"))

    def test_run_purge_now_requires_post(self):
        response = self.client.get(reverse("dashboard:settings-retention-purge"))
        self.assertEqual(response.status_code, 405)
