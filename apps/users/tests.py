from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import AuditLogEntry
from .services import record_audit_log

User = get_user_model()


class LoginTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")

    def test_login_page_renders(self):
        response = self.client.get(reverse("users:login"))
        self.assertEqual(response.status_code, 200)

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("users:login"), response.url)

    def test_login_success_redirects_to_dashboard(self):
        response = self.client.post(
            reverse("users:login"),
            {"username": "operator", "password": "s3cur3-pass-1234"},
        )
        self.assertRedirects(response, reverse("dashboard:index"))

    def test_login_failure_shows_error(self):
        response = self.client.post(
            reverse("users:login"),
            {"username": "operator", "password": "wrong"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid username or password")


class AuditLogTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")

    def test_record_audit_log_defaults_to_system_when_no_context(self):
        entry = record_audit_log("server.added", obj=self.user)
        self.assertIsNone(entry.user_id)
        self.assertEqual(entry.action, "server.added")
        self.assertEqual(entry.object_type, "User")
        self.assertEqual(entry.result, AuditLogEntry.Result.SUCCESS)

    def test_record_audit_log_explicit_user(self):
        entry = record_audit_log("server.added", user=self.user, ip_address="1.2.3.4")
        self.assertEqual(entry.user_id, self.user.id)
        self.assertEqual(entry.ip_address, "1.2.3.4")


class AuditLogViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("users:audit-log"))
        self.assertEqual(response.status_code, 302)

    def test_lists_entries(self):
        record_audit_log("server.added", user=self.user)
        response = self.client.get(reverse("users:audit-log"))
        self.assertContains(response, "server.added")

    def test_filters_by_action(self):
        record_audit_log("server.added", user=self.user)
        record_audit_log("ip.whois_forced", user=self.user)
        response = self.client.get(reverse("users:audit-log"), {"action": "whois"})
        self.assertContains(response, "ip.whois_forced")
        self.assertNotContains(response, "server.added")

    def test_filters_by_result(self):
        record_audit_log("server.added", user=self.user, result=AuditLogEntry.Result.FAILURE)
        record_audit_log("ip.whois_forced", user=self.user, result=AuditLogEntry.Result.SUCCESS)
        response = self.client.get(reverse("users:audit-log"), {"result": "failure"})
        self.assertContains(response, "server.added")
        self.assertNotContains(response, "ip.whois_forced")
