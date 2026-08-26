from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.ips.models import IPAddress
from apps.logs.models import LogSource
from apps.servers.models import Server

from .models import RequestEvent

User = get_user_model()


def _make_server(name: str) -> Server:
    return Server.objects.create(
        name=name,
        hostname=f"{name}.example.com",
        ssh_username="deploy",
        ssh_auth_type=Server.AuthType.PASSWORD,
        ssh_private_key="pw",
    )


class IncidentsViewTestsBase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

        self.server = _make_server("edge-1")
        self.log_source = LogSource.objects.create(
            server=self.server, name="access.log", path="/var/log/nginx/access.log"
        )
        now = timezone.now()
        self.iran_ip = IPAddress.objects.create(
            address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now, is_iran=True
        )
        self.other_ip = IPAddress.objects.create(
            address="9.9.9.9", version=4, first_seen_at=now, last_seen_at=now
        )
        for ip, count in ((self.iran_ip, 3), (self.other_ip, 1)):
            for i in range(count):
                RequestEvent.objects.create(
                    server=self.server,
                    log_source=self.log_source,
                    ip=ip,
                    timestamp=now,
                    host="example.com",
                    method="GET",
                    uri=f"/api/{i}",
                    status=503,
                    bytes=1,
                    raw_line="raw",
                )


class OverviewViewTests(IncidentsViewTestsBase):
    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("incidents:overview"))
        self.assertEqual(response.status_code, 302)

    def test_stats_are_correct(self):
        response = self.client.get(reverse("incidents:overview"))
        self.assertEqual(response.context["total_503"], 4)
        self.assertEqual(response.context["unique_ips"], 2)
        self.assertEqual(response.context["iranian_ips"], 1)
        self.assertEqual(response.context["iranian_pct"], 50.0)

    def test_top_ips_ordered_by_event_count(self):
        response = self.client.get(reverse("incidents:overview"))
        top = list(response.context["top_ips"])
        self.assertEqual(top[0].address, "5.1.1.1")
        self.assertEqual(top[0].event_count, 3)


class IpTableViewTests(IncidentsViewTestsBase):
    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("incidents:ip-table"))
        self.assertEqual(response.status_code, 302)

    def test_lists_both_ips(self):
        response = self.client.get(reverse("incidents:ip-table"))
        self.assertContains(response, "5.1.1.1")
        self.assertContains(response, "9.9.9.9")

    def test_is_iran_filter(self):
        response = self.client.get(reverse("incidents:ip-table"), {"is_iran": "true"})
        self.assertContains(response, "5.1.1.1")
        self.assertNotContains(response, "9.9.9.9")

    def test_invalid_sort_falls_back_to_default(self):
        response = self.client.get(reverse("incidents:ip-table"), {"sort": "'; DROP TABLE ips_addresses;"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["sort"], "-event_count")


class TimelineViewTests(IncidentsViewTestsBase):
    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("incidents:timeline"))
        self.assertEqual(response.status_code, 302)

    def test_lists_events(self):
        response = self.client.get(reverse("incidents:timeline"))
        self.assertEqual(response.context["page_obj"].paginator.count, 4)

    def test_server_filter(self):
        other_server = _make_server("edge-2")
        response = self.client.get(reverse("incidents:timeline"), {"server": other_server.pk})
        self.assertEqual(response.context["page_obj"].paginator.count, 0)

    def test_host_filter(self):
        response = self.client.get(reverse("incidents:timeline"), {"host": "example.com"})
        self.assertEqual(response.context["page_obj"].paginator.count, 4)
        response = self.client.get(reverse("incidents:timeline"), {"host": "nope.example.com"})
        self.assertEqual(response.context["page_obj"].paginator.count, 0)
