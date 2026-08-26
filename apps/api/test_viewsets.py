from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.iran.models import CountryNetwork
from apps.logs.models import LogSource
from apps.servers.models import Server
from apps.whois.models import WhoisRecord

User = get_user_model()


def _make_server(**overrides) -> Server:
    defaults = dict(
        name="edge-1",
        hostname="edge1.example.com",
        ssh_username="deploy",
        ssh_auth_type=Server.AuthType.PASSWORD,
        ssh_private_key="top-secret-password",
    )
    defaults.update(overrides)
    return Server.objects.create(**defaults)


class ApiTestBase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)


class ServerApiTests(ApiTestBase):
    def setUp(self):
        super().setUp()
        self.server = _make_server()

    def test_requires_auth(self):
        self.client.logout()
        response = self.client.get(reverse("api:server-list"))
        self.assertIn(response.status_code, (401, 403))

    def test_credential_never_appears_in_response(self):
        """Security-critical: ssh_private_key must never leave the server
        via any API response, regardless of auth type or content."""
        response = self.client.get(reverse("api:server-detail", args=[self.server.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("ssh_private_key", response.json())
        self.assertNotIn("top-secret-password", response.content.decode())

    def test_list_credential_never_appears(self):
        response = self.client.get(reverse("api:server-list"))
        body = response.content.decode()
        self.assertNotIn("ssh_private_key", body)
        self.assertNotIn("top-secret-password", body)

    def test_write_methods_not_allowed(self):
        response = self.client.post(reverse("api:server-list"), {"name": "new"})
        self.assertEqual(response.status_code, 405)

    def test_logs_action(self):
        log_source = LogSource.objects.create(
            server=self.server, name="access.log", path="/var/log/nginx/access.log"
        )
        response = self.client.get(reverse("api:server-logs", args=[self.server.pk]))
        self.assertEqual(response.status_code, 200)
        paths = [row["path"] for row in response.json()["results"]]
        self.assertEqual(paths, [log_source.path])

    def test_search_by_hostname(self):
        response = self.client.get(reverse("api:server-list"), {"search": "edge1"})
        self.assertEqual(response.json()["count"], 1)


class IPAddressApiTests(ApiTestBase):
    def setUp(self):
        super().setUp()
        now = timezone.now()
        self.iran_ip = IPAddress.objects.create(
            address="5.1.1.1",
            version=4,
            first_seen_at=now,
            last_seen_at=now,
            is_iran=True,
            country_code="IR",
        )
        self.other_ip = IPAddress.objects.create(
            address="9.9.9.9", version=4, first_seen_at=now, last_seen_at=now, country_code="US"
        )

    def test_country_query_param(self):
        response = self.client.get(reverse("api:ip-list"), {"country": "ir"})
        addresses = {row["address"] for row in response.json()["results"]}
        self.assertEqual(addresses, {"5.1.1.1"})

    def test_is_iran_filter(self):
        response = self.client.get(reverse("api:ip-list"), {"is_iran": "true"})
        addresses = {row["address"] for row in response.json()["results"]}
        self.assertEqual(addresses, {"5.1.1.1"})

    def test_events_action(self):
        server = _make_server()
        log_source = LogSource.objects.create(
            server=server, name="access.log", path="/var/log/nginx/access.log"
        )
        RequestEvent.objects.create(
            server=server,
            log_source=log_source,
            ip=self.iran_ip,
            timestamp=timezone.now(),
            status=503,
            bytes=1,
            raw_line="raw",
        )
        response = self.client.get(reverse("api:ip-events", args=[self.iran_ip.pk]))
        self.assertEqual(response.json()["count"], 1)

    def test_whois_action(self):
        WhoisRecord.objects.create(
            ip=self.iran_ip, queried_at=timezone.now(), raw_response="x", parsed_data={}
        )
        response = self.client.get(reverse("api:ip-whois", args=[self.iran_ip.pk]))
        self.assertEqual(response.json()["count"], 1)


class RequestEventApiTests(ApiTestBase):
    def setUp(self):
        super().setUp()
        self.server = _make_server()
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
        for ip in (self.iran_ip, self.other_ip):
            RequestEvent.objects.create(
                server=self.server,
                log_source=self.log_source,
                ip=ip,
                timestamp=now,
                status=503,
                bytes=1,
                raw_line="raw",
            )

    def test_registered_at_503_path(self):
        response = self.client.get("/api/v1/503/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)

    def test_is_iran_query_param(self):
        response = self.client.get("/api/v1/503/", {"is_iran": "true"})
        addresses = {row["ip_address"] for row in response.json()["results"]}
        self.assertEqual(addresses, {"5.1.1.1"})

    def test_days_query_param_excludes_old_events(self):
        from datetime import timedelta

        RequestEvent.objects.create(
            server=self.server,
            log_source=self.log_source,
            ip=self.other_ip,
            timestamp=timezone.now() - timedelta(days=30),
            status=503,
            bytes=1,
            raw_line="raw",
        )
        response = self.client.get("/api/v1/503/", {"days": "7"})
        self.assertEqual(response.json()["count"], 2)


class IranApiTests(ApiTestBase):
    def test_iran_ips_endpoint(self):
        now = timezone.now()
        IPAddress.objects.create(
            address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now, is_iran=True
        )
        IPAddress.objects.create(address="9.9.9.9", version=4, first_seen_at=now, last_seen_at=now)
        response = self.client.get("/api/v1/iran/ips/")
        addresses = {row["address"] for row in response.json()["results"]}
        self.assertEqual(addresses, {"5.1.1.1"})

    def test_iran_cidrs_endpoint(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        response = self.client.get("/api/v1/iran/cidrs/")
        self.assertEqual(response.json()["count"], 1)

    def test_iran_export_txt(self):
        now = timezone.now()
        IPAddress.objects.create(
            address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now, is_iran=True
        )
        response = self.client.get(
            "/api/v1/iran/export/", {"format": "txt", "status_503_only": "false"}
        )
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertEqual(response.content.decode(), "5.1.1.1\n")

    def test_iran_export_requires_auth(self):
        self.client.logout()
        response = self.client.get("/api/v1/iran/export/")
        self.assertIn(response.status_code, (401, 403))


class WorkersApiTests(ApiTestBase):
    def test_returns_five_queues(self):
        response = self.client.get("/api/v1/workers/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["queues"]), 5)

    def test_requires_auth(self):
        self.client.logout()
        response = self.client.get("/api/v1/workers/")
        self.assertIn(response.status_code, (401, 403))
