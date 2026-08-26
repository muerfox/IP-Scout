import unittest
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.http import QueryDict
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.logs.models import LogSource
from apps.servers.models import Server

from .export import ExportFilters, IPExportService, period_since
from .models import CountryNetwork, IPCountryHistory
from .services import IranCIDRService

User = get_user_model()


class PeriodSinceTests(unittest.TestCase):
    def test_all_returns_none(self):
        self.assertIsNone(period_since("all"))

    def test_unknown_returns_none(self):
        self.assertIsNone(period_since("not-a-period"))

    def test_24h(self):
        since = period_since("24h")
        self.assertAlmostEqual(
            (timezone.now() - since).total_seconds(), timedelta(hours=24).total_seconds(), delta=5
        )

    def test_7d(self):
        since = period_since("7d")
        self.assertAlmostEqual(
            (timezone.now() - since).total_seconds(), timedelta(days=7).total_seconds(), delta=5
        )


class ExportFiltersFromQuerydictTests(unittest.TestCase):
    def test_defaults_with_empty_querydict(self):
        filters = ExportFilters.from_querydict(QueryDict(""))
        self.assertEqual(filters.period, "all")
        self.assertIsNone(filters.server_id)
        self.assertEqual(filters.cidr, "")
        self.assertTrue(filters.status_503_only)
        self.assertEqual(filters.iran_status, "current")

    def test_parses_server_id(self):
        filters = ExportFilters.from_querydict(QueryDict("server=42"))
        self.assertEqual(filters.server_id, 42)

    def test_non_numeric_server_id_ignored(self):
        filters = ExportFilters.from_querydict(QueryDict("server=abc"))
        self.assertIsNone(filters.server_id)

    def test_status_503_only_hidden_field_false_wins_when_unchecked(self):
        # Matches the template's hidden+checkbox pattern: unchecked -> only "false" submitted.
        filters = ExportFilters.from_querydict(QueryDict("status_503_only=false"))
        self.assertFalse(filters.status_503_only)

    def test_status_503_only_checkbox_true_wins_when_checked(self):
        # Django's QueryDict.get() returns the last value for a repeated key,
        # matching real browser submission order (hidden field, then checkbox).
        filters = ExportFilters.from_querydict(QueryDict("status_503_only=false&status_503_only=true"))
        self.assertTrue(filters.status_503_only)

    def test_cidr_is_stripped(self):
        filters = ExportFilters.from_querydict(QueryDict("cidr=+5.1.0.0/22+"))
        self.assertEqual(filters.cidr, "5.1.0.0/22")


def _make_server(name: str) -> Server:
    return Server.objects.create(
        name=name,
        hostname=f"{name}.example.com",
        ssh_username="deploy",
        ssh_auth_type=Server.AuthType.PASSWORD,
        ssh_private_key="pw",
    )


class IPExportServiceTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.server = _make_server("edge-1")
        self.other_server = _make_server("edge-2")
        self.log_source = LogSource.objects.create(
            server=self.server, name="access.log", path="/var/log/nginx/access.log"
        )
        self.iran_ip = IPAddress.objects.create(
            address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now, is_iran=True
        )
        self.other_ip = IPAddress.objects.create(
            address="9.9.9.9", version=4, first_seen_at=now, last_seen_at=now
        )
        RequestEvent.objects.create(
            server=self.server,
            log_source=self.log_source,
            ip=self.iran_ip,
            timestamp=now,
            status=503,
            bytes=1,
            raw_line="raw",
        )

    def test_default_filters_return_only_iranian_ip_with_503(self):
        queryset = IPExportService.build_queryset(ExportFilters())
        self.assertEqual(list(queryset.values_list("address", flat=True)), ["5.1.1.1"])

    def test_any_iran_status_without_503_filter_returns_all(self):
        filters = ExportFilters(status_503_only=False, iran_status="any")
        queryset = IPExportService.build_queryset(filters)
        self.assertEqual(set(queryset.values_list("address", flat=True)), {"5.1.1.1", "9.9.9.9"})

    def test_server_filter_excludes_ips_from_other_servers(self):
        filters = ExportFilters(server_id=self.other_server.id, iran_status="any", status_503_only=False)
        queryset = IPExportService.build_queryset(filters)
        self.assertEqual(list(queryset), [])

    def test_cidr_filter(self):
        filters = ExportFilters(status_503_only=False, iran_status="any", cidr="5.1.0.0/22")
        queryset = IPExportService.build_queryset(filters)
        self.assertEqual(list(queryset.values_list("address", flat=True)), ["5.1.1.1"])

    def test_previous_iran_status(self):
        network = CountryNetwork.objects.create(country_code="IR", cidr="9.9.9.0/24", source="manual")
        IranCIDRService.classify(self.other_ip)
        network.enabled = False
        network.save()
        IranCIDRService.classify(self.other_ip)
        self.assertEqual(IPCountryHistory.objects.filter(ip=self.other_ip).count(), 1)

        filters = ExportFilters(status_503_only=False, iran_status="previous")
        queryset = IPExportService.build_queryset(filters)
        self.assertEqual(list(queryset.values_list("address", flat=True)), ["9.9.9.9"])


class ExportViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)
        now = timezone.now()
        IPAddress.objects.create(
            address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now, is_iran=True
        )

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("iran:export"))
        self.assertEqual(response.status_code, 302)

    def test_preview_shows_matching_address(self):
        response = self.client.get(reverse("iran:export"), {"status_503_only": "false"})
        self.assertContains(response, "5.1.1.1")

    def test_txt_download_one_ip_per_line(self):
        response = self.client.get(
            reverse("iran:export-download"), {"format": "txt", "status_503_only": "false"}
        )
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertEqual(response.content.decode(), "5.1.1.1\n")

    def test_csv_download_has_header_and_row(self):
        response = self.client.get(
            reverse("iran:export-download"), {"format": "csv", "status_503_only": "false"}
        )
        body = response.content.decode()
        self.assertIn("address", body.splitlines()[0])
        self.assertIn("5.1.1.1", body)

    def test_json_download_is_valid_json_list(self):
        import json

        response = self.client.get(
            reverse("iran:export-download"), {"format": "json", "status_503_only": "false"}
        )
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["address"], "5.1.1.1")
