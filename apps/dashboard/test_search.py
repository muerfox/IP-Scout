from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.ips.models import IPAddress
from apps.servers.models import Server

from .search import resolve_search

User = get_user_model()


def _make_server(**overrides) -> Server:
    defaults = dict(
        name="edge-1",
        hostname="edge1.example.com",
        ssh_username="deploy",
        ssh_auth_type=Server.AuthType.PASSWORD,
        ssh_private_key="pw",
    )
    defaults.update(overrides)
    return Server.objects.create(**defaults)


class ResolveSearchTests(TestCase):
    def test_known_ip_goes_to_detail_page(self):
        now = timezone.now()
        ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now)
        self.assertEqual(resolve_search("5.1.1.1"), reverse("ips:detail", args=[ip.pk]))

    def test_unknown_ip_falls_through_to_address_search(self):
        self.assertEqual(resolve_search("8.8.8.8"), f"{reverse('ips:list')}?q=8.8.8.8")

    def test_ipv6_address(self):
        now = timezone.now()
        ip = IPAddress.objects.create(address="::1", version=6, first_seen_at=now, last_seen_at=now)
        self.assertEqual(resolve_search("::1"), reverse("ips:detail", args=[ip.pk]))

    def test_cidr_goes_to_filtered_list(self):
        self.assertEqual(resolve_search("5.1.0.0/22"), f"{reverse('ips:list')}?cidr=5.1.0.0/22")

    def test_slash_present_but_invalid_cidr_falls_through(self):
        query = "not-a-cidr/thing"
        self.assertEqual(resolve_search(query), f"{reverse('ips:list')}?q={query}")

    def test_asn_goes_to_filtered_list(self):
        self.assertEqual(resolve_search("12880"), f"{reverse('ips:list')}?asn=12880")

    def test_as_prefixed_asn(self):
        self.assertEqual(resolve_search("AS12880"), f"{reverse('ips:list')}?asn=12880")
        self.assertEqual(resolve_search("as12880"), f"{reverse('ips:list')}?asn=12880")

    def test_exact_server_hostname_match(self):
        server = _make_server()
        self.assertEqual(resolve_search("edge1.example.com"), reverse("servers:detail", args=[server.pk]))

    def test_exact_server_name_match(self):
        server = _make_server()
        self.assertEqual(resolve_search("edge-1"), reverse("servers:detail", args=[server.pk]))

    def test_free_text_falls_through_to_address_search(self):
        self.assertEqual(resolve_search("some organization"), f"{reverse('ips:list')}?q=some organization")

    def test_empty_query_goes_to_dashboard(self):
        self.assertEqual(resolve_search(""), reverse("dashboard:index"))
        self.assertEqual(resolve_search("   "), reverse("dashboard:index"))


class SearchViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("dashboard:search"), {"q": "5.1.1.1"})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("users:login"), response.url)

    def test_redirects_per_resolve_search(self):
        response = self.client.get(reverse("dashboard:search"), {"q": "5.1.0.0/22"})
        self.assertRedirects(
            response, f"{reverse('ips:list')}?cidr=5.1.0.0/22", fetch_redirect_response=False
        )
