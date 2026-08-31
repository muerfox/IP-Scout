import unittest
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.ips.models import IPAddress

from .forms import CountryNetworkForm
from .models import CountryNetwork, IPCountryHistory, prefix_length_of
from .providers import (
    CIDREntry,
    IranCIDRProvider,
    RipeNccDelegatedStatsProvider,
    StaticIranCIDRProvider,
    get_provider,
)
from .services import IranCIDRService, IranCIDRValidationService

User = get_user_model()


class PrefixLengthOfTests(unittest.TestCase):
    """Pure function - no DB needed."""

    def test_ipv4(self):
        self.assertEqual(prefix_length_of("1.2.3.0/24"), 24)

    def test_ipv6(self):
        self.assertEqual(prefix_length_of("2001:db8::/32"), 32)

    def test_host_route(self):
        self.assertEqual(prefix_length_of("1.2.3.4/32"), 32)


class CIDREntryTests(unittest.TestCase):
    def test_defaults(self):
        entry = CIDREntry(cidr="5.1.0.0/22")
        self.assertEqual(entry.country_code, "IR")
        self.assertEqual(entry.network, "")


class GetProviderTests(unittest.TestCase):
    """Instantiating a provider doesn't touch the DB - only .fetch() does."""

    def test_static_provider_by_name(self):
        provider = get_provider("static")
        self.assertIsInstance(provider, StaticIranCIDRProvider)
        self.assertIsInstance(provider, IranCIDRProvider)

    def test_unknown_source_raises(self):
        with self.assertRaises(ImproperlyConfigured):
            get_provider("not-a-real-source")

    @override_settings(IRAN_CIDR_SOURCE="static")
    def test_reads_from_settings_when_name_omitted(self):
        self.assertIsInstance(get_provider(), StaticIranCIDRProvider)

    def test_ripencc_provider_by_name(self):
        provider = get_provider("ripencc")
        self.assertIsInstance(provider, RipeNccDelegatedStatsProvider)
        self.assertEqual(provider.SOURCE, "ripencc")


# A trimmed, synthetic (not real) RIPE NCC delegated-extended stats file,
# covering every line shape the parser must handle correctly.
_RIPE_STATS_FIXTURE = "\n".join(
    [
        "2.3|ripencc|20260825|999999|20260825|20260825+0000",
        "ripencc|*|asn|*|50000|summary",
        "ripencc|*|ipv4|*|900000000|summary",
        "# a comment line, should be ignored",
        "",
        "ripencc|IR|ipv4|10.0.0.0|256|20200101|allocated",
        "ripencc|IR|ipv4|10.4.0.0|512|20200101|assigned",
        "ripencc|US|ipv4|8.8.8.0|256|20200101|allocated",
        "ripencc|IR|ipv4|10.8.0.0|256|20200101|available",
        "ripencc|IR|asn|12880|1|20200101|allocated",
        "ripencc|IR|ipv6|2001:db8::|32|20200101|allocated",
    ]
)


class RipeNccDelegatedStatsProviderParseTests(unittest.TestCase):
    """Pure parsing logic - no network call, no DB."""

    def test_extracts_ipv4_and_ipv6_iran_blocks(self):
        cidrs = {entry.cidr for entry in RipeNccDelegatedStatsProvider.parse(_RIPE_STATS_FIXTURE)}
        self.assertEqual(cidrs, {"10.0.0.0/24", "10.4.0.0/23", "2001:db8::/32"})

    def test_every_entry_defaults_to_iran_country_code(self):
        entries = RipeNccDelegatedStatsProvider.parse(_RIPE_STATS_FIXTURE)
        self.assertTrue(entries)
        self.assertTrue(all(entry.country_code == "IR" for entry in entries))

    def test_ignores_other_countries(self):
        cidrs = {entry.cidr for entry in RipeNccDelegatedStatsProvider.parse(_RIPE_STATS_FIXTURE)}
        self.assertNotIn("8.8.8.0/24", cidrs)

    def test_ignores_available_status(self):
        cidrs = {entry.cidr for entry in RipeNccDelegatedStatsProvider.parse(_RIPE_STATS_FIXTURE)}
        self.assertNotIn("10.8.0.0/24", cidrs)

    def test_ignores_non_ip_record_types(self):
        # The asn|12880 line must not surface as anything resembling a
        # CIDR - if it did, this count would be off by one.
        entries = RipeNccDelegatedStatsProvider.parse(_RIPE_STATS_FIXTURE)
        self.assertEqual(len(entries), 3)

    def test_malformed_line_does_not_abort_parsing(self):
        body = _RIPE_STATS_FIXTURE + "\nripencc|IR|ipv4|not-an-ip|256|20200101|allocated"
        cidrs = {entry.cidr for entry in RipeNccDelegatedStatsProvider.parse(body)}
        self.assertEqual(cidrs, {"10.0.0.0/24", "10.4.0.0/23", "2001:db8::/32"})

    def test_empty_body_returns_no_entries(self):
        self.assertEqual(RipeNccDelegatedStatsProvider.parse(""), [])


class RipeNccDelegatedStatsProviderFetchTests(unittest.TestCase):
    """fetch() itself is mocked at the network boundary (hermetic, offline
    test suite) - the real live fetch is exercised manually as part of
    this project's infrastructure verification, not in the test suite."""

    @patch("apps.iran.providers.urllib.request.urlopen")
    @override_settings(IRAN_RIPE_STATS_URL="https://example.invalid/stats", IRAN_RIPE_STATS_TIMEOUT=7)
    def test_fetches_configured_url_with_configured_timeout(self, mock_urlopen):
        mock_urlopen.return_value.__enter__.return_value.read.return_value = (
            _RIPE_STATS_FIXTURE.encode("utf-8")
        )

        entries = RipeNccDelegatedStatsProvider().fetch()

        mock_urlopen.assert_called_once_with("https://example.invalid/stats", timeout=7)
        self.assertEqual({e.cidr for e in entries}, {"10.0.0.0/24", "10.4.0.0/23", "2001:db8::/32"})


class _FakeProvider:
    SOURCE = "manual"

    def __init__(self, entries, source="manual"):
        self._entries = entries
        self.SOURCE = source

    def fetch(self):
        return self._entries


class IranCIDRServiceTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now)

    def test_no_match_when_no_cidrs_configured(self):
        self.assertIsNone(IranCIDRService.find_matching_cidr("5.1.1.1"))

    def test_matches_containing_cidr(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        match = IranCIDRService.find_matching_cidr("5.1.1.1")
        self.assertIsNotNone(match)
        self.assertEqual(str(match.cidr), "5.1.0.0/22")

    def test_ignores_disabled_cidr(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual", enabled=False)
        self.assertIsNone(IranCIDRService.find_matching_cidr("5.1.1.1"))

    def test_ignores_non_containing_cidr(self):
        CountryNetwork.objects.create(country_code="IR", cidr="9.9.9.0/24", source="manual")
        self.assertIsNone(IranCIDRService.find_matching_cidr("5.1.1.1"))

    def test_most_specific_cidr_wins(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.0.0.0/8", source="manual")
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        match = IranCIDRService.find_matching_cidr("5.1.1.1")
        self.assertEqual(str(match.cidr), "5.1.0.0/22")

    def test_classify_marks_ip_iranian_and_opens_history(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        IranCIDRService.classify(self.ip)

        self.ip.refresh_from_db()
        self.assertTrue(self.ip.is_iran)
        self.assertEqual(self.ip.iran_match_cidr, "5.1.0.0/22")
        history = IPCountryHistory.objects.get(ip=self.ip)
        self.assertIsNone(history.valid_until)
        self.assertEqual(history.country_code, "IR")

    def test_classify_closes_history_when_cidr_disabled(self):
        network = CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        IranCIDRService.classify(self.ip)

        network.enabled = False
        network.save()
        IranCIDRService.classify(self.ip)

        self.ip.refresh_from_db()
        self.assertFalse(self.ip.is_iran)
        self.assertIsNone(self.ip.iran_match_cidr)
        history = IPCountryHistory.objects.get(ip=self.ip)
        self.assertIsNotNone(history.valid_until)

    def test_classify_is_idempotent_when_nothing_changed(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        IranCIDRService.classify(self.ip)
        IranCIDRService.classify(self.ip)
        self.assertEqual(IPCountryHistory.objects.filter(ip=self.ip).count(), 1)

    def test_classify_non_iranian_ip_creates_no_history(self):
        IranCIDRService.classify(self.ip)
        self.ip.refresh_from_db()
        self.assertFalse(self.ip.is_iran)
        self.assertEqual(IPCountryHistory.objects.filter(ip=self.ip).count(), 0)


class IranCIDRValidationServiceTests(TestCase):
    def test_creates_new_cidrs_from_provider(self):
        summary = IranCIDRValidationService.run(
            provider=_FakeProvider([CIDREntry(cidr="5.1.0.0/22", network="IR-TIC")])
        )
        self.assertEqual(summary.created, 1)
        self.assertEqual(CountryNetwork.objects.count(), 1)

    def test_disables_cidrs_no_longer_reported(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        summary = IranCIDRValidationService.run(provider=_FakeProvider([]))
        self.assertEqual(summary.disabled, 1)
        self.assertFalse(CountryNetwork.objects.get().enabled)

    def test_reevaluates_iran_flagged_ips_when_a_cidr_is_removed(self):
        now = timezone.now()
        ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now)
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        IranCIDRService.classify(ip)
        ip.refresh_from_db()
        self.assertTrue(ip.is_iran)

        summary = IranCIDRValidationService.run(provider=_FakeProvider([]))

        self.assertEqual(summary.reevaluated, 1)
        ip.refresh_from_db()
        self.assertFalse(ip.is_iran)

    def test_skips_reevaluation_when_nothing_changed(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        summary = IranCIDRValidationService.run(provider=_FakeProvider([CIDREntry(cidr="5.1.0.0/22")]))
        self.assertEqual(summary.created, 0)
        self.assertEqual(summary.disabled, 0)
        self.assertEqual(summary.reevaluated, 0)

    def test_new_entries_tagged_with_providers_own_source(self):
        summary = IranCIDRValidationService.run(
            provider=_FakeProvider([CIDREntry(cidr="5.1.0.0/22")], source="ripencc")
        )
        self.assertEqual(summary.created, 1)
        self.assertEqual(CountryNetwork.objects.get().source, "ripencc")

    def test_does_not_disable_another_providers_entries(self):
        """A validation run scoped to one provider's SOURCE must never
        disable rows another provider owns just because this fetch
        didn't report them - see IranCIDRProvider.SOURCE's docstring."""
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        CountryNetwork.objects.create(country_code="IR", cidr="9.9.0.0/16", source="ripencc")

        summary = IranCIDRValidationService.run(provider=_FakeProvider([], source="ripencc"))

        self.assertEqual(summary.disabled, 1)
        manual_row = CountryNetwork.objects.get(cidr="5.1.0.0/22")
        ripencc_row = CountryNetwork.objects.get(cidr="9.9.0.0/16")
        self.assertTrue(manual_row.enabled, "a ripencc-scoped run must not touch manual entries")
        self.assertFalse(ripencc_row.enabled)


class ClassifyIpTaskTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now)

    def test_runs_without_error(self):
        from .tasks import classify_ip

        classify_ip(self.ip.id)

    def test_logs_match_when_ip_is_iranian(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        from .tasks import classify_ip

        classify_ip(self.ip.id)  # exercises the is_iran logging branch

        self.ip.refresh_from_db()
        self.assertTrue(self.ip.is_iran)

    def test_missing_ip_returns_silently(self):
        from .tasks import classify_ip

        classify_ip(999999)

    @patch("apps.iran.tasks.redis_lock")
    def test_lock_held_is_skipped_silently(self, mock_lock):
        from apps.common.locks import LockHeldError

        from .tasks import classify_ip

        mock_lock.side_effect = LockHeldError(f"iran:{self.ip.address}")
        classify_ip(self.ip.id)


class RunMonthlyIranValidationTaskTests(TestCase):
    def test_noop_when_no_iran_data_configured(self):
        from .tasks import run_monthly_iran_validation

        run_monthly_iran_validation()
        self.assertEqual(CountryNetwork.objects.count(), 0)

    def test_runs_validation_when_data_exists(self):
        CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        from .tasks import run_monthly_iran_validation

        run_monthly_iran_validation()
        self.assertIsNotNone(CountryNetwork.objects.get().last_verified_at)


class CountryNetworkFormTests(TestCase):
    def test_valid_form_normalizes_country_code_and_derives_prefix_length(self):
        form = CountryNetworkForm(
            data={"country_code": "ir", "cidr": "5.1.0.0/22", "network": "", "enabled": True}
        )
        self.assertTrue(form.is_valid(), form.errors)
        network = form.save()
        self.assertEqual(network.country_code, "IR")
        self.assertEqual(network.prefix_length, 22)


class CidrViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_list_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("iran:cidrs"))
        self.assertEqual(response.status_code, 302)

    def test_create_cidr(self):
        response = self.client.post(
            reverse("iran:cidr-add"),
            {"country_code": "IR", "cidr": "5.1.0.0/22", "network": "IR-TIC", "enabled": True},
        )
        self.assertRedirects(response, reverse("iran:cidrs"))
        self.assertEqual(CountryNetwork.objects.count(), 1)

    def test_toggle_enabled(self):
        network = CountryNetwork.objects.create(country_code="IR", cidr="5.1.0.0/22", source="manual")
        response = self.client.post(reverse("iran:cidr-toggle-enabled", args=[network.pk]))
        network.refresh_from_db()
        self.assertFalse(network.enabled)
        self.assertEqual(response.status_code, 302)

    def test_toggle_enabled_htmx_returns_partial(self):
        network = CountryNetwork.objects.create(country_code="IR", cidr="5.1.1.0/24", source="manual")
        response = self.client.post(
            reverse("iran:cidr-toggle-enabled", args=[network.pk]), HTTP_HX_REQUEST="true"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "iran/partials/cidr_row.html")

    def test_create_get_renders_blank_form_defaulting_to_ir(self):
        response = self.client.get(reverse("iran:cidr-add"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["form"].initial["country_code"], "IR")

    @override_settings(IRAN_CIDR_SOURCE="static")
    def test_note_reflects_static_source(self):
        response = self.client.get(reverse("iran:cidrs"))
        self.assertContains(response, "Active source: <strong>static</strong>", html=False)

    @override_settings(IRAN_CIDR_SOURCE="ripencc")
    def test_note_reflects_ripencc_source(self):
        response = self.client.get(reverse("iran:cidrs"))
        self.assertContains(response, "Active source: <strong>ripencc</strong>", html=False)

    def test_changes_list_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("iran:changes"))
        self.assertEqual(response.status_code, 302)

    def test_changes_list_renders(self):
        response = self.client.get(reverse("iran:changes"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "iran/changes.html")

    def test_iranian_ips_redirects_to_filtered_ip_list(self):
        response = self.client.get(reverse("iran:iranian-ips"))
        self.assertRedirects(response, reverse("ips:list") + "?is_iran=true")
