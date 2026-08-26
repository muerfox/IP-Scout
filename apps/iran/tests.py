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
from .providers import CIDREntry, IranCIDRProvider, StaticIranCIDRProvider, get_provider
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


class _FakeProvider:
    def __init__(self, entries):
        self._entries = entries

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


class ClassifyIpTaskTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.ip = IPAddress.objects.create(address="5.1.1.1", version=4, first_seen_at=now, last_seen_at=now)

    def test_runs_without_error(self):
        from .tasks import classify_ip

        classify_ip(self.ip.id)

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

    def test_changes_list_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("iran:changes"))
        self.assertEqual(response.status_code, 302)

    def test_iranian_ips_redirects_to_filtered_ip_list(self):
        response = self.client.get(reverse("iran:iranian-ips"))
        self.assertRedirects(response, reverse("ips:list") + "?is_iran=true")
