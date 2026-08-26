"""Central IP intelligence record (spec sections 12-14).

Identity + "have we seen this IP" fields (address, version, first/last_seen_at)
were populated starting Phase 3. This phase adds the rest of the field
list from spec section 12 - geo (country/lat/lon), WHOIS-derived (asn,
organization, network, cidr, whois_status/checked_at/next_check_at,
whois_country) and Iran classification (is_iran, iran_checked_at,
iran_match_cidr) - as additive columns on the same table. The columns
exist now; the code that populates them (apps.geo, apps.whois, apps.iran)
lands in Phases 5-8. Until then they're honestly null/default, not fake.
"""
from __future__ import annotations

import ipaddress

from django.db import models

from apps.common.fields import CIDRField
from apps.common.models import TimeStampedModel


class IPAddress(TimeStampedModel):
    class Version(models.IntegerChoices):
        V4 = 4, "IPv4"
        V6 = 6, "IPv6"

    class WhoisStatus(models.TextChoices):
        NEVER_CHECKED = "never_checked", "Never checked"
        OK = "ok", "OK"
        ERROR = "error", "Error"

    address = models.GenericIPAddressField(unique=True)
    version = models.PositiveSmallIntegerField(choices=Version.choices)

    # -- Geographic (apps.geo, Phase 8) - kept separate from whois_country
    # below since WHOIS country and physical geolocation are not the same
    # thing (spec section 19).
    country_code = models.CharField(max_length=2, blank=True)
    country_name = models.CharField(max_length=100, blank=True)
    continent = models.CharField(max_length=2, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)

    # -- WHOIS-derived (apps.whois, Phase 5)
    asn = models.PositiveBigIntegerField(null=True, blank=True)
    organization = models.CharField(max_length=255, blank=True)
    network = models.CharField(max_length=255, blank=True)
    cidr = CIDRField(null=True, blank=True)
    whois_status = models.CharField(
        max_length=15, choices=WhoisStatus.choices, default=WhoisStatus.NEVER_CHECKED
    )
    whois_checked_at = models.DateTimeField(null=True, blank=True)
    whois_next_check_at = models.DateTimeField(null=True, blank=True)
    whois_country = models.CharField(max_length=2, blank=True)
    whois_error = models.TextField(blank=True)

    # -- Iran classification (apps.iran, Phase 6)
    is_iran = models.BooleanField(default=False)
    iran_checked_at = models.DateTimeField(null=True, blank=True)
    iran_match_cidr = CIDRField(null=True, blank=True)

    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()

    class Meta:
        db_table = "ip_addresses"
        ordering = ["-last_seen_at"]
        verbose_name_plural = "IP addresses"
        indexes = [
            models.Index(fields=["-last_seen_at"]),
            models.Index(fields=["is_iran"]),
            models.Index(fields=["country_code"]),
            models.Index(fields=["asn"]),
        ]

    def __str__(self) -> str:
        return self.address

    @staticmethod
    def version_of(address: str) -> int:
        return ipaddress.ip_address(address).version
