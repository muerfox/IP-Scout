"""Central IP intelligence record (spec sections 12-14).

Phase 3 only needs identity + "have we seen this IP" bookkeeping, so this
model currently holds just that. WHOIS/geo/Iran fields (whois_status,
country_code, asn, is_iran, ...) are added on top of this same table via
additive migrations in Phase 4-6 - not a rebuild.
"""
from __future__ import annotations

import ipaddress

from django.db import models

from apps.common.models import TimeStampedModel


class IPAddress(TimeStampedModel):
    class Version(models.IntegerChoices):
        V4 = 4, "IPv4"
        V6 = 6, "IPv6"

    address = models.GenericIPAddressField(unique=True)
    version = models.PositiveSmallIntegerField(choices=Version.choices)

    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()

    class Meta:
        db_table = "ip_addresses"
        ordering = ["-last_seen_at"]
        verbose_name_plural = "IP addresses"
        indexes = [
            models.Index(fields=["-last_seen_at"]),
        ]

    def __str__(self) -> str:
        return self.address

    @staticmethod
    def version_of(address: str) -> int:
        return ipaddress.ip_address(address).version
