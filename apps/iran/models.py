"""Country CIDR database and IP classification history (spec sections
20-22). Named "iran" for the app's purpose, but the schema itself is
country-generic (a `country_code` column, not a hard-coded IR-only
table) - matching and monthly validation logic below is what's Iran-
specific.
"""
from __future__ import annotations

from django.db import models

from apps.common.fields import CIDRField
from apps.common.models import TimeStampedModel
from apps.ips.models import IPAddress


def prefix_length_of(cidr: str) -> int:
    """"1.2.3.0/24" -> 24. Pure helper, kept separate from model.save()
    so it's testable without a database."""
    return int(str(cidr).rsplit("/", 1)[1])


class CountryNetwork(TimeStampedModel):
    country_code = models.CharField(max_length=2)
    cidr = CIDRField()
    network = models.CharField(max_length=255, blank=True)
    prefix_length = models.PositiveSmallIntegerField(editable=False)
    source = models.CharField(max_length=50, default="manual")
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    last_verified_at = models.DateTimeField(null=True, blank=True)
    enabled = models.BooleanField(default=True)

    class Meta:
        db_table = "country_networks"
        ordering = ["country_code", "cidr"]
        verbose_name_plural = "Country networks"
        indexes = [
            models.Index(fields=["country_code"]),
            models.Index(fields=["enabled"]),
        ]
        constraints = [
            models.UniqueConstraint(fields=["country_code", "cidr"], name="unique_country_cidr"),
        ]

    def __str__(self) -> str:
        return f"{self.country_code} {self.cidr}"

    def save(self, *args, **kwargs):
        if self.cidr:
            self.prefix_length = prefix_length_of(self.cidr)
        super().save(*args, **kwargs)


class IPCountryHistory(models.Model):
    """One row per contiguous period an IP was classified as `country_code`.

    `valid_until` is null while the classification is still current - see
    apps.iran.services.IranCIDRService.classify(), which is the only
    writer of this table.
    """

    ip = models.ForeignKey(IPAddress, on_delete=models.CASCADE, related_name="country_history")
    country_code = models.CharField(max_length=2)
    source = models.CharField(max_length=50)
    cidr = CIDRField(null=True, blank=True)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField(null=True, blank=True)
    confidence = models.FloatField(default=1.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ip_country_history"
        ordering = ["-valid_from"]
        verbose_name_plural = "IP country history"
        indexes = [
            models.Index(fields=["ip", "-valid_from"]),
            models.Index(fields=["country_code"]),
        ]

    def __str__(self) -> str:
        return f"{self.ip_id} {self.country_code} from {self.valid_from}"
