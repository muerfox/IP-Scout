"""WHOIS execution history (spec section 16).

One row per completed WHOIS query that actually returned a response to
preserve - "Raw WHOIS data is valuable for future parser improvements".
A failed attempt (timeout, no binary, empty response) is recorded on
IPAddress.whois_status/whois_error instead; there's no raw response worth
keeping in that case. Append-only - no updated_at.
"""
from __future__ import annotations

from django.db import models

from apps.common.fields import CIDRField, EncryptedTextField
from apps.common.models import TimeStampedModel
from apps.ips.models import IPAddress


class WhoisRecord(models.Model):
    ip = models.ForeignKey(IPAddress, on_delete=models.CASCADE, related_name="whois_records")
    queried_at = models.DateTimeField()
    whois_server = models.CharField(max_length=255, blank=True)
    raw_response = models.TextField()
    parsed_data = models.JSONField(default=dict, blank=True)
    response_hash = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "whois_records"
        ordering = ["-queried_at"]
        indexes = [
            models.Index(fields=["ip", "-queried_at"]),
            models.Index(fields=["-queried_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.ip_id} @ {self.queried_at}"


class ObservedNetwork(TimeStampedModel):
    """Every CIDR range this project's own WHOIS lookups have actually
    reported, for any country - not just Iran. apps.iran.models.CountryNetwork
    holds ranges *known to be Iranian* (manually entered, or from a real
    feed like RIPE NCC's delegated-extended stats); this table is the raw
    material underneath that: whatever apps.whois._inetnum_to_cidr derives
    from a real, successful WhoisService response, kept and accumulated so
    the CIDR picture for a country grows organically as logs are
    processed, instead of only ever knowing about the exact IPs seen so
    far. See apps.whois.tasks.record_observed_network, the only writer.

    Never fabricated: a row only exists because a real WHOIS query for
    some IP actually returned this network.
    """

    cidr = CIDRField(unique=True)
    country_code = models.CharField(max_length=2, blank=True)
    organization = models.CharField(max_length=255, blank=True)
    network = models.CharField(max_length=255, blank=True)
    asn = models.PositiveBigIntegerField(null=True, blank=True)
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    # How many distinct IPAddress WHOIS lookups have landed on this exact
    # CIDR - a rough "how solid is this range" signal, not a precise count
    # (an IP re-queried after its 7-day cache expires increments this
    # again; that's fine, it only ever makes the signal stronger).
    hit_count = models.PositiveIntegerField(default=1)

    class Meta:
        db_table = "observed_networks"
        ordering = ["-last_seen_at"]
        indexes = [
            models.Index(fields=["country_code"]),
            models.Index(fields=["-last_seen_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.cidr} ({self.country_code or 'unknown'})"


class ProxyEndpoint(TimeStampedModel):
    """A SOCKS proxy WhoisService can route a lookup through (spec-adjacent:
    public WHOIS servers rate-limit by source address, so a NOC doing
    volume lookups across many observed IPs needs more than one source
    address to stay usable). Managed like apps.iran.models.CountryNetwork -
    an operator adds/edits/disables rows via /admin or the WHOIS Proxies
    page; nothing here is auto-populated or fabricated.

    Actually used by apps.whois.proxies.ProxyPool + apps.whois.services -
    see their docstrings for the selection/backoff/wrapping mechanics.
    """

    class Scheme(models.TextChoices):
        SOCKS5 = "socks5", "SOCKS5"
        SOCKS5H = "socks5h", "SOCKS5 (remote DNS)"
        SOCKS4 = "socks4", "SOCKS4"

    label = models.CharField(max_length=100, blank=True)
    scheme = models.CharField(max_length=10, choices=Scheme.choices, default=Scheme.SOCKS5)
    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField()
    username = models.CharField(max_length=255, blank=True)
    # Encrypted at rest for the same reason apps.servers.Server encrypts
    # SSH credentials (spec section 42).
    password = EncryptedTextField(blank=True)
    enabled = models.BooleanField(default=True)

    last_used_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    # Auto-disabled once this hits settings.WHOIS_PROXY_MAX_FAILURES - a
    # dead/blocked proxy shouldn't keep eating lookups forever. Resets to
    # 0 on any success.
    consecutive_failures = models.PositiveIntegerField(default=0)
    total_uses = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "whois_proxy_endpoints"
        ordering = ["host", "port"]
        constraints = [
            models.UniqueConstraint(fields=["host", "port"], name="unique_proxy_host_port"),
        ]

    def __str__(self) -> str:
        return self.label or f"{self.scheme}://{self.host}:{self.port}"
