"""WHOIS execution history (spec section 16).

One row per completed WHOIS query that actually returned a response to
preserve - "Raw WHOIS data is valuable for future parser improvements".
A failed attempt (timeout, no binary, empty response) is recorded on
IPAddress.whois_status/whois_error instead; there's no raw response worth
keeping in that case. Append-only - no updated_at.
"""
from __future__ import annotations

from django.db import models

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
