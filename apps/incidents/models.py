"""HTTP request tracking (spec section 11).

One row per parsed access-log line, any HTTP status - the reader
(apps.logs.services.NginxLogReader) records every line it can parse, not
just 503s, so an IP's history and enrichment don't depend on it having
5xx'd. Filter on `status` for 503-focused views (dashboard, exports).
Hourly/daily rollups for the dashboard are Phase 8.
"""
from __future__ import annotations

from django.db import models

from apps.ips.models import IPAddress
from apps.logs.models import LogSource
from apps.servers.models import Server


class RequestEvent(models.Model):
    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="request_events")
    log_source = models.ForeignKey(LogSource, on_delete=models.CASCADE, related_name="request_events")
    ip = models.ForeignKey(IPAddress, on_delete=models.CASCADE, related_name="request_events")

    timestamp = models.DateTimeField()
    host = models.CharField(max_length=255, blank=True)
    method = models.CharField(max_length=16, blank=True)
    uri = models.CharField(max_length=2048, blank=True)
    status = models.PositiveSmallIntegerField()
    bytes = models.PositiveBigIntegerField(default=0)
    request_time = models.FloatField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    referer = models.CharField(max_length=2048, blank=True)
    raw_line = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "request_events"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["-timestamp"]),
            models.Index(fields=["ip", "-timestamp"]),
            models.Index(fields=["server", "-timestamp"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self) -> str:
        return f"{self.ip_id} {self.status} {self.timestamp}"
