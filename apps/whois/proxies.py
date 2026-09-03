"""SOCKS proxy pool for spreading WHOIS query volume across multiple
source addresses (public WHOIS servers rate-limit by source IP, so a
deployment doing lots of lookups across many observed IPs can exhaust a
single address's allowance quickly).

ProxyPool.pick() and .record_result() are the only two operations this
needs: pick the least-recently-used enabled ProxyEndpoint (spreading load
evenly rather than hammering whichever proxy sorts first), then record
whether it actually worked so a dead/blocked proxy gets auto-disabled
instead of silently eating every subsequent lookup.

No proxies configured is a fully supported, honest state - pick() just
returns None and WhoisService.lookup() falls back to a direct connection,
exactly as if this module didn't exist.
"""
from __future__ import annotations

import logging

from django.conf import settings
from django.db.models import F
from django.utils import timezone

from .models import ProxyEndpoint

logger = logging.getLogger("ipscout.whois")


class ProxyPool:
    @staticmethod
    def pick() -> ProxyEndpoint | None:
        """The enabled proxy least recently used (nulls - never used yet -
        sort first), or None if no proxy is configured/enabled."""
        return (
            ProxyEndpoint.objects.filter(enabled=True)
            .order_by(F("last_used_at").asc(nulls_first=True))
            .first()
        )

    @staticmethod
    def record_result(proxy: ProxyEndpoint, success: bool, error: str = "") -> None:
        now = timezone.now()
        proxy.last_used_at = now
        proxy.total_uses += 1
        update_fields = ["last_used_at", "total_uses"]

        if success:
            proxy.last_success_at = now
            proxy.last_error = ""
            proxy.consecutive_failures = 0
            update_fields += ["last_success_at", "last_error", "consecutive_failures"]
        else:
            proxy.last_error = error
            proxy.consecutive_failures += 1
            update_fields += ["last_error", "consecutive_failures"]
            if proxy.consecutive_failures >= settings.WHOIS_PROXY_MAX_FAILURES:
                proxy.enabled = False
                update_fields.append("enabled")
                logger.warning(
                    "ProxyPool: disabling %s after %d consecutive failure(s): %s",
                    proxy,
                    proxy.consecutive_failures,
                    error,
                )

        proxy.save(update_fields=update_fields)
