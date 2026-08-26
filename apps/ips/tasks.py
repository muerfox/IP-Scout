"""Celery IP queue (spec sections 13-14, 36).

process_new_ip is the single entry point for new-IP intelligence
enrichment. It dispatches apps.whois's WHOIS lookup (Phase 5),
apps.iran's CIDR classification (Phase 6), and apps.geo's enrichment
(Phase 8) - every intelligence source spec section 59's example
workflow lists.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task

from django.conf import settings
from django.utils import timezone

from apps.common.locks import LockHeldError, redis_lock

from .models import IPAddress
from .services import IPIntelligenceService

logger = logging.getLogger("ipscout.ips")


@shared_task(queue="ips")
def process_new_ip(ip_id: int) -> None:
    try:
        ip = IPAddress.objects.get(pk=ip_id)
    except IPAddress.DoesNotExist:
        return

    lock_key = f"ip:process:{ip.address}"
    try:
        with redis_lock(lock_key, timeout=300):
            if IPIntelligenceService.needs_whois_check(ip):
                # Imported lazily to avoid a module-level import cycle
                # (apps.whois.tasks imports apps.ips.models/services).
                from apps.whois.tasks import perform_whois_lookup

                perform_whois_lookup.delay(ip.id)

            from apps.iran.tasks import classify_ip

            classify_ip.delay(ip.id)

            from apps.geo.tasks import enrich_ip

            enrich_ip.delay(ip.id)
    except LockHeldError:
        logger.info("process_new_ip: %s already being processed, skipping", ip.address)


def _purge_eligible_ips():
    """Spec section 38's exact compound rule: an IP is only eligible for
    deletion when ALL of these hold:
      - last_seen_at is older than IP_RETENTION_DAYS
      - no 503 activity references it (RequestEvent has its own, much
        shorter retention, so this is trivially true once the first
        condition holds - kept explicit for correctness/clarity anyway)
      - no active Iran relationship (is_iran is False)
      - no protected historical data - IPCountryHistory rows must be kept
        indefinitely (spec section 22), and that model's FK to IPAddress
        is CASCADE, so an IP with *any* history row (even a closed one)
        is excluded rather than letting deletion silently erase it.
    """
    from apps.incidents.models import RequestEvent
    from apps.iran.models import IPCountryHistory

    cutoff = timezone.now() - timedelta(days=settings.IP_RETENTION_DAYS)
    return (
        IPAddress.objects.filter(last_seen_at__lt=cutoff, is_iran=False)
        .exclude(id__in=RequestEvent.objects.values_list("ip_id", flat=True))
        .exclude(id__in=IPCountryHistory.objects.values_list("ip_id", flat=True))
    )


@shared_task(queue="maintenance")
def purge_stale_ips() -> int:
    queryset = _purge_eligible_ips()
    count = queryset.count()
    if count:
        queryset.delete()
    logger.info("purge_stale_ips: deleted %d IP(s) older than %d days", count, settings.IP_RETENTION_DAYS)
    return count


@shared_task(queue="maintenance")
def purge_old_data() -> dict[str, int]:
    """The maintenance task spec section 38 asks for. Runs request events
    and WHOIS history first (both have short retention windows and are
    always safe to clear), then IPs last - the IP purge query already
    excludes anything a RequestEvent still references, but ordering it
    last keeps the intent obvious."""
    from apps.incidents.tasks import purge_old_request_events
    from apps.whois.tasks import purge_old_whois_records

    result = {
        "request_events": purge_old_request_events(),
        "whois_records": purge_old_whois_records(),
        "ips": purge_stale_ips(),
    }
    logger.info("purge_old_data: %s", result)
    return result
