"""Celery IP queue (spec sections 13-14, 36).

process_new_ip is the single entry point for new-IP intelligence
enrichment. It dispatches apps.whois's WHOIS lookup (Phase 5),
apps.iran's CIDR classification (Phase 6), and apps.geo's enrichment
(Phase 8) - every intelligence source spec section 59's example
workflow lists.
"""
from __future__ import annotations

import logging

from celery import shared_task

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
