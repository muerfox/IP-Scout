"""Celery IP queue (spec sections 13-14, 36).

process_new_ip is the single entry point for new-IP intelligence
enrichment. It now dispatches apps.whois's WHOIS lookup (Phase 5); Iran
CIDR matching (Phase 6) and GeoIP enrichment (Phase 8) are the remaining
TODOs here.
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
            # TODO(Phase 6): dispatch Iran CIDR matching.
            # TODO(Phase 8): dispatch GeoIP enrichment.
    except LockHeldError:
        logger.info("process_new_ip: %s already being processed, skipping", ip.address)
