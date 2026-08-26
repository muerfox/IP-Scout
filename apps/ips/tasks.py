"""Celery IP queue (spec sections 13-14, 36).

process_new_ip is the single entry point Phase 5/6/8 will extend to
actually dispatch WHOIS/geo/Iran work. Right now none of that exists, so
this task does exactly what's honestly possible today: guard against
duplicate concurrent processing for the same IP, and record whether
intelligence enrichment is still needed. It does not fake a WHOIS lookup.
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
                # TODO(Phase 5): dispatch apps.whois.tasks.perform_whois_lookup
                # here once the whois app exists. TODO(Phase 6/8): same for
                # Iran CIDR matching and GeoIP enrichment.
                logger.info(
                    "process_new_ip: %s needs intelligence enrichment "
                    "(WHOIS/geo/Iran - not yet implemented)",
                    ip.address,
                )
    except LockHeldError:
        logger.info("process_new_ip: %s already being processed, skipping", ip.address)
