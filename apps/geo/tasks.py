"""GeoIP enrichment task. No dedicated "geo" queue exists in the spec's
queue list (section 35: logs/ips/whois/iran/maintenance) - a local .mmdb
lookup is cheap, so this rides the "ips" queue alongside the rest of
new-IP intelligence processing.
"""
from __future__ import annotations

import logging

from celery import shared_task

from apps.common.locks import LockHeldError, redis_lock
from apps.ips.models import IPAddress

from .services import GeoIPService

logger = logging.getLogger("ipscout.geo")


@shared_task(queue="ips")
def enrich_ip(ip_id: int) -> None:
    try:
        ip = IPAddress.objects.get(pk=ip_id)
    except IPAddress.DoesNotExist:
        logger.warning("enrich_ip: IP %s no longer exists", ip_id)
        return

    try:
        with redis_lock(f"geo:{ip.address}", timeout=60):
            GeoIPService.enrich(ip)
    except LockHeldError:
        logger.info("enrich_ip: %s already being enriched, skipping", ip.address)
