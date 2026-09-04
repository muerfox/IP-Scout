"""Iran CIDR Celery tasks (spec sections 14, 23, 36, 45).

classify_ip is dispatched by apps.ips.tasks.process_new_ip for every new
IP, and by the "Recalculate Iran" UI action. run_monthly_iran_validation
is Celery Beat-scheduled (see the data migration in this app).
"""
from __future__ import annotations

import logging

from celery import shared_task

from apps.common.locks import LockHeldError, redis_lock

from .models import CountryNetwork
from .providers import IRAN_COUNTRY_CODE, get_provider
from .services import IranCIDRService, IranCIDRValidationService

logger = logging.getLogger("ipscout.iran")


@shared_task(queue="iran")
def classify_ip(ip_id: int) -> None:
    from apps.ips.models import IPAddress

    try:
        ip = IPAddress.objects.get(pk=ip_id)
    except IPAddress.DoesNotExist:
        logger.warning("classify_ip: IP %s no longer exists", ip_id)
        return

    try:
        with redis_lock(f"iran:{ip.address}", timeout=60):
            result = IranCIDRService.classify(ip)
    except LockHeldError:
        logger.info("classify_ip: %s already being classified, skipping", ip.address)
        return

    if result.is_iran:
        logger.info("classify_ip: %s matched Iranian CIDR %s", ip.address, result.iran_match_cidr)


@shared_task(queue="iran")
def run_monthly_iran_validation() -> None:
    """Skipped only for the static/manual source with nothing in it yet -
    that provider's fetch() just reads back existing manual rows, so an
    empty table really does mean "nothing to do". Any other provider (e.g.
    ripencc) fetches from a real external feed independent of what's
    already in the database, so it must run even from zero rows - this is
    the only way the CIDR table bootstraps itself the first time, without
    an operator seeding one row by hand first."""
    provider = get_provider()
    if provider.SOURCE == "manual" and not CountryNetwork.objects.filter(
        country_code=IRAN_COUNTRY_CODE, source="manual"
    ).exists():
        logger.info("run_monthly_iran_validation: static source has no manual entries yet, nothing to do")
        return

    summary = IranCIDRValidationService.run(provider=provider)
    logger.info(
        "run_monthly_iran_validation: fetched=%d created=%d disabled=%d reevaluated=%d",
        summary.fetched,
        summary.created,
        summary.disabled,
        summary.reevaluated,
    )
