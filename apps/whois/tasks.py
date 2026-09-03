"""WHOIS Celery task (spec sections 14, 17, 18, 36, 46).

perform_whois_lookup is queued by apps.ips.tasks.process_new_ip for new
IPs, and (with force=True) by the "Force WHOIS" UI action. It respects
the 7-day freshness cache unless forced, retries transient failures with
exponential backoff, and never lets two lookups run for the same IP at
once (redis_lock("whois:<address>"), spec section 36).
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.utils import timezone

from apps.common.locks import LockHeldError, redis_lock
from apps.ips.models import IPAddress
from apps.ips.services import IPIntelligenceService

from .models import WhoisRecord
from .parsers import WhoisParser
from .proxies import ProxyPool
from .services import WhoisService

logger = logging.getLogger("ipscout.whois")

MAX_RETRIES = 3
_ASN_RE = re.compile(r"AS(\d+)", re.IGNORECASE)
_REFERRAL_KEYS = ("referralserver", "whois", "refer")


@shared_task(bind=True, queue="whois", max_retries=MAX_RETRIES)
def perform_whois_lookup(self, ip_id: int, force: bool = False) -> None:
    try:
        ip = IPAddress.objects.get(pk=ip_id)
    except IPAddress.DoesNotExist:
        logger.warning("perform_whois_lookup: IP %s no longer exists", ip_id)
        return

    if not force and not IPIntelligenceService.needs_whois_check(ip):
        logger.debug("perform_whois_lookup: %s still fresh, skipping", ip.address)
        return

    try:
        with redis_lock(f"whois:{ip.address}", timeout=settings.WHOIS_TIMEOUT + 30):
            _run_lookup(self, ip)
    except LockHeldError:
        logger.info("perform_whois_lookup: %s already being looked up, skipping", ip.address)


def _run_lookup(task, ip: IPAddress) -> None:
    proxy = ProxyPool.pick()
    result = WhoisService().lookup(ip.address, proxy=proxy)
    if proxy is not None:
        ProxyPool.record_result(proxy, result.success, result.error)
    now = timezone.now()

    if not result.success:
        if result.retryable and task.request.retries < MAX_RETRIES:
            countdown = 30 * (2**task.request.retries)
            raise task.retry(exc=RuntimeError(result.error), countdown=countdown)

        ip.whois_status = IPAddress.WhoisStatus.ERROR
        ip.whois_error = result.error
        ip.whois_checked_at = now
        # Give up rather than retry forever (spec section 18), but back
        # off a full cache window before trying this IP again instead of
        # hammering it on the very next poll.
        ip.whois_next_check_at = now + timedelta(days=settings.WHOIS_CACHE_DAYS)
        ip.save(
            update_fields=[
                "whois_status",
                "whois_error",
                "whois_checked_at",
                "whois_next_check_at",
                "updated_at",
            ]
        )
        return

    generic, known = WhoisParser().parse(result.raw_response)

    WhoisRecord.objects.create(
        ip=ip,
        queried_at=now,
        whois_server=_guess_whois_server(generic),
        raw_response=result.raw_response,
        parsed_data=generic,
        response_hash=WhoisService.response_hash(result.raw_response),
    )

    ip.whois_status = IPAddress.WhoisStatus.OK
    ip.whois_error = ""
    ip.whois_checked_at = now
    ip.whois_next_check_at = now + timedelta(days=settings.WHOIS_CACHE_DAYS)
    ip.whois_country = known.get("country", "")[:2]
    ip.organization = known.get("organization", "")[:255]
    ip.network = known.get("netname", known.get("inetnum", ""))[:255]

    origin = known.get("origin", "")
    if origin:
        ip.asn = _parse_asn(origin)

    inetnum = known.get("inetnum")
    if inetnum:
        ip.cidr = _inetnum_to_cidr(inetnum)

    if ip.cidr:
        # Log the range this IP's WHOIS response actually reported, for
        # any country - and mirror it into the Iran CIDR database when the
        # country is IR (see NetworkIntelService's docstring for why).
        from .network_intel import NetworkIntelService

        NetworkIntelService.record(
            ip.cidr,
            country_code=ip.whois_country,
            organization=ip.organization,
            network=ip.network,
            asn=ip.asn,
            seen_at=now,
        )

    ip.save(
        update_fields=[
            "whois_status",
            "whois_error",
            "whois_checked_at",
            "whois_next_check_at",
            "whois_country",
            "organization",
            "network",
            "asn",
            "cidr",
            "updated_at",
        ]
    )

    if ip.whois_country:
        # process_new_ip fires this lookup and apps.iran's classify_ip in
        # parallel, so the first classify_ip pass usually runs before
        # whois_country exists. Re-run it now that a real WHOIS country is
        # on the record, so IranCIDRService.classify's whois fallback
        # (see its docstring) isn't silently lost to that race.
        from apps.iran.tasks import classify_ip

        classify_ip.delay(ip.id)


def _guess_whois_server(generic: dict[str, list[str]]) -> str:
    for key in _REFERRAL_KEYS:
        values = generic.get(key)
        if values:
            return values[0][:255]
    return ""


def _parse_asn(origin: str) -> int | None:
    match = _ASN_RE.search(origin)
    return int(match.group(1)) if match else None


@shared_task(queue="maintenance")
def purge_old_whois_records() -> int:
    """Retention/purge (spec section 38). Only the historical raw-response
    rows are deleted - an IP's *current* whois_status/whois_checked_at
    live on IPAddress itself, so this never loses "active" information."""
    cutoff = timezone.now() - timedelta(days=settings.WHOIS_RETENTION_DAYS)
    queryset = WhoisRecord.objects.filter(queried_at__lt=cutoff)
    count = queryset.count()
    if count:
        queryset.delete()
    logger.info(
        "purge_old_whois_records: deleted %d record(s) older than %d days",
        count,
        settings.WHOIS_RETENTION_DAYS,
    )
    return count


def _inetnum_to_cidr(inetnum: str) -> str | None:
    """Best-effort: exact CIDR notation is used as-is; a "start - end"
    range (common in RIPE/APNIC output) is summarized to its first CIDR
    block. Not guaranteed to be lossless for oddly-aligned ranges - this
    is informational context on the IP record, not the authoritative
    Iran-matching data (that's a dedicated CIDR database in Phase 6)."""
    inetnum = inetnum.strip()
    try:
        if "/" in inetnum:
            return str(ipaddress.ip_network(inetnum, strict=False))
        if "-" in inetnum:
            start_str, _, end_str = inetnum.partition("-")
            start = ipaddress.ip_address(start_str.strip())
            end = ipaddress.ip_address(end_str.strip())
            blocks = list(ipaddress.summarize_address_range(start, end))
            return str(blocks[0]) if blocks else None
    except ValueError:
        return None
    return None
