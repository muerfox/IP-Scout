"""IP identity bookkeeping and intelligence-freshness logic (spec sections
12-14, 17, the "critical 503 rule" in section 58).

record_sightings_bulk stays cheap and synchronous-safe ("Do not perform
expensive WHOIS operations synchronously during log parsing", section 13):
it only ever does find-or-create + first/last_seen_at bookkeeping inline,
then fires a Celery message (not a blocking call) for genuinely new IPs.
needs_whois_check() is the freshness rule Phase 5's WhoisService will use
before spending a `whois` process on an IP.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime

from django.db import models
from django.utils import timezone

from .models import IPAddress


def normalize_ip(raw: str) -> str:
    """Validate and normalize an IP string (e.g. compresses IPv6).

    Raises ValueError for anything that isn't a valid IPv4/IPv6 address.
    """
    return str(ipaddress.ip_address(raw.strip()))


class IPIntelligenceService:
    @staticmethod
    def needs_whois_check(ip: IPAddress) -> bool:
        """True if `ip` has never been checked, or its freshness window
        (whois_next_check_at, set by Phase 5 after a successful lookup)
        has expired. Every IP is "never checked" until Phase 5 exists, so
        this is always True for now - that's correct, not a stub."""
        return ip.whois_next_check_at is None or ip.whois_next_check_at <= timezone.now()

    @staticmethod
    def whois_pending_queryset():
        """IPs due for a WHOIS check right now - same condition as
        needs_whois_check, expressed as a queryset so it can be counted
        cheaply (e.g. the dashboard's WHOIS Queue card) without loading
        every row into Python."""
        return IPAddress.objects.filter(
            models.Q(whois_next_check_at__isnull=True) | models.Q(whois_next_check_at__lte=timezone.now())
        )

    @staticmethod
    def record_sighting(raw_address: str, seen_at: datetime) -> IPAddress:
        """Find-or-create the IPAddress for one sighting and bump last_seen_at."""
        return IPIntelligenceService.record_sightings_bulk([(raw_address, seen_at)])[
            normalize_ip(raw_address)
        ]

    @staticmethod
    def record_sightings_bulk(sightings: list[tuple[str, datetime]]) -> dict[str, IPAddress]:
        """Resolve many (raw_address, seen_at) pairs to IPAddress rows in as
        few queries as possible, deduplicating IPs seen multiple times in
        the same batch. Returns {normalized_address: IPAddress}.

        Never creates a duplicate row for an address that already exists
        (spec section 12: UNIQUE(address)) and never regresses last_seen_at
        (a monotonic, DB-side conditional UPDATE handles concurrent readers
        racing on the same IP from different servers).

        For a brand-new IP, enqueues intelligence processing (spec section
        14's "Unique IP Queue") exactly once. An IP that already existed
        only gets its last_seen_at bumped here - re-queuing it because its
        WHOIS went stale is Phase 5's job (needs_whois_check above), not
        this reader-facing bookkeeping path, so a busy log doesn't flood
        the "ips" queue with no-op messages every 30s for IPs nothing can
        act on yet.
        """
        if not sightings:
            return {}

        latest_seen_at: dict[str, datetime] = {}
        for raw_address, seen_at in sightings:
            address = normalize_ip(raw_address)
            if address not in latest_seen_at or seen_at > latest_seen_at[address]:
                latest_seen_at[address] = seen_at

        addresses = list(latest_seen_at.keys())
        existing = {ip.address: ip for ip in IPAddress.objects.filter(address__in=addresses)}
        newly_seen_addresses = set(latest_seen_at) - set(existing)

        to_create = [
            IPAddress(
                address=address,
                version=IPAddress.version_of(address),
                first_seen_at=seen_at,
                last_seen_at=seen_at,
            )
            for address, seen_at in latest_seen_at.items()
            if address not in existing
        ]
        if to_create:
            IPAddress.objects.bulk_create(to_create, ignore_conflicts=True)
            # bulk_create(..., ignore_conflicts=True) doesn't populate pk on
            # the in-memory objects, and a concurrent reader may have just
            # created some of these too - re-fetch to get the real rows.
            existing = {ip.address: ip for ip in IPAddress.objects.filter(address__in=addresses)}

        now = timezone.now()
        for address, seen_at in latest_seen_at.items():
            ip_obj = existing[address]
            if seen_at > ip_obj.last_seen_at:
                IPAddress.objects.filter(pk=ip_obj.pk, last_seen_at__lt=seen_at).update(
                    last_seen_at=seen_at, updated_at=now
                )
                ip_obj.last_seen_at = seen_at

        if newly_seen_addresses:
            # Imported here, not at module level, to avoid a hard import
            # cycle risk between services.py and tasks.py at app-loading time.
            from .tasks import process_new_ip

            for address in newly_seen_addresses:
                ip_obj = existing.get(address)
                if ip_obj is not None:
                    process_new_ip.delay(ip_obj.id)

        return existing
