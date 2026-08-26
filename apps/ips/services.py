"""IP identity bookkeeping (spec sections 12-14, the "critical 503 rule"
in section 58).

Deliberately narrow for Phase 3: find-or-create + first/last_seen_at
tracking only. Never touches WHOIS/geo/Iran state and never blocks on
anything expensive - safe to call inline from the log parsing pipeline
("Do not perform expensive WHOIS operations synchronously during log
parsing", spec section 13). Queuing WHOIS/geo/Iran intelligence work is
Phase 4-6.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime

from django.utils import timezone

from .models import IPAddress


def normalize_ip(raw: str) -> str:
    """Validate and normalize an IP string (e.g. compresses IPv6).

    Raises ValueError for anything that isn't a valid IPv4/IPv6 address.
    """
    return str(ipaddress.ip_address(raw.strip()))


class IPIntelligenceService:
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

        return existing
