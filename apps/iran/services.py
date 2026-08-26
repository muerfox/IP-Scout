"""Iran CIDR matching, classification history, and monthly validation
(spec sections 21-23).
"""
from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from apps.ips.models import IPAddress

from .models import CountryNetwork, IPCountryHistory
from .providers import IRAN_COUNTRY_CODE, IranCIDRProvider, get_provider


class IranCIDRService:
    @staticmethod
    def find_matching_cidr(address: str) -> CountryNetwork | None:
        """Most specific (longest-prefix) active Iranian CIDR containing
        `address`, or None. Uses PostgreSQL network containment (spec
        section 21) - never a Python string prefix check."""
        return (
            CountryNetwork.objects.filter(
                country_code=IRAN_COUNTRY_CODE, enabled=True, cidr__contains_ip=address
            )
            .order_by("-prefix_length")
            .first()
        )

    @staticmethod
    def classify(ip: IPAddress) -> IPAddress:
        """Determine whether `ip` currently belongs to an active Iranian
        CIDR, persist the result on `ip`, and record an IPCountryHistory
        transition if it actually changed (spec section 22 - allocations
        change, so `is_iran` alone isn't enough to answer "was this IP
        Iranian last month?")."""
        match = IranCIDRService.find_matching_cidr(ip.address)
        now = timezone.now()
        new_is_iran = match is not None
        new_cidr = str(match.cidr) if match else None
        changed = new_is_iran != ip.is_iran or new_cidr != ip.iran_match_cidr

        with transaction.atomic():
            if changed:
                # Close out whatever period was open (a no-op if the IP
                # was never Iranian - the filter simply matches nothing).
                IPCountryHistory.objects.filter(ip=ip, valid_until__isnull=True).update(valid_until=now)
                if new_is_iran:
                    IPCountryHistory.objects.create(
                        ip=ip,
                        country_code=IRAN_COUNTRY_CODE,
                        source=match.source,
                        cidr=new_cidr,
                        valid_from=now,
                        confidence=1.0,
                    )
            ip.is_iran = new_is_iran
            ip.iran_match_cidr = new_cidr
            ip.iran_checked_at = now
            ip.save(update_fields=["is_iran", "iran_match_cidr", "iran_checked_at", "updated_at"])
        return ip


@dataclass
class ValidationSummary:
    fetched: int
    created: int
    disabled: int
    reevaluated: int


class IranCIDRValidationService:
    @staticmethod
    def run(provider: IranCIDRProvider | None = None) -> ValidationSummary:
        """Spec section 23's monthly workflow: fetch the current list from
        `provider`, upsert CountryNetwork, disable entries the source no
        longer reports, then re-evaluate every IP currently flagged
        Iranian (the only ones a removed CIDR could possibly affect - a
        newly *added* CIDR only matters for IPs not yet classified, which
        pick it up the next time they're sighted via classify())."""
        provider = provider or get_provider()
        entries = provider.fetch()
        now = timezone.now()

        created = 0
        fetched_cidrs: set[str] = set()
        for entry in entries:
            fetched_cidrs.add(entry.cidr)
            _, was_created = CountryNetwork.objects.update_or_create(
                country_code=entry.country_code,
                cidr=entry.cidr,
                defaults={
                    "network": entry.network,
                    "source": "manual",
                    "enabled": True,
                    "last_verified_at": now,
                },
            )
            if was_created:
                created += 1

        removed_qs = CountryNetwork.objects.filter(
            country_code=IRAN_COUNTRY_CODE, source="manual", enabled=True
        ).exclude(cidr__in=fetched_cidrs)
        disabled = removed_qs.update(enabled=False, last_verified_at=now)

        reevaluated = 0
        if created or disabled:
            # The set of enabled CIDRs actually changed - every currently-
            # Iranian IP needs a fresh containment check. Unchanged CIDRs
            # can't have altered any IP's classification, so skip the scan
            # entirely on a no-op validation pass (spec section 47: don't
            # do expensive work you don't need to).
            for ip in IPAddress.objects.filter(is_iran=True).iterator():
                IranCIDRService.classify(ip)
                reevaluated += 1

        return ValidationSummary(
            fetched=len(entries), created=created, disabled=disabled, reevaluated=reevaluated
        )
