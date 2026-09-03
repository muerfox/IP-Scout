"""Turns real WHOIS responses into a growing CIDR intelligence database.

apps.whois.tasks._run_lookup calls NetworkIntelService.record() after every
successful WHOIS lookup that resolved a CIDR. Two things happen:

1. The CIDR is upserted into ObservedNetwork (apps.whois.models) - a
   country-agnostic ledger of every network range this deployment's own
   WHOIS traffic has actually observed, for later analysis/export.
2. If the WHOIS-reported country is Iran, the same CIDR is *also* mirrored
   into apps.iran.models.CountryNetwork (source="whois", the same table
   /admin and the Iran > CIDRs page manage manually). That's what lets the
   Iran CIDR database grow organically from real traffic instead of
   staying limited to whatever an operator entered by hand or pulled from
   RIPE NCC - the next IP seen anywhere in that range gets classified by
   CIDR containment (IranCIDRService.find_matching_cidr), not just an
   exact per-IP whois_country fallback.

Both writes are keyed off data WhoisService actually returned for a real
IP - nothing here invents or guesses a network.
"""
from __future__ import annotations

from datetime import datetime

from django.db import models as db_models

from .models import ObservedNetwork


class NetworkIntelService:
    @staticmethod
    def record(
        cidr: str,
        *,
        country_code: str,
        organization: str,
        network: str,
        asn: int | None,
        seen_at: datetime,
    ) -> ObservedNetwork:
        obj, created = ObservedNetwork.objects.get_or_create(
            cidr=cidr,
            defaults={
                "country_code": country_code,
                "organization": organization,
                "network": network,
                "asn": asn,
                "first_seen_at": seen_at,
                "last_seen_at": seen_at,
            },
        )
        if not created:
            ObservedNetwork.objects.filter(pk=obj.pk).update(
                country_code=country_code or db_models.F("country_code"),
                organization=organization or db_models.F("organization"),
                network=network or db_models.F("network"),
                asn=asn if asn is not None else db_models.F("asn"),
                last_seen_at=seen_at,
                hit_count=db_models.F("hit_count") + 1,
                updated_at=seen_at,
            )
            obj.refresh_from_db()

        if country_code == "IR":
            NetworkIntelService._mirror_into_iran_cidrs(cidr, network, seen_at)

        return obj

    @staticmethod
    def _mirror_into_iran_cidrs(cidr: str, network: str, seen_at: datetime) -> None:
        # Imported lazily - apps.iran imports apps.ips, and this module is
        # reached from apps.whois.tasks, which already has to be careful
        # about import cycles for the same reason (see its own docstring).
        from apps.iran.models import CountryNetwork
        from apps.iran.providers import IRAN_COUNTRY_CODE

        CountryNetwork.objects.get_or_create(
            country_code=IRAN_COUNTRY_CODE,
            cidr=cidr,
            defaults={
                "network": network,
                "source": "whois",
                "enabled": True,
                "last_verified_at": seen_at,
            },
        )
        # If a row already exists (from "manual", "ripencc", or an earlier
        # "whois" hit), leave it exactly as-is - a re-observation isn't
        # more authoritative than whatever source already vouches for this
        # CIDR, and disabling/overwriting another source's entry here
        # would violate the same one-writer-per-SOURCE rule
        # IranCIDRValidationService.run relies on.
