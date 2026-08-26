"""Pluggable Iran CIDR data sources (spec section 23).

`settings.IRAN_CIDR_SOURCE` selects which provider `run_monthly_validation`
uses via `get_provider()` - never hard-coded into the matching/validation
logic itself, so a real feed can be added later without touching
apps.iran.services.

No specific Iran IP ranges are bundled with this project. This sandbox
has no network access and no way to verify a dataset's accuracy, and
guessing at specific CIDR blocks from memory for a feature whose entire
purpose is classifying real IPs as Iranian would risk shipping wrong
data presented as authoritative - exactly what the project's rule against
faking functionality exists to prevent. The default "static" provider
instead treats whatever's already in CountryNetwork (entered via
/admin - source="manual") as the source of truth; a production
deployment with a trusted feed (a national registry's delegated stats,
a licensed GeoIP vendor, etc.) should implement a provider against that
feed and set IRAN_CIDR_SOURCE to it.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

IRAN_COUNTRY_CODE = "IR"


@dataclass(frozen=True)
class CIDREntry:
    cidr: str
    country_code: str = IRAN_COUNTRY_CODE
    network: str = ""


class IranCIDRProvider(abc.ABC):
    """Implement this and register it in PROVIDERS to add a new source."""

    @abc.abstractmethod
    def fetch(self) -> list[CIDREntry]:
        """Return the full current list of CIDR entries this source
        considers Iranian (or whatever country it's scoped to)."""


class StaticIranCIDRProvider(IranCIDRProvider):
    """No external fetch. CountryNetwork rows with source="manual" *are*
    the data - an operator adds/edits/disables them via /admin or the
    Iran > CIDRs page. Monthly validation against this provider is a
    self-consistency pass (stamps last_verified_at), not a real update -
    that's expected until a real external-feed provider is configured.
    """

    def fetch(self) -> list[CIDREntry]:
        from .models import CountryNetwork

        return [
            CIDREntry(cidr=str(row.cidr), country_code=row.country_code, network=row.network)
            for row in CountryNetwork.objects.filter(country_code=IRAN_COUNTRY_CODE, source="manual")
        ]


PROVIDERS: dict[str, type[IranCIDRProvider]] = {
    "static": StaticIranCIDRProvider,
}


def get_provider(name: str | None = None) -> IranCIDRProvider:
    key = name or settings.IRAN_CIDR_SOURCE
    try:
        return PROVIDERS[key]()
    except KeyError as exc:
        raise ImproperlyConfigured(
            f"Unknown IRAN_CIDR_SOURCE: {key!r}. Available: {sorted(PROVIDERS)}"
        ) from exc
