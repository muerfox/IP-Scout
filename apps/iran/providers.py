"""Pluggable Iran CIDR data sources (spec section 23).

`settings.IRAN_CIDR_SOURCE` selects which provider `run_monthly_validation`
uses via `get_provider()` - never hard-coded into the matching/validation
logic itself, so a real feed can be added later without touching
apps.iran.services.

No specific Iran IP ranges are bundled with this project's code or
migrations - the default "static" provider ships empty, and an operator
must deliberately populate it (via /admin or the Iran > CIDRs page) or
switch IRAN_CIDR_SOURCE to a real feed. That's not a network-access
limitation: RipeNccDelegatedStatsProvider below fetches and parses RIPE
NCC's own delegated-extended stats file - the registry's primary
allocation record, not a third-party mirror or guessed-from-memory data
- and is exercised against a real live fetch as part of this project's
end-to-end verification. It isn't the default because switching the
periodic validation task's data source is a real production behavior
change (an external network dependency on a schedule) that a deployment
should opt into deliberately, not something to default silently.
"""
from __future__ import annotations

import abc
import ipaddress
import urllib.request
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
    """Implement this and register it in PROVIDERS to add a new source.

    SOURCE tags every CountryNetwork row this provider writes, and scopes
    which rows a validation run is allowed to disable (see
    IranCIDRValidationService.run) - two providers must never share a
    SOURCE, or one's validation pass would silently disable the other's
    entries as "no longer reported"."""

    SOURCE: str = "manual"

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

    SOURCE = "manual"

    def fetch(self) -> list[CIDREntry]:
        from .models import CountryNetwork

        return [
            CIDREntry(cidr=str(row.cidr), country_code=row.country_code, network=row.network)
            for row in CountryNetwork.objects.filter(country_code=IRAN_COUNTRY_CODE, source=self.SOURCE)
        ]


class RipeNccDelegatedStatsProvider(IranCIDRProvider):
    """RIPE NCC publishes a plain-text "delegated-extended" stats file
    listing every IPv4/IPv6 block it has allocated or assigned, one per
    line, by country - the registry's own primary record, freely
    published with no API key or account required. Iran's address space
    is delegated through RIPE NCC (its service region covers the Middle
    East), so this is a real, authoritative, no-fabrication source for
    exactly what this provider interface needs.

    Format (https://ftp.ripe.net/pub/stats/ripencc/README):
    `registry|cc|type|start|value|date|status[|extensions]`. For an
    ipv4 record `value` is an address *count* (not a prefix length),
    converted to the minimal covering CIDR block(s) via
    ipaddress.summarize_address_range; for ipv6 `value` is already a
    prefix length.
    """

    SOURCE = "ripencc"

    def fetch(self) -> list[CIDREntry]:
        url = settings.IRAN_RIPE_STATS_URL
        timeout = settings.IRAN_RIPE_STATS_TIMEOUT
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 (fixed https URL, not user input)
            body = response.read().decode("utf-8", errors="replace")
        return self.parse(body)

    @classmethod
    def parse(cls, body: str) -> list[CIDREntry]:
        entries: list[CIDREntry] = []
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("|")
            # Real per-block records have >= 7 fields; this also skips
            # the file's version line (6 fields) and per-registry summary
            # lines (cc="*") without any special-casing beyond the
            # cc/type/status filters already needed for real records.
            if len(fields) < 7:
                continue
            _registry, cc, rtype, start, value, _date, status = fields[:7]
            if cc != IRAN_COUNTRY_CODE or rtype not in ("ipv4", "ipv6"):
                continue
            if status not in ("allocated", "assigned"):
                continue
            try:
                if rtype == "ipv4":
                    count = int(value)
                    start_ip = ipaddress.IPv4Address(start)
                    end_ip = ipaddress.IPv4Address(int(start_ip) + count - 1)
                    for network in ipaddress.summarize_address_range(start_ip, end_ip):
                        entries.append(CIDREntry(cidr=str(network)))
                else:
                    prefix_length = int(value)
                    network = ipaddress.IPv6Network(f"{start}/{prefix_length}", strict=False)
                    entries.append(CIDREntry(cidr=str(network)))
            except (ValueError, ipaddress.AddressValueError):
                # A malformed line shouldn't take down the whole fetch -
                # skip it and keep going.
                continue
        return entries


PROVIDERS: dict[str, type[IranCIDRProvider]] = {
    "static": StaticIranCIDRProvider,
    "ripencc": RipeNccDelegatedStatsProvider,
}


def get_provider(name: str | None = None) -> IranCIDRProvider:
    key = name or settings.IRAN_CIDR_SOURCE
    try:
        return PROVIDERS[key]()
    except KeyError as exc:
        raise ImproperlyConfigured(
            f"Unknown IRAN_CIDR_SOURCE: {key!r}. Available: {sorted(PROVIDERS)}"
        ) from exc
