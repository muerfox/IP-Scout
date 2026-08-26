"""Pluggable GeoIP providers (spec section 19: "The data model should
support an external GeoIP provider later. Design the geo application so
the provider can be replaced.").

No geolocation dataset ships with this project. This sandbox has no
network access and no way to obtain or verify a real IP-to-location
database, and fabricating coordinates would be exactly the kind of fake
data the project rules warn against (same reasoning as apps.iran's
provider - see its module docstring). The default "null" provider
honestly returns nothing; MaxMindGeoIPProvider is real, correct code
against the standard `geoip2` library for a deployment that adds its own
GeoLite2-City.mmdb (free with a MaxMind account) and points
GEOIP_DATABASE_PATH at it.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


@dataclass(frozen=True)
class GeoResult:
    country_code: str = ""
    country_name: str = ""
    continent: str = ""
    latitude: float | None = None
    longitude: float | None = None


class GeoIPProvider(abc.ABC):
    @abc.abstractmethod
    def lookup(self, address: str) -> GeoResult | None:
        """Return geo data for `address`, or None if unavailable."""


class NullGeoIPProvider(GeoIPProvider):
    """The honest default: no dataset configured, so no result."""

    def lookup(self, address: str) -> GeoResult | None:
        return None


class MaxMindGeoIPProvider(GeoIPProvider):
    """Reads a local MaxMind GeoLite2-City (or GeoIP2-City) .mmdb file.

    `geoip2` is only imported here, not at module level, so a deployment
    that never configures this provider doesn't need the package
    installed at all.
    """

    def __init__(self, database_path: str | None = None):
        self.database_path = database_path or settings.GEOIP_DATABASE_PATH
        if not self.database_path:
            raise ImproperlyConfigured(
                "GEOIP_DATABASE_PATH must be set to use GEOIP_PROVIDER=maxmind."
            )
        self._reader = None

    def _get_reader(self):
        if self._reader is None:
            try:
                import geoip2.database
            except ImportError as exc:
                raise ImproperlyConfigured(
                    "GEOIP_PROVIDER=maxmind requires the 'geoip2' package (pip install geoip2)."
                ) from exc
            self._reader = geoip2.database.Reader(self.database_path)
        return self._reader

    def lookup(self, address: str) -> GeoResult | None:
        reader = self._get_reader()  # raises ImproperlyConfigured first if geoip2 isn't installed
        import geoip2.errors

        try:
            response = reader.city(address)
        except geoip2.errors.AddressNotFoundError:
            return None

        return GeoResult(
            country_code=response.country.iso_code or "",
            country_name=response.country.name or "",
            continent=response.continent.code or "",
            latitude=response.location.latitude,
            longitude=response.location.longitude,
        )


PROVIDERS: dict[str, type[GeoIPProvider]] = {
    "null": NullGeoIPProvider,
    "maxmind": MaxMindGeoIPProvider,
}


def get_provider(name: str | None = None) -> GeoIPProvider:
    key = name or settings.GEOIP_PROVIDER
    try:
        return PROVIDERS[key]()
    except KeyError as exc:
        raise ImproperlyConfigured(
            f"Unknown GEOIP_PROVIDER: {key!r}. Available: {sorted(PROVIDERS)}"
        ) from exc
