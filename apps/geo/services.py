from __future__ import annotations

from apps.ips.models import IPAddress

from .providers import get_provider


class GeoIPService:
    @staticmethod
    def enrich(ip: IPAddress) -> IPAddress:
        """Look up `ip.address` via the configured provider and persist
        whatever it returns. A None result (the default NullGeoIPProvider,
        or a real provider that simply doesn't recognize the address)
        leaves the geo fields untouched rather than clearing them - we'd
        rather keep stale-but-real data than erase it on a transient miss.
        """
        result = get_provider().lookup(ip.address)
        if result is None:
            return ip

        ip.country_code = result.country_code
        ip.country_name = result.country_name
        ip.continent = result.continent
        ip.latitude = result.latitude
        ip.longitude = result.longitude
        ip.save(
            update_fields=["country_code", "country_name", "continent", "latitude", "longitude", "updated_at"]
        )
        return ip
