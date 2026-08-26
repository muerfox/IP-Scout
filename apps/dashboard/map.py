"""World map data aggregation (spec sections 28-29).

Never sends one marker per IP at scale: below HIGH_ZOOM_THRESHOLD, points
are grid-rounded into aggregate clusters (count only); at or above it,
individual IPs are returned with the full detail the click popup needs
(spec section 28: "IP, Country, ASN, Organization, 503 Count, Last Seen,
Iran Status").
"""
from __future__ import annotations

from datetime import datetime

from django.db.models import Count, Q

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress

HIGH_ZOOM_THRESHOLD = 8
MAX_INDIVIDUAL_POINTS = 2000


def filtered_queryset(status: str, start: datetime, end: datetime):
    """IPAddress rows with known coordinates, filtered by the map's
    status selector (spec section 28: All / 503 / Iran / Non-Iran /
    Unknown)."""
    queryset = IPAddress.objects.filter(latitude__isnull=False, longitude__isnull=False)

    if status == "503":
        ip_ids = (
            RequestEvent.objects.filter(timestamp__gte=start, timestamp__lte=end)
            .values_list("ip_id", flat=True)
            .distinct()
        )
        queryset = queryset.filter(id__in=ip_ids)
    elif status == "iran":
        queryset = queryset.filter(is_iran=True)
    elif status == "non_iran":
        queryset = queryset.filter(is_iran=False, iran_checked_at__isnull=False)
    elif status == "unknown":
        queryset = queryset.filter(iran_checked_at__isnull=True)
    # "all" -> no extra filter

    return queryset


class MapAggregationService:
    @staticmethod
    def build_points(queryset, zoom: int, status: str, start: datetime, end: datetime) -> list[dict]:
        if zoom >= HIGH_ZOOM_THRESHOLD:
            return MapAggregationService._individual_points(queryset, status, start, end)
        return MapAggregationService._clustered_points(queryset, zoom, status)

    @staticmethod
    def _individual_points(queryset, status: str, start: datetime, end: datetime) -> list[dict]:
        annotated = queryset.annotate(
            event_count=Count(
                "request_events",
                filter=Q(request_events__timestamp__gte=start, request_events__timestamp__lte=end),
            )
        )[:MAX_INDIVIDUAL_POINTS]

        return [
            {
                "lat": ip.latitude,
                "lon": ip.longitude,
                "count": 1,
                "status": status,
                "ip_id": ip.id,
                "address": ip.address,
                "country_code": ip.country_code,
                "asn": ip.asn,
                "organization": ip.organization,
                "is_iran": ip.is_iran,
                "event_count": ip.event_count,
                "last_seen_at": ip.last_seen_at.isoformat() if ip.last_seen_at else None,
            }
            for ip in annotated
        ]

    @staticmethod
    def _clustered_points(queryset, zoom: int, status: str) -> list[dict]:
        grid_size = MapAggregationService.grid_size_for_zoom(zoom)
        buckets: dict[tuple[float, float], dict] = {}

        for lat, lon, is_iran in queryset.values_list("latitude", "longitude", "is_iran"):
            key = (round(lat / grid_size) * grid_size, round(lon / grid_size) * grid_size)
            bucket = buckets.setdefault(
                key, {"lat": key[0], "lon": key[1], "count": 0, "iran_count": 0, "status": status}
            )
            bucket["count"] += 1
            if is_iran:
                bucket["iran_count"] += 1

        return list(buckets.values())

    @staticmethod
    def grid_size_for_zoom(zoom: int) -> float:
        """Degrees per grid cell - coarser at low zoom, roughly halving
        per zoom level, floored so it never gets meaninglessly fine."""
        return max(0.5, 40 / (2 ** max(zoom, 0)))
