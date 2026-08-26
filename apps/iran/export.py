"""Iran IP export (spec section 24): a filterable IP list with a
copy-to-clipboard preview and TXT/CSV/JSON downloads.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from django.http import QueryDict
from django.utils import timezone

from apps.ips.models import IPAddress

from .providers import IRAN_COUNTRY_CODE

PERIODS: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def period_since(period: str) -> datetime | None:
    delta = PERIODS.get(period)
    return timezone.now() - delta if delta else None


@dataclass
class ExportFilters:
    period: str = "all"
    server_id: int | None = None
    cidr: str = ""
    status_503_only: bool = True
    iran_status: str = "current"  # "current" | "previous" | "any"

    @classmethod
    def from_querydict(cls, params: QueryDict) -> ExportFilters:
        server_id = params.get("server") or ""
        return cls(
            period=params.get("period", "all"),
            server_id=int(server_id) if server_id.isdigit() else None,
            cidr=params.get("cidr", "").strip(),
            status_503_only=params.get("status_503_only", "true") != "false",
            iran_status=params.get("iran_status", "current"),
        )


class IPExportService:
    @staticmethod
    def build_queryset(filters: ExportFilters):
        from apps.incidents.models import RequestEvent

        queryset = IPAddress.objects.all()

        if filters.status_503_only or filters.server_id or filters.period != "all":
            event_qs = RequestEvent.objects.all()
            if filters.server_id:
                event_qs = event_qs.filter(server_id=filters.server_id)
            since = period_since(filters.period)
            if since:
                event_qs = event_qs.filter(timestamp__gte=since)
            queryset = queryset.filter(id__in=event_qs.values_list("ip_id", flat=True).distinct())

        if filters.cidr:
            queryset = queryset.filter(address__is_contained_by=filters.cidr)

        if filters.iran_status == "current":
            queryset = queryset.filter(is_iran=True)
        elif filters.iran_status == "previous":
            from .models import IPCountryHistory

            previously_iran = IPCountryHistory.objects.filter(
                country_code=IRAN_COUNTRY_CODE, valid_until__isnull=False
            ).values_list("ip_id", flat=True)
            queryset = queryset.filter(id__in=previously_iran, is_iran=False)

        return queryset.order_by("address")
