"""Dashboard chart data (spec section 27). One service backing
/api/v1/dashboard/, consumed by Chart.js on the dashboard page.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.db.models import Count
from django.db.models.functions import TruncDay, TruncHour, TruncMinute
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress

PERIOD_DELTAS: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
DEFAULT_PERIOD = "24h"
TOP_N = 10


def resolve_period(
    period: str, custom_start: str | None = None, custom_end: str | None = None
) -> tuple[datetime, datetime]:
    """"1h"/"6h"/"24h"/"7d"/"30d" -> (now - delta, now). "custom" uses the
    given ISO-8601 start/end (falls back to the default period if either
    is missing or unparseable, rather than raising on a malformed
    request)."""
    now = timezone.now()
    if period == "custom" and custom_start and custom_end:
        start = parse_datetime(custom_start)
        end = parse_datetime(custom_end)
        if start and end:
            if timezone.is_naive(start):
                start = timezone.make_aware(start)
            if timezone.is_naive(end):
                end = timezone.make_aware(end)
            return start, end
    delta = PERIOD_DELTAS.get(period, PERIOD_DELTAS[DEFAULT_PERIOD])
    return now - delta, now


def _bucket_trunc(start: datetime, end: datetime):
    """Coarser buckets for a longer window, so a chart never renders
    thousands of points for a 30-day range."""
    duration = end - start
    if duration <= timedelta(hours=2):
        return TruncMinute
    if duration <= timedelta(hours=48):
        return TruncHour
    return TruncDay


@dataclass
class DashboardSeries:
    requests_over_time: list[dict] = field(default_factory=list)
    unique_ips_over_time: list[dict] = field(default_factory=list)
    countries: list[dict] = field(default_factory=list)
    iran_split: dict = field(default_factory=dict)
    top_iranian_ips: list[dict] = field(default_factory=list)
    top_iranian_cidrs: list[dict] = field(default_factory=list)
    top_countries: list[dict] = field(default_factory=list)


class DashboardAnalyticsService:
    @staticmethod
    def build(start: datetime, end: datetime) -> DashboardSeries:
        events = RequestEvent.objects.filter(timestamp__gte=start, timestamp__lte=end)
        trunc = _bucket_trunc(start, end)

        requests_over_time = (
            events.annotate(bucket=trunc("timestamp"))
            .values("bucket")
            .annotate(count=Count("id"))
            .order_by("bucket")
        )
        unique_ips_over_time = (
            events.annotate(bucket=trunc("timestamp"))
            .values("bucket")
            .annotate(count=Count("ip_id", distinct=True))
            .order_by("bucket")
        )

        ip_ids = events.values_list("ip_id", flat=True).distinct()
        ips_in_period = IPAddress.objects.filter(id__in=ip_ids)

        countries = list(
            ips_in_period.exclude(country_code="")
            .values("country_code")
            .annotate(count=Count("id"))
            .order_by("-count")
        )

        iran_split = {
            "iran": ips_in_period.filter(is_iran=True).count(),
            "other": ips_in_period.filter(is_iran=False, iran_checked_at__isnull=False).count(),
            "unknown": ips_in_period.filter(is_iran=False, iran_checked_at__isnull=True).count(),
        }

        top_iranian_ips = (
            events.filter(ip__is_iran=True)
            .values("ip__address")
            .annotate(count=Count("id"))
            .order_by("-count")[:TOP_N]
        )
        top_iranian_cidrs = (
            events.filter(ip__is_iran=True)
            .exclude(ip__iran_match_cidr__isnull=True)
            .values("ip__iran_match_cidr")
            .annotate(count=Count("id"))
            .order_by("-count")[:TOP_N]
        )

        return DashboardSeries(
            requests_over_time=[{"bucket": r["bucket"].isoformat(), "count": r["count"]} for r in requests_over_time],
            unique_ips_over_time=[
                {"bucket": r["bucket"].isoformat(), "count": r["count"]} for r in unique_ips_over_time
            ],
            countries=countries,
            iran_split=iran_split,
            top_iranian_ips=[{"address": r["ip__address"], "count": r["count"]} for r in top_iranian_ips],
            top_iranian_cidrs=[
                {"cidr": r["ip__iran_match_cidr"], "count": r["count"]} for r in top_iranian_cidrs
            ],
            top_countries=countries[:TOP_N],
        )
