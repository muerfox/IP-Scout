"""Dashboard/map/iran-export/workers endpoints (spec section 39:
/api/v1/dashboard/, /api/v1/map/, /api/v1/iran/export/, /api/v1/workers/).
"""
from __future__ import annotations

from dataclasses import asdict

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.dashboard.analytics import DashboardAnalyticsService, resolve_period
from apps.dashboard.map import MapAggregationService, filtered_queryset
from apps.dashboard.workers import WorkerMonitoringService
from apps.iran.export import ExportFilters, IPExportService
from apps.iran.views import _export_csv, _export_json, _export_txt
from apps.users.services import record_audit_log

VALID_MAP_STATUSES = {"all", "503", "iran", "non_iran", "unknown"}


class DashboardDataView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        period = request.query_params.get("period", "24h")
        start, end = resolve_period(period, request.query_params.get("start"), request.query_params.get("end"))
        series = DashboardAnalyticsService.build(start, end)
        return Response(
            {"period": period, "start": start.isoformat(), "end": end.isoformat(), **asdict(series)}
        )


class MapDataView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        status = request.query_params.get("status", "503")
        if status not in VALID_MAP_STATUSES:
            status = "503"

        period = request.query_params.get("period", "24h")
        start, end = resolve_period(period, request.query_params.get("start"), request.query_params.get("end"))

        try:
            zoom = int(request.query_params.get("zoom", 2))
        except ValueError:
            zoom = 2

        queryset = filtered_queryset(status, start, end)
        points = MapAggregationService.build_points(queryset, zoom, status, start, end)
        return Response({"status": status, "zoom": zoom, "points": points})


class IranExportAPIView(APIView):
    """GET /api/v1/iran/export/?format=txt|csv|json (spec sections 24, 40).

    A DRF APIView (not a plain reuse of apps.iran.views.export_download)
    specifically so this goes through DRF's JWT authentication - a plain
    `@login_required` view only recognizes a session cookie, which an
    external API client authenticating with a bearer token wouldn't have.
    The actual filtering/response-building code is reused, not duplicated.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        fmt = request.query_params.get("format", "txt")
        filters = ExportFilters.from_querydict(request.query_params)
        queryset = IPExportService.build_queryset(filters)

        record_audit_log(
            "iran.export",
            metadata={"format": fmt, "filters": vars(filters), "count": queryset.count(), "via": "api"},
            user=request.user,
        )

        if fmt == "csv":
            return _export_csv(queryset)
        if fmt == "json":
            return _export_json(queryset)
        return _export_txt(queryset)


class WorkersAPIView(APIView):
    """GET /api/v1/workers/ (spec sections 34, 39)."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        statuses = [asdict(status) for status in WorkerMonitoringService.build_statuses()]
        return Response({"queues": statuses})
