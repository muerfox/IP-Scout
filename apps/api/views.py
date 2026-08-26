"""Chart/map data endpoints (spec section 39: /api/v1/dashboard/, /api/v1/map/)."""
from __future__ import annotations

from dataclasses import asdict

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.dashboard.analytics import DashboardAnalyticsService, resolve_period
from apps.dashboard.map import MapAggregationService, filtered_queryset

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
