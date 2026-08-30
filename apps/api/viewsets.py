"""Read-only DRF ViewSets (spec section 39). Read-only deliberately:
mutating a Server (which touches encrypted SSH credentials), toggling a
LogSource, or forcing WHOIS/Iran recalculation all stay web-UI-only
actions (audit-logged, CSRF-protected forms) rather than a second,
parallel JSON surface for the same security-sensitive operations. This
API is for querying and integration, matching spec section 40's example
queries - all of them are GETs.
"""
from __future__ import annotations

from datetime import timedelta

from django.utils import timezone
from rest_framework import viewsets
from rest_framework.decorators import action

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.iran.models import CountryNetwork
from apps.logs.models import LogSource
from apps.servers.models import Server

from .serializers import (
    CountryNetworkSerializer,
    IPAddressSerializer,
    LogSourceSerializer,
    RequestEventSerializer,
    ServerSerializer,
    WhoisRecordSerializer,
)


class ServerViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Server.objects.all()
    serializer_class = ServerSerializer
    filterset_fields = ["enabled", "ssh_auth_type"]
    search_fields = ["name", "hostname"]
    ordering_fields = ["name", "last_connected_at", "created_at"]

    @action(detail=True, methods=["get"], url_path="logs")
    def logs(self, request, pk=None):
        """GET /api/v1/servers/{id}/logs/ (spec section 39)."""
        server = self.get_object()
        page = self.paginate_queryset(server.log_sources.all())
        serializer = LogSourceSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class LogSourceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = LogSource.objects.select_related("server").all()
    serializer_class = LogSourceSerializer
    filterset_fields = ["enabled", "server"]
    search_fields = ["path", "name"]
    ordering_fields = ["last_read_at", "last_event_at"]


class IPAddressViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = IPAddress.objects.all()
    serializer_class = IPAddressSerializer
    filterset_fields = ["is_iran", "version", "whois_status"]
    search_fields = ["address", "organization", "network"]
    ordering_fields = ["last_seen_at", "first_seen_at", "asn"]

    def get_queryset(self):
        # ?country=IR (spec section 40) - the model field is country_code,
        # but the example query names it "country", so this isn't a plain
        # filterset_fields entry.
        queryset = super().get_queryset()
        country = self.request.query_params.get("country")
        if country:
            queryset = queryset.filter(country_code__iexact=country)
        return queryset

    @action(detail=True, methods=["get"])
    def events(self, request, pk=None):
        """GET /api/v1/ips/{id}/events/ (spec section 39)."""
        ip = self.get_object()
        page = self.paginate_queryset(ip.request_events.order_by("-timestamp"))
        serializer = RequestEventSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    @action(detail=True, methods=["get"])
    def whois(self, request, pk=None):
        """GET /api/v1/ips/{id}/whois/ (spec section 39)."""
        ip = self.get_object()
        page = self.paginate_queryset(ip.whois_records.order_by("-queried_at"))
        serializer = WhoisRecordSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class RequestEventViewSet(viewsets.ReadOnlyModelViewSet):
    """Registered at "503" (spec section 39: /api/v1/503/)."""

    queryset = RequestEvent.objects.select_related("ip", "server").order_by("-timestamp")
    serializer_class = RequestEventSerializer
    filterset_fields = ["server", "status"]
    search_fields = ["host", "uri"]
    ordering_fields = ["timestamp"]

    def get_queryset(self):
        queryset = super().get_queryset()

        # ?days=7 (spec section 40)
        days = self.request.query_params.get("days")
        if days:
            try:
                since = timezone.now() - timedelta(days=int(days))
            except ValueError:
                pass
            else:
                queryset = queryset.filter(timestamp__gte=since)

        # ?is_iran=true (spec section 40)
        if self.request.query_params.get("is_iran") == "true":
            queryset = queryset.filter(ip__is_iran=True)

        return queryset


class IranIPViewSet(viewsets.ReadOnlyModelViewSet):
    """GET /api/v1/iran/ips/ (spec section 40's literal example)."""

    queryset = IPAddress.objects.filter(is_iran=True)
    serializer_class = IPAddressSerializer
    search_fields = ["address", "organization"]
    ordering_fields = ["last_seen_at"]


class CountryNetworkViewSet(viewsets.ReadOnlyModelViewSet):
    """Registered at "iran/cidrs" (spec: /api/v1/iran/cidrs/)."""

    queryset = CountryNetwork.objects.all()
    serializer_class = CountryNetworkSerializer
    filterset_fields = ["country_code", "enabled", "source"]
    search_fields = ["cidr", "network"]
    ordering_fields = ["last_verified_at", "created_at"]
