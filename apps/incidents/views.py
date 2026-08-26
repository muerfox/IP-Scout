"""503 Intelligence UI (spec section 25): "Which Iranian IPs are
currently generating 503 requests?" - an overview (stat cards + a
compact top-N table), the full sortable/filterable IPs table, and a
global chronological event timeline.
"""
from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count
from django.shortcuts import render

from apps.ips.models import IPAddress
from apps.servers.models import Server

from .models import RequestEvent

_ALLOWED_SORTS = {
    "address",
    "-address",
    "event_count",
    "-event_count",
    "last_seen_at",
    "-last_seen_at",
    "first_seen_at",
    "-first_seen_at",
    "asn",
    "-asn",
}


def _ips_with_503(request) -> tuple:
    queryset = IPAddress.objects.annotate(event_count=Count("request_events")).filter(
        event_count__gt=0
    )

    is_iran = request.GET.get("is_iran")
    if is_iran == "true":
        queryset = queryset.filter(is_iran=True)

    sort = request.GET.get("sort", "-event_count")
    if sort not in _ALLOWED_SORTS:
        sort = "-event_count"
    queryset = queryset.order_by(sort)

    return queryset, sort, is_iran


@login_required
def overview(request):
    total_503 = RequestEvent.objects.count()
    unique_ips = RequestEvent.objects.values("ip_id").distinct().count()
    iranian_ips = RequestEvent.objects.filter(ip__is_iran=True).values("ip_id").distinct().count()
    iranian_pct = round(iranian_ips / unique_ips * 100, 1) if unique_ips else 0

    top_ips = IPAddress.objects.annotate(event_count=Count("request_events")).filter(
        event_count__gt=0
    ).order_by("-event_count")[:10]

    return render(
        request,
        "incidents/overview.html",
        {
            "total_503": total_503,
            "unique_ips": unique_ips,
            "iranian_ips": iranian_ips,
            "iranian_pct": iranian_pct,
            "top_ips": top_ips,
        },
    )


@login_required
def ip_table(request):
    queryset, sort, is_iran = _ips_with_503(request)
    paginator = Paginator(queryset, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request, "incidents/ip_table.html", {"page_obj": page_obj, "sort": sort, "is_iran": is_iran}
    )


@login_required
def timeline(request):
    queryset = RequestEvent.objects.select_related("ip", "server").order_by("-timestamp")

    selected_server = request.GET.get("server", "")
    selected_host = request.GET.get("host", "")
    if selected_server:
        queryset = queryset.filter(server_id=selected_server)
    if selected_host:
        queryset = queryset.filter(host=selected_host)

    paginator = Paginator(queryset, 100)
    page_obj = paginator.get_page(request.GET.get("page"))
    servers = Server.objects.filter(enabled=True).order_by("name")

    return render(
        request,
        "incidents/timeline.html",
        {
            "page_obj": page_obj,
            "servers": servers,
            "selected_server": selected_server,
            "selected_host": selected_host,
        },
    )
