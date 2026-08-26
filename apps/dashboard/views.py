from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.ips.services import IPIntelligenceService
from apps.logs.models import LogSource
from apps.servers.models import Server

from .workers import WorkerMonitoringService


@login_required
def index(request):
    # Stat cards are all-time totals; the charts below them are the
    # time-filtered view (spec section 27), fetched client-side from
    # /api/v1/dashboard/.
    stat_cards = [
        {"label": "503 Requests", "value": RequestEvent.objects.count()},
        {"label": "Unique IPs", "value": IPAddress.objects.count()},
        {"label": "Iranian IPs", "value": IPAddress.objects.filter(is_iran=True).count()},
        {"label": "Active Servers", "value": Server.objects.filter(enabled=True).count()},
        {"label": "Monitored Logs", "value": LogSource.objects.filter(enabled=True).count()},
        {"label": "WHOIS Queue", "value": IPIntelligenceService.whois_pending_queryset().count()},
    ]
    return render(request, "dashboard/index.html", {"stat_cards": stat_cards})


@login_required
def world_map(request):
    """Static shell - all data is fetched client-side from /api/v1/map/
    (spec sections 28-29)."""
    return render(request, "dashboard/map.html")


@login_required
def workers(request):
    return render(request, "dashboard/workers.html", {"statuses": WorkerMonitoringService.build_statuses()})
