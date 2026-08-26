from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.ips.services import IPIntelligenceService
from apps.logs.models import LogSource
from apps.servers.models import Server


@login_required
def index(request):
    # All totals below are all-time, not time-windowed - time filters are
    # Phase 8 (dashboard charts).
    stat_cards = [
        {"label": "503 Requests", "value": RequestEvent.objects.count()},
        {"label": "Unique IPs", "value": IPAddress.objects.count()},
        {"label": "Iranian IPs", "value": IPAddress.objects.filter(is_iran=True).count()},
        {"label": "Active Servers", "value": Server.objects.filter(enabled=True).count()},
        {"label": "Monitored Logs", "value": LogSource.objects.filter(enabled=True).count()},
        {"label": "WHOIS Queue", "value": IPIntelligenceService.whois_pending_queryset().count()},
    ]
    return render(request, "dashboard/index.html", {"stat_cards": stat_cards})
