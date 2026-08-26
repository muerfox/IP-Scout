from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.logs.models import LogSource
from apps.servers.models import Server


@login_required
def index(request):
    # Iranian IPs / WHOIS Queue depend on apps.whois / apps.iran, which
    # don't exist yet (phases 4-6) - left as an explicit TODO rather than
    # fake numbers, see spec section 63. Totals below are all-time, not
    # time-windowed - proper time filters are Phase 8 (dashboard charts).
    stat_cards = [
        {"label": "503 Requests", "value": RequestEvent.objects.count()},
        {"label": "Unique IPs", "value": IPAddress.objects.count()},
        {"label": "Iranian IPs", "value": None},
        {"label": "Active Servers", "value": Server.objects.filter(enabled=True).count()},
        {"label": "Monitored Logs", "value": LogSource.objects.filter(enabled=True).count()},
        {"label": "WHOIS Queue", "value": None},
    ]
    return render(request, "dashboard/index.html", {"stat_cards": stat_cards})
