from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.incidents.models import RequestEvent
from apps.ips.models import IPAddress
from apps.ips.services import IPIntelligenceService
from apps.logs.models import LogSource
from apps.servers.models import Server


@login_required
def index(request):
    # Iranian IPs depends on apps.iran (Phase 6), which doesn't exist yet.
    # is_iran defaults False for every row right now, so a real count
    # would always read "0" and look like a computed negative result
    # rather than "not yet classified" - "pending" is the honest answer
    # (spec section 63). WHOIS Queue is real: it's just a count of IPs
    # due for a check, true today even though nothing consumes it yet.
    # All totals below are all-time, not time-windowed - time filters are
    # Phase 8 (dashboard charts).
    stat_cards = [
        {"label": "503 Requests", "value": RequestEvent.objects.count()},
        {"label": "Unique IPs", "value": IPAddress.objects.count()},
        {"label": "Iranian IPs", "value": None},
        {"label": "Active Servers", "value": Server.objects.filter(enabled=True).count()},
        {"label": "Monitored Logs", "value": LogSource.objects.filter(enabled=True).count()},
        {"label": "WHOIS Queue", "value": IPIntelligenceService.whois_pending_queryset().count()},
    ]
    return render(request, "dashboard/index.html", {"stat_cards": stat_cards})
