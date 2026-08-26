from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.logs.models import LogSource
from apps.servers.models import Server


@login_required
def index(request):
    # 503 Requests / Unique IPs / Iranian IPs / WHOIS Queue depend on
    # apps.incidents / apps.ips / apps.whois, which don't exist yet
    # (phases 3-5) - left as an explicit TODO rather than fake numbers,
    # see spec section 63.
    stat_cards = [
        {"label": "503 Requests", "value": None},
        {"label": "Unique IPs", "value": None},
        {"label": "Iranian IPs", "value": None},
        {"label": "Active Servers", "value": Server.objects.filter(enabled=True).count()},
        {"label": "Monitored Logs", "value": LogSource.objects.filter(enabled=True).count()},
        {"label": "WHOIS Queue", "value": None},
    ]
    return render(request, "dashboard/index.html", {"stat_cards": stat_cards})
