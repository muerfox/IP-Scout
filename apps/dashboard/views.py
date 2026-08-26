from django.contrib.auth.decorators import login_required
from django.shortcuts import render

# Populated once apps.incidents / apps.ips / apps.servers / apps.whois exist
# (phases 2-8). Kept as an explicit TODO list rather than fake numbers -
# see spec section 63.
STAT_CARDS = [
    {"label": "503 Requests", "value": None},
    {"label": "Unique IPs", "value": None},
    {"label": "Iranian IPs", "value": None},
    {"label": "Active Servers", "value": None},
    {"label": "Monitored Logs", "value": None},
    {"label": "WHOIS Queue", "value": None},
]


@login_required
def index(request):
    return render(request, "dashboard/index.html", {"stat_cards": STAT_CARDS})
