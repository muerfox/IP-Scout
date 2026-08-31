"""Browsable WHOIS lookup history (nav: IP Intelligence -> WHOIS).

Read-only - a WhoisRecord is either produced by perform_whois_lookup or
it doesn't exist; there's nothing here for a human to edit. The IP
detail page already lists a given IP's last 5 records, but nowhere in
the UI showed a record's actual raw_response/parsed_data until this.
"""
from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, render

from .models import WhoisRecord


@login_required
def whois_list(request):
    records = WhoisRecord.objects.select_related("ip").all()

    ip_query = request.GET.get("ip", "").strip()
    if ip_query:
        records = records.filter(ip__address__icontains=ip_query)

    paginator = Paginator(records, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "whois/list.html", {"page_obj": page_obj, "ip_query": ip_query})


@login_required
def whois_detail(request, pk):
    record = get_object_or_404(WhoisRecord.objects.select_related("ip"), pk=pk)
    return render(request, "whois/detail.html", {"record": record})
