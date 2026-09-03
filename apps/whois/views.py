"""Browsable WHOIS lookup history (nav: IP Intelligence -> WHOIS).

Read-only - a WhoisRecord is either produced by perform_whois_lookup or
it doesn't exist; there's nothing here for a human to edit. The IP
detail page already lists a given IP's last 5 records, but nowhere in
the UI showed a record's actual raw_response/parsed_data until this.
"""
from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.users.services import record_audit_log

from .forms import ProxyEndpointForm
from .models import ObservedNetwork, ProxyEndpoint, WhoisRecord


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


@login_required
def network_list(request):
    """Every CIDR range this deployment's own WHOIS lookups have actually
    observed (nav: IP Intelligence -> Networks) - see
    apps.whois.network_intel.NetworkIntelService, the sole writer."""
    queryset = ObservedNetwork.objects.all()

    country_query = request.GET.get("country", "").strip().upper()
    if country_query:
        queryset = queryset.filter(country_code=country_query)

    paginator = Paginator(queryset, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "whois/networks.html", {"page_obj": page_obj, "country_query": country_query})


@login_required
def proxy_list(request):
    proxies = ProxyEndpoint.objects.all()
    return render(request, "whois/proxies.html", {"proxies": proxies})


@login_required
def proxy_create(request):
    if request.method == "POST":
        form = ProxyEndpointForm(request.POST)
        if form.is_valid():
            proxy = form.save()
            record_audit_log("whois_proxy.added", obj=proxy)
            messages.success(request, f"Added proxy {proxy}.")
            return redirect("whois:proxies")
    else:
        form = ProxyEndpointForm()
    return render(request, "whois/proxy_form.html", {"form": form})


@login_required
@require_POST
def proxy_toggle_enabled(request, pk):
    proxy = get_object_or_404(ProxyEndpoint, pk=pk)
    proxy.enabled = not proxy.enabled
    # Re-enabling by hand is a deliberate operator override - give it a
    # clean slate rather than leaving it one failure away from
    # auto-disabling itself again immediately.
    if proxy.enabled:
        proxy.consecutive_failures = 0
    proxy.save(update_fields=["enabled", "consecutive_failures", "updated_at"])
    record_audit_log("whois_proxy.enabled" if proxy.enabled else "whois_proxy.disabled", obj=proxy)
    if request.headers.get("HX-Request"):
        return render(request, "whois/partials/proxy_row.html", {"proxy": proxy})
    return redirect("whois:proxies")
