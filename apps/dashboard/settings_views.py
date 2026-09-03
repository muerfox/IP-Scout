"""Settings pages (spec section 61's "Settings" nav section).

Read-only displays of the *current effective configuration* - never
editable forms. Spec section 51 is explicit that configuration lives in
environment variables ("Never hard-code secrets... nothing read from
os.environ outside config/env.py and config/settings/*.py"); a "Save"
button here would either silently do nothing or require a parallel
DB-backed override mechanism that doesn't exist and would fight with the
env-var source of truth. Where a page's job is to *do* something
(retention has a real purge-now button), that dispatches the same Celery
tasks the schedule already uses - it doesn't touch settings.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from apps.geo.providers import get_provider as get_geo_provider
from apps.ips.models import IPAddress
from apps.ips.services import IPIntelligenceService
from apps.iran.models import CountryNetwork
from apps.users.services import record_audit_log
from apps.whois.models import ProxyEndpoint
from apps.whois.services import WhoisService


@login_required
def settings_whois(request):
    resolved_binary = WhoisService._resolve_binary(settings.WHOIS_BINARY)
    proxychains_binary = shutil.which(settings.WHOIS_PROXYCHAINS_BINARY)
    context = {
        "whois_binary": settings.WHOIS_BINARY,
        "resolved_binary": resolved_binary,
        "binary_found": Path(resolved_binary).exists(),
        "whois_timeout": settings.WHOIS_TIMEOUT,
        "whois_cache_days": settings.WHOIS_CACHE_DAYS,
        "whois_queue_concurrency": settings.WHOIS_QUEUE_CONCURRENCY,
        "whois_pending_count": IPIntelligenceService.whois_pending_queryset().count(),
        "proxychains_binary": settings.WHOIS_PROXYCHAINS_BINARY,
        "proxychains_found": bool(proxychains_binary),
        "proxy_max_failures": settings.WHOIS_PROXY_MAX_FAILURES,
        "total_proxies": ProxyEndpoint.objects.count(),
        "enabled_proxies": ProxyEndpoint.objects.filter(enabled=True).count(),
    }
    return render(request, "dashboard/settings/whois.html", context)


@login_required
def settings_retention(request):
    context = {
        "request_retention_days": settings.REQUEST_RETENTION_DAYS,
        "whois_retention_days": settings.WHOIS_RETENTION_DAYS,
        "ip_retention_days": settings.IP_RETENTION_DAYS,
        "incident_retention_days": settings.INCIDENT_RETENTION_DAYS,
    }
    return render(request, "dashboard/settings/retention.html", context)


@login_required
@require_POST
def run_purge_now(request):
    from apps.ips.tasks import purge_old_data

    purge_old_data.delay()
    record_audit_log("retention.purge_forced")
    messages.info(request, "Retention purge queued.")
    return redirect("dashboard:settings-retention")


@login_required
def settings_geoip(request):
    provider_error = ""
    try:
        get_geo_provider()
    except ImproperlyConfigured as exc:
        provider_error = str(exc)

    context = {
        "geoip_provider": settings.GEOIP_PROVIDER,
        "geoip_database_path": settings.GEOIP_DATABASE_PATH,
        "provider_error": provider_error,
        "ips_with_coordinates": IPAddress.objects.filter(latitude__isnull=False).count(),
    }
    return render(request, "dashboard/settings/geoip.html", context)


@login_required
def settings_iran_sources(request):
    context = {
        "iran_cidr_source": settings.IRAN_CIDR_SOURCE,
        "total_cidrs": CountryNetwork.objects.filter(country_code="IR").count(),
        "enabled_cidrs": CountryNetwork.objects.filter(country_code="IR", enabled=True).count(),
    }
    return render(request, "dashboard/settings/iran_sources.html", context)


@login_required
def settings_users_redirect(request):
    return redirect("/admin/users/user/")
