import csv
import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from apps.servers.models import Server
from apps.users.services import record_audit_log

from .export import ExportFilters, IPExportService
from .forms import CountryNetworkForm
from .models import CountryNetwork, IPCountryHistory

_EXPORT_FIELDS = (
    "address",
    "version",
    "country_code",
    "asn",
    "organization",
    "is_iran",
    "iran_match_cidr",
    "first_seen_at",
    "last_seen_at",
)


@login_required
def iranian_ips(request):
    """Thin redirect so the nav can point somewhere real without adding
    query-string support to NavItem - the IP list already knows how to
    filter to is_iran=true."""
    return redirect(f"{reverse('ips:list')}?is_iran=true")


@login_required
def cidr_list(request):
    queryset = CountryNetwork.objects.all()
    paginator = Paginator(queryset, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "iran/cidrs.html", {"page_obj": page_obj})


@login_required
def cidr_create(request):
    if request.method == "POST":
        form = CountryNetworkForm(request.POST)
        if form.is_valid():
            network = form.save()
            record_audit_log("iran_cidr.added", obj=network)
            messages.success(request, f"Added {network.country_code} {network.cidr}.")
            return redirect("iran:cidrs")
    else:
        form = CountryNetworkForm(initial={"country_code": "IR"})
    return render(request, "iran/cidr_form.html", {"form": form})


@login_required
@require_POST
def cidr_toggle_enabled(request, pk):
    network = get_object_or_404(CountryNetwork, pk=pk)
    network.enabled = not network.enabled
    network.save(update_fields=["enabled", "updated_at"])
    record_audit_log("iran_cidr.enabled" if network.enabled else "iran_cidr.disabled", obj=network)
    if request.headers.get("HX-Request"):
        return render(request, "iran/partials/cidr_row.html", {"network": network})
    return redirect("iran:cidrs")


@login_required
def changes_list(request):
    queryset = IPCountryHistory.objects.select_related("ip").all()
    paginator = Paginator(queryset, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "iran/changes.html", {"page_obj": page_obj})


@login_required
def export_view(request):
    filters = ExportFilters.from_querydict(request.GET)
    queryset = IPExportService.build_queryset(filters)
    addresses = list(queryset.values_list("address", flat=True))
    servers = Server.objects.filter(enabled=True).order_by("name")
    return render(
        request,
        "iran/export.html",
        {
            "addresses": addresses,
            "count": len(addresses),
            "filters": filters,
            "servers": servers,
            "querystring": request.GET.urlencode(),
        },
    )


@login_required
def export_download(request):
    fmt = request.GET.get("format", "txt")
    filters = ExportFilters.from_querydict(request.GET)
    queryset = IPExportService.build_queryset(filters)

    record_audit_log(
        "iran.export", metadata={"format": fmt, "filters": vars(filters), "count": queryset.count()}
    )

    if fmt == "csv":
        return _export_csv(queryset)
    if fmt == "json":
        return _export_json(queryset)
    return _export_txt(queryset)


def _export_txt(queryset) -> HttpResponse:
    body = "\n".join(queryset.values_list("address", flat=True))
    if body:
        body += "\n"
    response = HttpResponse(body, content_type="text/plain")
    response["Content-Disposition"] = 'attachment; filename="iran-ips.txt"'
    return response


def _export_csv(queryset) -> HttpResponse:
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="iran-ips.csv"'
    writer = csv.writer(response)
    writer.writerow(_EXPORT_FIELDS)
    for row in queryset.values(*_EXPORT_FIELDS):
        writer.writerow([row[field] for field in _EXPORT_FIELDS])
    return response


def _export_json(queryset) -> HttpResponse:
    data = list(queryset.values(*_EXPORT_FIELDS))
    response = HttpResponse(json.dumps(data, default=str, indent=2), content_type="application/json")
    response["Content-Disposition"] = 'attachment; filename="iran-ips.json"'
    return response
