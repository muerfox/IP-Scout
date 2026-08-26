from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Max, Min, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.servers.models import Server
from apps.users.services import record_audit_log

from .models import IPAddress


@login_required
def ip_list(request):
    queryset = IPAddress.objects.all()

    query = request.GET.get("q", "").strip()
    if query:
        # Free-text: address, organization/network (WHOIS), or country -
        # everything spec section 41 lists as a global-search criterion
        # that isn't already its own dedicated filter (cidr/asn below).
        queryset = queryset.filter(
            Q(address__icontains=query)
            | Q(organization__icontains=query)
            | Q(network__icontains=query)
            | Q(country_code__iexact=query)
        )

    cidr = request.GET.get("cidr", "").strip()
    if cidr:
        queryset = queryset.filter(address__is_contained_by=cidr)

    asn = request.GET.get("asn", "").strip()
    if asn.isdigit():
        queryset = queryset.filter(asn=int(asn))

    is_iran = request.GET.get("is_iran")
    if is_iran == "true":
        queryset = queryset.filter(is_iran=True)

    paginator = Paginator(queryset, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request,
        "ips/list.html",
        {
            "page_obj": page_obj,
            "query": query,
            "cidr": cidr,
            "asn": asn,
            "is_iran": is_iran,
        },
    )


@login_required
def ip_detail(request, pk):
    """Full intelligence page for one IP (spec sections 30-31): every
    IPAddress field, recent WHOIS/Iran history, and a filterable 503
    timeline with aggregate stats."""
    ip = get_object_or_404(IPAddress, pk=pk)

    events = ip.request_events.select_related("server").order_by("-timestamp")
    selected_server = request.GET.get("server", "")
    selected_host = request.GET.get("host", "")
    if selected_server:
        events = events.filter(server_id=selected_server)
    if selected_host:
        events = events.filter(host=selected_host)

    paginator = Paginator(events, 50)
    page_obj = paginator.get_page(request.GET.get("page"))

    stats = ip.request_events.aggregate(count=Count("id"), first=Min("timestamp"), last=Max("timestamp"))
    servers = Server.objects.filter(request_events__ip=ip).distinct().order_by("name")
    hosts = list(ip.request_events.exclude(host="").order_by().values_list("host", flat=True).distinct())

    return render(
        request,
        "ips/detail.html",
        {
            "ip": ip,
            "page_obj": page_obj,
            "stats": stats,
            "servers": servers,
            "hosts": hosts,
            "whois_records": ip.whois_records.order_by("-queried_at")[:5],
            "history": ip.country_history.order_by("-valid_from")[:10],
            "selected_server": selected_server,
            "selected_host": selected_host,
        },
    )


@login_required
def whois_status_cell(request, pk):
    ip = get_object_or_404(IPAddress, pk=pk)
    return render(request, "ips/partials/whois_status.html", {"ip": ip})


@login_required
@require_POST
def force_whois(request, pk):
    ip = get_object_or_404(IPAddress, pk=pk)

    # Imported here, not at module level, to avoid a hard import cycle
    # (apps.whois.tasks imports apps.ips.models/services).
    from apps.whois.tasks import perform_whois_lookup

    perform_whois_lookup.delay(ip.id, force=True)
    record_audit_log("ip.whois_forced", obj=ip)

    if request.headers.get("HX-Request"):
        return render(request, "ips/partials/whois_status.html", {"ip": ip})
    return redirect("ips:detail", pk=ip.pk)


@login_required
def iran_status_cell(request, pk):
    ip = get_object_or_404(IPAddress, pk=pk)
    return render(request, "ips/partials/iran_status.html", {"ip": ip})


@login_required
@require_POST
def recalculate_iran(request, pk):
    ip = get_object_or_404(IPAddress, pk=pk)

    from apps.iran.tasks import classify_ip

    classify_ip.delay(ip.id)
    record_audit_log("ip.iran_recalculated", obj=ip)

    if request.headers.get("HX-Request"):
        return render(request, "ips/partials/iran_status.html", {"ip": ip})
    return redirect("ips:detail", pk=ip.pk)
