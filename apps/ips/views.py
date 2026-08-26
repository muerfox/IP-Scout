from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.users.services import record_audit_log

from .models import IPAddress


@login_required
def ip_list(request):
    queryset = IPAddress.objects.all()
    query = request.GET.get("q", "").strip()
    if query:
        queryset = queryset.filter(address__icontains=query)

    is_iran = request.GET.get("is_iran")
    if is_iran == "true":
        queryset = queryset.filter(is_iran=True)

    paginator = Paginator(queryset, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request, "ips/list.html", {"page_obj": page_obj, "query": query, "is_iran": is_iran}
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
    return redirect("ips:list")


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
    return redirect("ips:list")
