from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from apps.users.services import record_audit_log

from .forms import CountryNetworkForm
from .models import CountryNetwork, IPCountryHistory


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
