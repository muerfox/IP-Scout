from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.users.services import record_audit_log

from .forms import ServerForm
from .models import Server
from .tasks import discover_server_logs, test_server_connection


@login_required
def server_list(request):
    servers = Server.objects.all().prefetch_related("log_sources")
    return render(request, "servers/list.html", {"servers": servers})


@login_required
def server_create(request):
    if request.method == "POST":
        form = ServerForm(request.POST)
        if form.is_valid():
            server = form.save()
            record_audit_log("server.added", obj=server)
            messages.success(request, f"Server “{server.name}” added.")
            return redirect("servers:detail", pk=server.pk)
    else:
        form = ServerForm()
    return render(request, "servers/form.html", {"form": form, "is_new": True})


@login_required
def server_update(request, pk):
    server = get_object_or_404(Server, pk=pk)
    if request.method == "POST":
        form = ServerForm(request.POST, instance=server)
        if form.is_valid():
            form.save()
            record_audit_log("server.updated", obj=server)
            messages.success(request, f"Server “{server.name}” updated.")
            return redirect("servers:detail", pk=server.pk)
    else:
        form = ServerForm(instance=server)
    return render(request, "servers/form.html", {"form": form, "is_new": False, "server": server})


@login_required
@require_POST
def server_delete(request, pk):
    server = get_object_or_404(Server, pk=pk)
    name = server.name
    record_audit_log("server.deleted", obj=server)
    server.delete()
    messages.success(request, f"Server “{name}” deleted.")
    return redirect("servers:list")


@login_required
@require_POST
def server_toggle_enabled(request, pk):
    server = get_object_or_404(Server, pk=pk)
    server.enabled = not server.enabled
    server.save(update_fields=["enabled", "updated_at"])
    record_audit_log("server.enabled" if server.enabled else "server.disabled", obj=server)
    if request.headers.get("HX-Request"):
        return render(request, "servers/partials/status_badge.html", {"server": server})
    return redirect("servers:detail", pk=server.pk)


@login_required
def server_status_badge(request, pk):
    server = get_object_or_404(Server, pk=pk)
    return render(request, "servers/partials/status_badge.html", {"server": server})


@login_required
def server_detail(request, pk):
    server = get_object_or_404(Server, pk=pk)
    log_sources = server.log_sources.annotate(event_count=Count("request_events")).all()
    return render(request, "servers/detail.html", {"server": server, "log_sources": log_sources})


@login_required
@require_POST
def server_test_connection(request, pk):
    server = get_object_or_404(Server, pk=pk)
    test_server_connection.delay(server.id, user_id=request.user.id)
    messages.info(request, "Connection test queued.")
    if request.headers.get("HX-Request"):
        return render(request, "servers/partials/status_badge.html", {"server": server, "queued": True})
    return redirect("servers:detail", pk=server.pk)


@login_required
@require_POST
def server_discover_logs(request, pk):
    server = get_object_or_404(Server, pk=pk)
    discover_server_logs.delay(server.id, user_id=request.user.id)
    messages.info(request, "Log discovery queued — refresh in a few seconds.")
    return redirect("servers:detail", pk=server.pk)
