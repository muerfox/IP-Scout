from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.users.services import record_audit_log

from .models import LogSource


@login_required
def log_source_list(request):
    log_sources = (
        LogSource.objects.select_related("server").annotate(event_count=Count("request_events")).all()
    )
    return render(request, "logs/list.html", {"log_sources": log_sources})


@login_required
@require_POST
def log_source_toggle_enabled(request, pk):
    log_source = get_object_or_404(LogSource, pk=pk)
    log_source.enabled = not log_source.enabled
    log_source.save(update_fields=["enabled", "updated_at"])
    record_audit_log(
        "logsource.enabled" if log_source.enabled else "logsource.disabled",
        obj=log_source,
    )
    if request.headers.get("HX-Request"):
        return render(request, "logs/partials/log_source_row.html", {"log_source": log_source})
    return redirect("logs:list")
