from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import render

from .models import AuditLogEntry


@login_required
def audit_log_list(request):
    """Read-only surface for AuditLogEntry (spec section 44). The data
    has existed since Phase 1 (every mutating action in the app writes
    one via record_audit_log); this is its first in-app view - previously
    only visible via /admin."""
    queryset = AuditLogEntry.objects.select_related("user").all()

    action = request.GET.get("action", "").strip()
    if action:
        queryset = queryset.filter(action__icontains=action)

    result = request.GET.get("result", "")
    if result in (AuditLogEntry.Result.SUCCESS, AuditLogEntry.Result.FAILURE):
        queryset = queryset.filter(result=result)

    paginator = Paginator(queryset, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request,
        "users/audit_log.html",
        {"page_obj": page_obj, "action": action, "result": result},
    )
