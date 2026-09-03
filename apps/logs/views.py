from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.users.services import record_audit_log

from .models import LogSource
from .parsers import NGINX_LOG_FORMATS
from .services import ManualLogUploadService


@login_required
def log_source_list(request):
    log_sources = (
        LogSource.objects.select_related("server").annotate(event_count=Count("request_events")).all()
    )
    return render(request, "logs/list.html", {"log_sources": log_sources})


@login_required
def reader_list(request):
    """Reader diagnostics (nav: Logs -> Readers): the raw incremental-read
    state (inode/byte_offset/last_error) "Log Sources" summarizes into a
    status dot, plus a manual poll trigger - previously the only way to
    run a reader was to wait for Celery Beat's schedule."""
    log_sources = LogSource.objects.select_related("server").all()
    return render(request, "logs/readers.html", {"log_sources": log_sources})


@login_required
@require_POST
def log_source_poll_now(request, pk):
    log_source = get_object_or_404(LogSource, pk=pk)

    from .tasks import poll_log_source

    poll_log_source.delay(log_source.id)
    record_audit_log("logsource.poll_forced", obj=log_source)
    messages.info(request, f"Poll queued for {log_source.path}.")
    return redirect("logs:readers")


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


@login_required
def log_upload(request):
    """Paste or upload a raw nginx access log directly - no Server/SSH
    setup required. Parses and records it immediately (same pipeline
    NginxLogReader uses for live-polled logs) against a fixed, never-
    polled "Manual Uploads" Server."""
    format_choices = list(NGINX_LOG_FORMATS.keys())

    if request.method == "POST":
        format_value = request.POST.get("format", "combined")
        label = request.POST.get("label", "").strip()
        uploaded_file = request.FILES.get("logfile")

        if uploaded_file:
            text = uploaded_file.read().decode("utf-8", errors="replace")
            label = label or uploaded_file.name
        else:
            text = request.POST.get("logtext", "")

        if not text.strip():
            messages.error(request, "Paste some log lines or choose a file to upload.")
            return redirect("logs:upload")

        summary = ManualLogUploadService.ingest(text, format_value, label)
        record_audit_log(
            "logsource.manual_upload",
            metadata={
                "lines_read": summary.lines_read,
                "events_created": summary.events_created,
                "parse_errors": summary.parse_errors,
                "new_ips": summary.new_ips,
            },
        )

        if summary.events_created:
            messages.success(
                request,
                f"Recorded {summary.events_created} request(s) from {summary.lines_read} line(s) "
                f"({summary.new_ips} new IP address(es)). WHOIS/Iran/GeoIP enrichment for new IPs "
                f"runs in the background - check IP Intelligence or Iran > Iranian IPs shortly.",
            )
        else:
            messages.warning(
                request,
                f"No lines matched format {format_value!r} out of {summary.lines_read} line(s) read "
                f"({summary.parse_errors} parse error(s)). Check the format selection.",
            )
        if summary.truncated:
            messages.warning(
                request, f"Only the first {summary.lines_read} lines were processed (upload was larger)."
            )
        return redirect("logs:upload")

    return render(
        request,
        "logs/upload.html",
        {"format_choices": format_choices, "nginx_log_formats": NGINX_LOG_FORMATS},
    )
