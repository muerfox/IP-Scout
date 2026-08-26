from __future__ import annotations

from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> str | None:
    """Best-effort client IP extraction, honoring a trusted reverse proxy.

    Only the first hop of X-Forwarded-For is trusted; IP Scout is expected
    to sit behind a single Nginx reverse proxy (see docker/nginx).
    """
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")
