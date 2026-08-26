from collections.abc import Callable

from django.http import HttpRequest, HttpResponse

from apps.common.utils import get_client_ip

from . import context


class AuditLogMiddleware:
    """Publishes the current user/IP into a contextvar for the duration of
    the request, so `apps.users.services.record_audit_log` can attribute
    actions without every call site needing to accept `request`.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        user = getattr(request, "user", None)
        token = context.set_context(
            user_id=user.id if user and user.is_authenticated else None,
            ip_address=get_client_ip(request),
        )
        try:
            return self.get_response(request)
        finally:
            context.reset_context(token)
