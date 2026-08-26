from __future__ import annotations

from typing import Any

from . import context
from .models import AuditLogEntry, User


def record_audit_log(
    action: str,
    *,
    obj: Any = None,
    result: str = AuditLogEntry.Result.SUCCESS,
    metadata: dict | None = None,
    user: User | None = None,
    ip_address: str | None = None,
) -> AuditLogEntry:
    """Record one administrative action.

    `user`/`ip_address` default to the current request context (see
    apps.users.middleware.AuditLogMiddleware); pass them explicitly when
    calling from a Celery task, where there is no request.

    Example:
        record_audit_log("server.disabled", obj=server)
        record_audit_log("whois.forced", obj=ip_address_obj, metadata={"reason": "manual"})
    """
    ctx = context.get_context()
    user_id = user.id if user else ctx["user_id"]

    return AuditLogEntry.objects.create(
        user_id=user_id,
        action=action,
        object_type=obj.__class__.__name__ if obj is not None else "",
        object_id=str(getattr(obj, "pk", "")) if obj is not None else "",
        object_repr=str(obj)[:255] if obj is not None else "",
        ip_address=ip_address or ctx["ip_address"],
        result=result,
        metadata=metadata or {},
    )
