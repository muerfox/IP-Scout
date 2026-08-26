"""Per-request context so services outside the view layer (forms, model
signals) can attribute an audit log entry to the acting user/IP without
threading `request` through every call.

Celery tasks run outside any request and simply see empty context, which
`record_audit_log` treats as a system-initiated action.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import TypedDict


class RequestContext(TypedDict):
    user_id: int | None
    ip_address: str | None


_context: ContextVar[RequestContext] = ContextVar("ipscout_request_context")


def set_context(*, user_id: int | None, ip_address: str | None) -> None:
    _context.set({"user_id": user_id, "ip_address": ip_address})


def get_context() -> RequestContext:
    return _context.get({"user_id": None, "ip_address": None})
