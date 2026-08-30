from __future__ import annotations

import logging

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.common.locks import LockHeldError, redis_lock
from apps.logs.models import LogSource
from apps.users.models import AuditLogEntry
from apps.users.services import record_audit_log

from .models import Server
from .services import SSHConnectionError, SSHService

logger = logging.getLogger("ipscout.servers")


def _resolve_user(user_id: int | None):
    if not user_id:
        return None
    return get_user_model().objects.filter(pk=user_id).first()


@shared_task(queue="maintenance")
def test_server_connection(server_id: int, user_id: int | None = None) -> None:
    try:
        server = Server.objects.get(pk=server_id)
    except Server.DoesNotExist:
        logger.warning("test_server_connection: server %s no longer exists", server_id)
        return

    user = _resolve_user(user_id)
    lock_timeout = settings.SSH_CONNECT_TIMEOUT + 30

    try:
        with redis_lock(f"ssh:test:{server_id}", timeout=lock_timeout):
            result = SSHService(server).test_connection()
    except LockHeldError:
        logger.info("test_server_connection: %s already running, skipping", server_id)
        return

    if result.success:
        server.last_connected_at = timezone.now()
        server.last_error = ""
    else:
        server.last_error = result.error or "Unknown SSH error"
    server.save(update_fields=["last_connected_at", "last_error", "updated_at"])

    record_audit_log(
        "server.test_connection",
        obj=server,
        result=AuditLogEntry.Result.SUCCESS if result.success else AuditLogEntry.Result.FAILURE,
        metadata={
            "os_name": result.os_name,
            "nginx_found": result.nginx_found,
            "nginx_version": result.nginx_version,
            "error": result.error,
        },
        user=user,
    )


@shared_task(queue="maintenance")
def discover_server_logs(server_id: int, user_id: int | None = None) -> None:
    try:
        server = Server.objects.get(pk=server_id)
    except Server.DoesNotExist:
        logger.warning("discover_server_logs: server %s no longer exists", server_id)
        return

    user = _resolve_user(user_id)
    lock_timeout = settings.SSH_CONNECT_TIMEOUT + 60

    try:
        with redis_lock(f"ssh:discover:{server_id}", timeout=lock_timeout):
            try:
                files = SSHService(server).discover_logs(server.log_search_paths)
            except SSHConnectionError as exc:
                server.last_error = str(exc)
                server.save(update_fields=["last_error", "updated_at"])
                record_audit_log(
                    "server.discover_logs",
                    obj=server,
                    result=AuditLogEntry.Result.FAILURE,
                    metadata={"error": str(exc)},
                    user=user,
                )
                return
    except LockHeldError:
        logger.info("discover_server_logs: %s already running, skipping", server_id)
        return

    created = 0
    for discovered_file in files:
        _, was_created = LogSource.objects.get_or_create(
            server=server,
            path=discovered_file.path,
            defaults={"name": discovered_file.path.rsplit("/", 1)[-1]},
        )
        if was_created:
            created += 1

    server.last_connected_at = timezone.now()
    server.last_error = ""
    server.save(update_fields=["last_connected_at", "last_error", "updated_at"])

    record_audit_log(
        "server.discover_logs",
        obj=server,
        result=AuditLogEntry.Result.SUCCESS,
        metadata={"discovered": len(files), "created": created},
        user=user,
    )
