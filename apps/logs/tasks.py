from __future__ import annotations

import logging

from celery import shared_task

from apps.common.locks import LockHeldError, redis_lock

from .models import LogSource
from .services import NginxLogReader

logger = logging.getLogger("ipscout.logs")


@shared_task(queue="logs")
def poll_log_source(log_source_id: int) -> None:
    try:
        log_source = LogSource.objects.select_related("server").get(pk=log_source_id)
    except LogSource.DoesNotExist:
        return
    if not log_source.enabled or not log_source.server.enabled:
        return

    lock_key = f"logreader:{log_source.server_id}:{log_source_id}"
    try:
        with redis_lock(lock_key, timeout=120):
            summary = NginxLogReader(log_source).poll()
    except LockHeldError:
        logger.info("poll_log_source: %s already running, skipping", log_source_id)
        return

    if summary.rotated:
        logger.info("poll_log_source: %s detected log rotation", log_source_id)
    if summary.events_created:
        logger.info(
            "poll_log_source: %s created %d RequestEvent(s) from %d line(s)",
            log_source_id,
            summary.events_created,
            summary.lines_read,
        )


@shared_task(queue="logs")
def poll_all_log_sources() -> None:
    """Celery Beat dispatcher - fans out one poll_log_source task per
    enabled log source on an enabled server. See the data migration in
    this app for the periodic schedule."""
    ids = LogSource.objects.filter(enabled=True, server__enabled=True).values_list("id", flat=True)
    for log_source_id in ids:
        poll_log_source.delay(log_source_id)
