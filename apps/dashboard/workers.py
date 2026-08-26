"""Worker/queue monitoring (spec section 34).

Combines two real, independent sources rather than faking either:
- Queue depth (backlog waiting to be picked up) comes straight from
  Redis - Celery queues are Redis lists, so LLEN is exact and live.
- Running/Failed/Completed/Last execution come from django-celery-results'
  TaskResult table, which workers write to directly (CELERY_TASK_TRACK_STARTED
  makes "STARTED" a real, queryable state, not just an assumption).
Neither needs a currently-running worker to answer - unlike Celery's
`inspect()` RPC, which only reports on workers that happen to be up right
now and returns nothing useful otherwise.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import redis as redis_lib

from django.conf import settings
from django.utils import timezone

QUEUE_TASK_GROUPS: dict[str, list[str]] = {
    "Log Readers": [
        "apps.logs.tasks.poll_log_source",
        "apps.logs.tasks.poll_all_log_sources",
    ],
    "IP Processing": [
        "apps.ips.tasks.process_new_ip",
        "apps.geo.tasks.enrich_ip",
    ],
    "WHOIS Queue": [
        "apps.whois.tasks.perform_whois_lookup",
    ],
    "Iran Validation": [
        "apps.iran.tasks.classify_ip",
        "apps.iran.tasks.run_monthly_iran_validation",
    ],
    "Maintenance": [
        "apps.ips.tasks.purge_old_data",
        "apps.ips.tasks.purge_stale_ips",
        "apps.incidents.tasks.purge_old_request_events",
        "apps.whois.tasks.purge_old_whois_records",
        "apps.servers.tasks.test_server_connection",
        "apps.servers.tasks.discover_server_logs",
    ],
}
QUEUE_NAME_FOR_GROUP: dict[str, str] = {
    "Log Readers": "logs",
    "IP Processing": "ips",
    "WHOIS Queue": "whois",
    "Iran Validation": "iran",
    "Maintenance": "maintenance",
}


@dataclass
class QueueStatus:
    label: str
    queue_name: str
    queued: int | None
    running: int
    failed_recent: int
    completed_recent: int
    last_execution: datetime | None
    redis_error: str = ""


def _redis_queue_length(queue_name: str) -> tuple[int | None, str]:
    try:
        client = redis_lib.from_url(settings.REDIS_URL, socket_connect_timeout=2)
        return client.llen(queue_name), ""
    except redis_lib.RedisError as exc:
        return None, str(exc)


class WorkerMonitoringService:
    @staticmethod
    def build_statuses(recent_window_hours: int = 24) -> list[QueueStatus]:
        from django_celery_results.models import TaskResult

        since = timezone.now() - timedelta(hours=recent_window_hours)
        statuses = []
        for label, task_names in QUEUE_TASK_GROUPS.items():
            queue_name = QUEUE_NAME_FOR_GROUP[label]
            queued, redis_error = _redis_queue_length(queue_name)

            base = TaskResult.objects.filter(task_name__in=task_names)
            last_execution = base.order_by("-date_done").values_list("date_done", flat=True).first()

            statuses.append(
                QueueStatus(
                    label=label,
                    queue_name=queue_name,
                    queued=queued,
                    running=base.filter(status="STARTED").count(),
                    failed_recent=base.filter(status="FAILURE", date_done__gte=since).count(),
                    completed_recent=base.filter(status="SUCCESS", date_done__gte=since).count(),
                    last_execution=last_execution,
                    redis_error=redis_error,
                )
            )
        return statuses
