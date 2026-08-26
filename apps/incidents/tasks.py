"""Retention/purge for RequestEvent (spec section 38)."""
from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task

from django.conf import settings
from django.utils import timezone

from .models import RequestEvent

logger = logging.getLogger("ipscout.incidents")


@shared_task(queue="maintenance")
def purge_old_request_events() -> int:
    cutoff = timezone.now() - timedelta(days=settings.REQUEST_RETENTION_DAYS)
    queryset = RequestEvent.objects.filter(timestamp__lt=cutoff)
    count = queryset.count()
    if count:
        queryset.delete()
    logger.info("purge_old_request_events: deleted %d event(s) older than %d days", count, settings.REQUEST_RETENTION_DAYS)
    return count
