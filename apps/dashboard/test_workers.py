import unittest

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .workers import QUEUE_NAME_FOR_GROUP, QUEUE_TASK_GROUPS, WorkerMonitoringService, _redis_queue_length

User = get_user_model()


class QueueTaskGroupsTests(unittest.TestCase):
    """Pure structural checks - no DB, no Redis needed."""

    def test_every_group_has_a_queue_name(self):
        self.assertEqual(set(QUEUE_TASK_GROUPS.keys()), set(QUEUE_NAME_FOR_GROUP.keys()))

    def test_every_group_lists_at_least_one_task(self):
        for label, task_names in QUEUE_TASK_GROUPS.items():
            self.assertTrue(task_names, f"{label} has no task names")

    def test_covers_the_five_spec_queues(self):
        self.assertEqual(set(QUEUE_NAME_FOR_GROUP.values()), {"logs", "ips", "whois", "iran", "maintenance"})

    def test_task_names_are_unique_across_groups(self):
        seen: set[str] = set()
        for task_names in QUEUE_TASK_GROUPS.values():
            for name in task_names:
                self.assertNotIn(name, seen, f"{name} listed in more than one group")
                seen.add(name)


class RedisQueueLengthTests(unittest.TestCase):
    def test_unreachable_redis_returns_none_and_error_not_an_exception(self):
        # No Redis is running in this sandbox - this exercises the real
        # failure path, not a simulated one.
        length, error = _redis_queue_length("logs")
        self.assertIsNone(length)
        self.assertTrue(error)


class WorkerMonitoringServiceTests(TestCase):
    def test_build_statuses_returns_one_entry_per_group(self):
        statuses = WorkerMonitoringService.build_statuses()
        self.assertEqual({s.label for s in statuses}, set(QUEUE_TASK_GROUPS.keys()))

    def test_counts_running_failed_completed_from_task_results(self):
        from django_celery_results.models import TaskResult

        now = timezone.now()
        TaskResult.objects.create(
            task_id="t1", task_name="apps.whois.tasks.perform_whois_lookup", status="STARTED"
        )
        TaskResult.objects.create(
            task_id="t2",
            task_name="apps.whois.tasks.perform_whois_lookup",
            status="FAILURE",
            date_done=now,
        )
        TaskResult.objects.create(
            task_id="t3",
            task_name="apps.whois.tasks.perform_whois_lookup",
            status="SUCCESS",
            date_done=now,
        )

        statuses = {s.label: s for s in WorkerMonitoringService.build_statuses()}
        whois_status = statuses["WHOIS Queue"]
        self.assertEqual(whois_status.running, 1)
        self.assertEqual(whois_status.failed_recent, 1)
        self.assertEqual(whois_status.completed_recent, 1)


class WorkersViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="operator", password="s3cur3-pass-1234")
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("dashboard:workers"))
        self.assertEqual(response.status_code, 302)

    def test_renders_all_group_labels(self):
        response = self.client.get(reverse("dashboard:workers"))
        self.assertEqual(response.status_code, 200)
        for label in QUEUE_TASK_GROUPS:
            self.assertContains(response, label)
