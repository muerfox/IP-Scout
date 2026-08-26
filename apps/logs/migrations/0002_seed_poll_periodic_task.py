"""Seeds a django-celery-beat PeriodicTask that fans out log polling.

The interval (30s) and everything else about this schedule is editable
afterward from /admin/django_celery_beat/periodictask/ - this migration
only establishes a sane default so polling works out of the box.
"""
from django.db import migrations

TASK_NAME = "Poll enabled log sources"
TASK_PATH = "apps.logs.tasks.poll_all_log_sources"


def create_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(every=30, period="seconds")
    PeriodicTask.objects.get_or_create(
        name=TASK_NAME,
        defaults={"interval": schedule, "task": TASK_PATH, "queue": "logs"},
    )


def remove_periodic_task(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name=TASK_NAME).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("logs", "0001_initial"),
        ("django_celery_beat", "0001_initial"),
    ]

    operations = [migrations.RunPython(create_periodic_task, remove_periodic_task)]
