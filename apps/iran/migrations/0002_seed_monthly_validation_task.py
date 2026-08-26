"""Seeds a django-celery-beat PeriodicTask running Iran CIDR validation
once a month (spec section 23). Editable afterward from
/admin/django_celery_beat/periodictask/ - this migration only
establishes a sane default.
"""
from django.db import migrations

TASK_NAME = "Monthly Iran CIDR validation"
TASK_PATH = "apps.iran.tasks.run_monthly_iran_validation"


def create_periodic_task(apps, schema_editor):
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = CrontabSchedule.objects.get_or_create(
        minute="0",
        hour="3",
        day_of_month="1",
        month_of_year="*",
        day_of_week="*",
        defaults={"timezone": "UTC"},
    )
    PeriodicTask.objects.get_or_create(
        name=TASK_NAME,
        defaults={"crontab": schedule, "task": TASK_PATH, "queue": "iran"},
    )


def remove_periodic_task(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name=TASK_NAME).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("iran", "0001_initial"),
        ("django_celery_beat", "0001_initial"),
    ]

    operations = [migrations.RunPython(create_periodic_task, remove_periodic_task)]
