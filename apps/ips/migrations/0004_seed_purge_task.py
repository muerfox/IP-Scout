"""Seeds a django-celery-beat PeriodicTask running the retention/purge
job daily (spec section 38). Editable afterward from
/admin/django_celery_beat/periodictask/ or Settings > Retention.
"""
from django.db import migrations

TASK_NAME = "Daily retention purge"
TASK_PATH = "apps.ips.tasks.purge_old_data"


def create_periodic_task(apps, schema_editor):
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = CrontabSchedule.objects.get_or_create(
        minute="0",
        hour="2",
        day_of_month="*",
        month_of_year="*",
        day_of_week="*",
        defaults={"timezone": "UTC"},
    )
    PeriodicTask.objects.get_or_create(
        name=TASK_NAME,
        defaults={"crontab": schedule, "task": TASK_PATH, "queue": "maintenance"},
    )


def remove_periodic_task(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name=TASK_NAME).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("ips", "0003_ipaddress_whois_error"),
        ("django_celery_beat", "0001_initial"),
    ]

    operations = [migrations.RunPython(create_periodic_task, remove_periodic_task)]
