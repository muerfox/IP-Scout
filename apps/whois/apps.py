from django.apps import AppConfig


class WhoisConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.whois"
    label = "whois"
    verbose_name = "WHOIS"
