from django.contrib.auth.models import AbstractUser
from django.db import models

from apps.common.models import TimeStampedModel


class User(AbstractUser):
    """IP Scout operator account.

    Authorization is handled through Django's built-in groups/permissions
    (see admin) rather than a bespoke role field, so new roles don't require
    a migration.
    """

    class Meta:
        db_table = "users"
        ordering = ["username"]

    def __str__(self) -> str:
        return self.get_username()


class AuditLogEntry(TimeStampedModel):
    """Immutable record of an administrative action (spec section 44).

    Populated via `apps.users.services.record_audit_log`, never edited
    in place - the admin/API only ever expose read access.
    """

    class Result(models.TextChoices):
        SUCCESS = "success", "Success"
        FAILURE = "failure", "Failure"

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_log_entries",
    )
    action = models.CharField(max_length=100, db_index=True)
    object_type = models.CharField(max_length=100, blank=True)
    object_id = models.CharField(max_length=100, blank=True)
    object_repr = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    result = models.CharField(max_length=10, choices=Result.choices, default=Result.SUCCESS)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "audit_log_entries"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["action", "-created_at"]),
            models.Index(fields=["object_type", "object_id"]),
        ]
        verbose_name = "Audit log entry"
        verbose_name_plural = "Audit log entries"

    def __str__(self) -> str:
        who = self.user.get_username() if self.user else "system"
        return f"{who} {self.action} ({self.result})"
