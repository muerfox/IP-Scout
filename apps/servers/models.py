"""SSH server inventory and connection management (spec sections 6-7)."""
from __future__ import annotations

from django.db import models

from apps.common.fields import EncryptedTextField
from apps.common.models import TimeStampedModel


class Server(TimeStampedModel):
    class AuthType(models.TextChoices):
        SSH_KEY = "ssh_key", "SSH Key"
        PASSWORD = "password", "Password"

    name = models.CharField(max_length=100, unique=True)
    hostname = models.CharField(max_length=255, help_text="DNS name or IP address used to connect.")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    ssh_port = models.PositiveIntegerField(default=22)
    ssh_username = models.CharField(max_length=100)
    ssh_auth_type = models.CharField(max_length=10, choices=AuthType.choices, default=AuthType.SSH_KEY)

    # Holds the private key (SSH_KEY auth) or password (PASSWORD auth),
    # whichever ssh_auth_type selects. Encrypted at rest - see
    # apps.common.fields.EncryptedTextField.
    ssh_private_key = EncryptedTextField(blank=True)

    # Extra directories to search during log discovery, beyond the
    # always-scanned /var/log/nginx/ (spec section 7).
    log_search_paths = models.JSONField(default=list, blank=True)

    enabled = models.BooleanField(default=True)

    last_connected_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        db_table = "servers"
        ordering = ["name"]
        indexes = [
            models.Index(fields=["enabled"]),
        ]

    def __str__(self) -> str:
        return self.name

    @property
    def connection_status(self) -> str:
        if not self.enabled:
            return "disabled"
        if self.last_error:
            return "error"
        if self.last_connected_at:
            return "ok"
        return "unknown"
