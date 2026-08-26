"""Nginx log sources and the incremental log reader/parser (spec sections 8-11).

The reader/parser themselves (inode/offset tracking in motion, line
parsing, 503 extraction) land in Phase 3. This phase only defines the
LogSource record that discovery (apps.servers) populates.
"""
from __future__ import annotations

from django.db import models

from apps.common.models import TimeStampedModel
from apps.servers.models import Server


class LogSource(TimeStampedModel):
    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="log_sources")
    name = models.CharField(max_length=255, help_text="Usually the file's basename.")
    path = models.CharField(max_length=1024)
    format = models.CharField(
        max_length=50,
        default="combined",
        help_text="Nginx log_format name this file is written in. Used by the parser from Phase 3 onward.",
    )
    enabled = models.BooleanField(default=False, help_text="Whether the reader should monitor this file.")

    # Incremental-read state (spec section 9) - populated once Phase 3's
    # reader runs. inode/byte_offset together (not byte_offset alone)
    # let the reader detect logrotate replacing the file.
    inode = models.BigIntegerField(null=True, blank=True)
    byte_offset = models.BigIntegerField(default=0)

    last_read_at = models.DateTimeField(null=True, blank=True)
    last_event_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        db_table = "log_sources"
        ordering = ["server__name", "path"]
        constraints = [
            models.UniqueConstraint(fields=["server", "path"], name="unique_log_source_per_server_path"),
        ]
        indexes = [
            models.Index(fields=["server", "enabled"]),
        ]

    def __str__(self) -> str:
        return f"{self.server.name}:{self.path}"

    @property
    def reader_status(self) -> str:
        if not self.enabled:
            return "disabled"
        if self.last_error:
            return "error"
        if self.last_read_at:
            return "running"
        return "pending"
