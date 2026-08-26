from django.contrib import admin

from .models import LogSource


@admin.register(LogSource)
class LogSourceAdmin(admin.ModelAdmin):
    list_display = ("server", "path", "format", "enabled", "reader_status", "last_read_at", "last_event_at")
    list_filter = ("enabled", "server")
    search_fields = ("path", "name", "server__name")
    readonly_fields = ("inode", "byte_offset", "last_read_at", "last_event_at", "last_error", "created_at", "updated_at")
