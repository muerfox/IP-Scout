from django.contrib import admin

from .models import Server


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ("name", "hostname", "ssh_port", "ssh_auth_type", "enabled", "connection_status", "last_connected_at")
    list_filter = ("enabled", "ssh_auth_type")
    search_fields = ("name", "hostname", "ip_address")
    readonly_fields = ("last_connected_at", "last_error", "created_at", "updated_at")
