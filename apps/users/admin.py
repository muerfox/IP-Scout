from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import AuditLogEntry, User

admin.site.register(User, UserAdmin)
admin.site.site_header = "IP Scout Administration"
admin.site.site_title = "IP Scout"
admin.site.index_title = "System Administration"


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(admin.ModelAdmin):
    list_display = ("created_at", "user", "action", "object_type", "object_repr", "result", "ip_address")
    list_filter = ("result", "action", "object_type")
    search_fields = ("action", "object_type", "object_repr", "user__username", "ip_address")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False
