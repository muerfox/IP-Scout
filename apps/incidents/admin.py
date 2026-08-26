from django.contrib import admin

from .models import RequestEvent


@admin.register(RequestEvent)
class RequestEventAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "ip", "server", "status", "host", "method", "uri")
    list_filter = ("status", "server")
    search_fields = ("ip__address", "host", "uri")
    date_hierarchy = "timestamp"
    readonly_fields = [f.name for f in RequestEvent._meta.fields]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False
