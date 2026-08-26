from django.contrib import admin

from .models import WhoisRecord


@admin.register(WhoisRecord)
class WhoisRecordAdmin(admin.ModelAdmin):
    list_display = ("ip", "queried_at", "whois_server", "response_hash")
    search_fields = ("ip__address", "whois_server")
    date_hierarchy = "queried_at"
    readonly_fields = [f.name for f in WhoisRecord._meta.fields]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False
