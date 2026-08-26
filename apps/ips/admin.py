from django.contrib import admin

from .models import IPAddress


@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    list_display = ("address", "version", "first_seen_at", "last_seen_at")
    list_filter = ("version",)
    search_fields = ("address",)
    readonly_fields = ("created_at", "updated_at")
