from django.contrib import admin

from .models import IPAddress


@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    list_display = (
        "address",
        "version",
        "is_iran",
        "country_code",
        "asn",
        "whois_status",
        "first_seen_at",
        "last_seen_at",
    )
    list_filter = ("version", "is_iran", "whois_status")
    search_fields = ("address", "organization", "network")
    readonly_fields = ("first_seen_at", "last_seen_at", "created_at", "updated_at")
