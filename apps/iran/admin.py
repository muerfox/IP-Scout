from django.contrib import admin

from .models import CountryNetwork, IPCountryHistory


@admin.register(CountryNetwork)
class CountryNetworkAdmin(admin.ModelAdmin):
    list_display = (
        "country_code",
        "cidr",
        "network",
        "source",
        "enabled",
        "last_verified_at",
    )
    list_filter = ("country_code", "source", "enabled")
    search_fields = ("cidr", "network")
    readonly_fields = ("prefix_length", "last_verified_at", "created_at", "updated_at")


@admin.register(IPCountryHistory)
class IPCountryHistoryAdmin(admin.ModelAdmin):
    list_display = ("ip", "country_code", "source", "cidr", "valid_from", "valid_until", "confidence")
    list_filter = ("country_code", "source")
    search_fields = ("ip__address",)
    date_hierarchy = "valid_from"
    readonly_fields = [f.name for f in IPCountryHistory._meta.fields]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False
