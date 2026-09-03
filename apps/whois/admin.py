from django.contrib import admin

from .models import ObservedNetwork, ProxyEndpoint, WhoisRecord


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


@admin.register(ObservedNetwork)
class ObservedNetworkAdmin(admin.ModelAdmin):
    list_display = (
        "cidr",
        "country_code",
        "organization",
        "asn",
        "hit_count",
        "first_seen_at",
        "last_seen_at",
    )
    list_filter = ("country_code",)
    search_fields = ("cidr", "organization", "network")
    date_hierarchy = "last_seen_at"
    readonly_fields = [f.name for f in ObservedNetwork._meta.fields]

    def has_add_permission(self, request) -> bool:
        # Real WHOIS-derived data only (apps.whois.network_intel is the
        # sole writer) - never hand-entered here.
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False


@admin.register(ProxyEndpoint)
class ProxyEndpointAdmin(admin.ModelAdmin):
    list_display = (
        "__str__",
        "scheme",
        "host",
        "port",
        "enabled",
        "consecutive_failures",
        "total_uses",
        "last_used_at",
    )
    list_filter = ("scheme", "enabled")
    search_fields = ("label", "host")
    readonly_fields = (
        "last_used_at",
        "last_success_at",
        "last_error",
        "consecutive_failures",
        "total_uses",
        "created_at",
        "updated_at",
    )
