from django.urls import path

from . import settings_views, views

app_name = "dashboard"

urlpatterns = [
    path("", views.index, name="index"),
    path("map/", views.world_map, name="map"),
    path("workers/", views.workers, name="workers"),
    path("search/", views.search, name="search"),
    path("settings/whois/", settings_views.settings_whois, name="settings-whois"),
    path("settings/retention/", settings_views.settings_retention, name="settings-retention"),
    path("settings/retention/purge/", settings_views.run_purge_now, name="settings-retention-purge"),
    path("settings/geoip/", settings_views.settings_geoip, name="settings-geoip"),
    path("settings/iran-sources/", settings_views.settings_iran_sources, name="settings-iran-sources"),
    path("settings/users/", settings_views.settings_users_redirect, name="settings-users"),
]
