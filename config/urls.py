from django.conf import settings
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("apps.dashboard.urls", namespace="dashboard")),
    path("accounts/", include("apps.users.urls", namespace="users")),
    path("servers/", include("apps.servers.urls", namespace="servers")),
    path("logs/", include("apps.logs.urls", namespace="logs")),
    path("ips/", include("apps.ips.urls", namespace="ips")),
    path("iran/", include("apps.iran.urls", namespace="iran")),
    path("api/v1/", include("apps.api.urls", namespace="api")),
]

if settings.DEBUG:
    import debug_toolbar
    from django.conf.urls.static import static

    urlpatterns += [path("__debug__/", include(debug_toolbar.urls))]
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
