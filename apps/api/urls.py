from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

from django.urls import include, path

from . import views
from .router import router

app_name = "api"

urlpatterns = [
    path("auth/token/", TokenObtainPairView.as_view(), name="token-obtain"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("auth/token/verify/", TokenVerifyView.as_view(), name="token-verify"),
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path("docs/", SpectacularSwaggerView.as_view(url_name="api:schema"), name="docs"),
    path("dashboard/", views.DashboardDataView.as_view(), name="dashboard"),
    path("map/", views.MapDataView.as_view(), name="map"),
    path("iran/export/", views.IranExportAPIView.as_view(), name="iran-export"),
    path("workers/", views.WorkersAPIView.as_view(), name="workers"),
    path("", include(router.urls)),
]
