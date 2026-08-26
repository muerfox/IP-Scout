from django.urls import path

from . import views

app_name = "servers"

urlpatterns = [
    path("", views.server_list, name="list"),
    path("add/", views.server_create, name="create"),
    path("<int:pk>/", views.server_detail, name="detail"),
    path("<int:pk>/edit/", views.server_update, name="update"),
    path("<int:pk>/delete/", views.server_delete, name="delete"),
    path("<int:pk>/toggle/", views.server_toggle_enabled, name="toggle-enabled"),
    path("<int:pk>/status-badge/", views.server_status_badge, name="status-badge"),
    path("<int:pk>/test-connection/", views.server_test_connection, name="test-connection"),
    path("<int:pk>/discover-logs/", views.server_discover_logs, name="discover-logs"),
]
