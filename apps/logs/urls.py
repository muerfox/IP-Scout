from django.urls import path

from . import views

app_name = "logs"

urlpatterns = [
    path("", views.log_source_list, name="list"),
    path("<int:pk>/toggle/", views.log_source_toggle_enabled, name="toggle-enabled"),
]
