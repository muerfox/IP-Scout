from django.urls import path

from . import views

app_name = "iran"

urlpatterns = [
    path("ips/", views.iranian_ips, name="iranian-ips"),
    path("cidrs/", views.cidr_list, name="cidrs"),
    path("cidrs/add/", views.cidr_create, name="cidr-add"),
    path("cidrs/<int:pk>/toggle/", views.cidr_toggle_enabled, name="cidr-toggle-enabled"),
    path("changes/", views.changes_list, name="changes"),
]
