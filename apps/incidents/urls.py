from django.urls import path

from . import views

app_name = "incidents"

urlpatterns = [
    path("overview/", views.overview, name="overview"),
    path("ips/", views.ip_table, name="ip-table"),
    path("timeline/", views.timeline, name="timeline"),
]
