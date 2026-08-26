from django.urls import path

from . import views

app_name = "ips"

urlpatterns = [
    path("", views.ip_list, name="list"),
    path("<int:pk>/whois-status/", views.whois_status_cell, name="whois-status-cell"),
    path("<int:pk>/force-whois/", views.force_whois, name="force-whois"),
]
