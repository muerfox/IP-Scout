from django.urls import path

from . import views

app_name = "ips"

urlpatterns = [
    path("", views.ip_list, name="list"),
    path("<int:pk>/", views.ip_detail, name="detail"),
    path("<int:pk>/whois-status/", views.whois_status_cell, name="whois-status-cell"),
    path("<int:pk>/force-whois/", views.force_whois, name="force-whois"),
    path("<int:pk>/iran-status/", views.iran_status_cell, name="iran-status-cell"),
    path("<int:pk>/recalculate-iran/", views.recalculate_iran, name="recalculate-iran"),
]
