from django.urls import path

from . import views

app_name = "ips"

urlpatterns = [
    path("", views.ip_list, name="list"),
]
