from django.urls import path

from . import views

app_name = "whois"

urlpatterns = [
    path("", views.whois_list, name="list"),
    path("<int:pk>/", views.whois_detail, name="detail"),
]
