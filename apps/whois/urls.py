from django.urls import path

from . import views

app_name = "whois"

urlpatterns = [
    path("", views.whois_list, name="list"),
    path("networks/", views.network_list, name="networks"),
    path("proxies/", views.proxy_list, name="proxies"),
    path("proxies/add/", views.proxy_create, name="proxy-add"),
    path("proxies/<int:pk>/toggle/", views.proxy_toggle_enabled, name="proxy-toggle-enabled"),
    path("<int:pk>/", views.whois_detail, name="detail"),
]
