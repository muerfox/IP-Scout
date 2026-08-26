"""Central DRF router (spec section 39)."""
from rest_framework.routers import DefaultRouter

from .viewsets import (
    CountryNetworkViewSet,
    IPAddressViewSet,
    IranIPViewSet,
    LogSourceViewSet,
    RequestEventViewSet,
    ServerViewSet,
)

router = DefaultRouter()
router.register(r"servers", ServerViewSet, basename="server")
router.register(r"log-sources", LogSourceViewSet, basename="log-source")
router.register(r"ips", IPAddressViewSet, basename="ip")
router.register(r"503", RequestEventViewSet, basename="request-event")
router.register(r"iran/ips", IranIPViewSet, basename="iran-ip")
router.register(r"iran/cidrs", CountryNetworkViewSet, basename="iran-cidr")
