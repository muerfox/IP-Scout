"""Central DRF router.

Each app registers its own ViewSets here as it's implemented (servers,
log-sources, ips, whois, 503, iran, map, dashboard, workers - spec
section 39). Empty in the foundation phase.
"""
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
