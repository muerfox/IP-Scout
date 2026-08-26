"""Geographic enrichment, decoupled from WHOIS country (spec section 19).

Will hold: a pluggable GeoIPProvider interface and the lat/lon and
country resolution it feeds into apps.ips.IPAddress. Not yet
implemented - foundation phase only, see the project's incremental
build plan (spec section 62, Phase 8).
"""
