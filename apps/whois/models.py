"""Linux whois binary execution, caching and parsing (spec sections 15-18).

Will hold: WhoisRecord model (raw + parsed response), subprocess execution
via settings.WHOIS_BINARY, the 7-day freshness cache (settings.WHOIS_CACHE_DAYS),
retry/backoff on failure. Not yet implemented - foundation phase only, see
the project's incremental build plan (spec section 62, Phase 5).
"""
