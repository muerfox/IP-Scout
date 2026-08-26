"""Iranian CIDR database and classification (spec sections 20-24).

Will hold: CountryNetwork model (cidr-typed), network-containment
matching (PostgreSQL network operators, not string prefix checks),
IPCountryHistory, and the monthly IranCIDRProvider validation job.
Not yet implemented - foundation phase only, see the project's
incremental build plan (spec section 62, Phase 6).
"""
