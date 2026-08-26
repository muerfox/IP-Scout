"""HTTP 503 request tracking and aggregation (spec sections 11, 49).

Will hold: RequestEvent model (one row per parsed 503 line) and the
HourlyStats/CountryHourlyStats/IPDailyStats rollups the dashboard reads
from. Not yet implemented - foundation phase only, see the project's
incremental build plan (spec section 62, Phase 3/8).
"""
