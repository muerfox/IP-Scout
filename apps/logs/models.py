"""Nginx log sources and the incremental log reader/parser (spec sections 8-11).

Will hold: LogSource model, inode/offset tracking, log rotation handling,
Nginx access-log line parsing. Not yet implemented - foundation phase
only, see the project's incremental build plan (spec section 62, Phase 3).
"""
