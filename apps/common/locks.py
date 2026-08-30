"""Redis-backed mutual-exclusion locks (spec section 36).

Built on Django's cache `add()`, which the Redis cache backend implements
as an atomic SET NX EX - no extra dependency needed. Every lock has a
timeout so a crashed worker can never block processing forever.

Example keys used elsewhere: `ssh:test:<server_id>`, `ssh:discover:<server_id>`,
`whois:<ip>`, `iran:<ip>`, `logreader:<server_id>:<log_source_id>`.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from django.core.cache import cache


class LockHeldError(RuntimeError):
    """Raised when a lock is already held by another task."""

    def __init__(self, key: str):
        self.key = key
        super().__init__(f"Lock already held: {key}")


@contextmanager
def redis_lock(key: str, timeout: int = 300) -> Iterator[None]:
    if not cache.add(key, "1", timeout=timeout):
        raise LockHeldError(key)
    try:
        yield
    finally:
        cache.delete(key)
