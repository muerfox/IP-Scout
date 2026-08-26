"""Small, dependency-light environment variable helpers.

Loads a `.env` file (development convenience only; production should set
real environment variables) and exposes typed getters so settings modules
never touch `os.environ` directly.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")


def env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


def env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


def env_bool(key: str, default: bool = False) -> bool:
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(key: str, default: int) -> int:
    value = os.environ.get(key)
    if value is None or value == "":
        return default
    return int(value)


def env_list(key: str, default: list[str] | None = None, separator: str = ",") -> list[str]:
    value = os.environ.get(key)
    if not value:
        return default or []
    return [item.strip() for item in value.split(separator) if item.strip()]


def parse_database_url(url: str) -> dict:
    """Parse a `postgres://user:pass@host:port/name` URL into a Django DATABASES entry.

    Deliberately minimal - only what IP Scout needs (PostgreSQL). Avoids adding
    a dj-database-url dependency for a single call site.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ValueError(f"Unsupported DATABASE_URL scheme: {parsed.scheme!r}")
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": parsed.path.lstrip("/"),
        "USER": parsed.username or "",
        "PASSWORD": parsed.password or "",
        "HOST": parsed.hostname or "",
        "PORT": str(parsed.port or 5432),
    }
