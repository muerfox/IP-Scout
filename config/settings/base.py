"""Base settings shared by every environment.

Environment-specific modules (development.py / production.py / test.py)
import * from here and override what they need. Nothing here should read
DEBUG-dependent behaviour directly except where explicitly noted.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from config.env import env_bool, env_int, env_list, env_str, parse_database_url

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

SECRET_KEY = env_str("DJANGO_SECRET_KEY", "insecure-dev-key-change-me")
DEBUG = env_bool("DJANGO_DEBUG", False)
ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", ["localhost", "127.0.0.1"])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "django.contrib.postgres",
    # Third-party
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "django_filters",
    "corsheaders",
    "drf_spectacular",
    "django_celery_beat",
    # IP Scout apps
    "apps.users",
    "apps.dashboard",
    "apps.servers",
    "apps.logs",
    "apps.ips",
    "apps.whois",
    "apps.geo",
    "apps.incidents",
    "apps.iran",
    "apps.api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.users.middleware.AuditLogMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.dashboard.context_processors.nav_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ---------------------------------------------------------------------------
# Database
#
# PostgreSQL only - IP Scout relies on native `inet`/`cidr` network types
# (see apps.ips / apps.iran models) that other backends cannot represent.
# ---------------------------------------------------------------------------

DATABASE_URL = env_str("DATABASE_URL", "")
if DATABASE_URL:
    _db_config = parse_database_url(DATABASE_URL)
else:
    _db_config = {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env_str("POSTGRES_DB", "ipscout"),
        "USER": env_str("POSTGRES_USER", "ipscout"),
        "PASSWORD": env_str("POSTGRES_PASSWORD", "ipscout"),
        "HOST": env_str("POSTGRES_HOST", "localhost"),
        "PORT": env_str("POSTGRES_PORT", "5432"),
    }

DATABASES = {
    "default": {
        **_db_config,
        "CONN_MAX_AGE": env_int("DATABASE_CONN_MAX_AGE", 60),
        "ATOMIC_REQUESTS": False,
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_USER_MODEL = "users.User"

# ---------------------------------------------------------------------------
# Auth / passwords
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LOGIN_URL = "users:login"
LOGIN_REDIRECT_URL = "dashboard:index"
LOGOUT_REDIRECT_URL = "users:login"

# ---------------------------------------------------------------------------
# i18n
# ---------------------------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = env_str("TIME_ZONE", "UTC")
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static / media
# ---------------------------------------------------------------------------

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"

# ---------------------------------------------------------------------------
# Redis / cache
# ---------------------------------------------------------------------------

REDIS_URL = env_str("REDIS_URL", "redis://localhost:6379/0")

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
    }
}

# ---------------------------------------------------------------------------
# Celery
#
# Separate queues so a WHOIS backlog cannot starve log ingestion, and log
# ingestion cannot starve maintenance/purge jobs. See apps.*.tasks and
# section 35 of the project spec.
# ---------------------------------------------------------------------------

CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_DEFAULT_QUEUE = "maintenance"
# Not a Celery setting - the queue names workers are started against
# (`celery -A config worker -Q logs`, etc). Kept here, not CELERY_-prefixed,
# so it isn't swallowed into the Celery app config namespace.
IPSCOUT_TASK_QUEUE_NAMES = ("logs", "ips", "whois", "iran", "maintenance")
CELERY_WORKER_PREFETCH_MULTIPLIER = env_int("CELERY_WORKER_PREFETCH_MULTIPLIER", 1)
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True

# WHOIS lookups must never run with unbounded concurrency against upstream
# registries - this caps the whois queue's worker concurrency independently
# of other queues (enforced via `celery -A config worker -Q whois --concurrency=N`).
WHOIS_QUEUE_CONCURRENCY = env_int("WHOIS_QUEUE_CONCURRENCY", 4)

# ---------------------------------------------------------------------------
# Django REST Framework / JWT
# ---------------------------------------------------------------------------

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": ("rest_framework.throttling.UserRateThrottle",),
    "DEFAULT_THROTTLE_RATES": {"user": "300/min"},
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=env_int("JWT_ACCESS_TOKEN_MINUTES", 30)),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=env_int("JWT_REFRESH_TOKEN_DAYS", 7)),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

SPECTACULAR_SETTINGS = {
    "TITLE": "IP Scout API",
    "DESCRIPTION": "503 / IP intelligence platform API.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS", [])

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

CSRF_COOKIE_HTTPONLY = False  # HTMX needs to read the CSRF cookie
SESSION_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SESSION_COOKIE_AGE = env_int("SESSION_COOKIE_AGE", 60 * 60 * 8)

# ---------------------------------------------------------------------------
# IP Scout domain configuration
#
# Every knob referenced by the ingestion/WHOIS/Iran/retention pipeline
# (spec sections 15-24, 38, 51) lives here so services never read
# os.environ directly.
# ---------------------------------------------------------------------------

WHOIS_BINARY = env_str("WHOIS_BINARY", "/usr/bin/whois")
WHOIS_TIMEOUT = env_int("WHOIS_TIMEOUT", 10)
WHOIS_CACHE_DAYS = env_int("WHOIS_CACHE_DAYS", 7)

REQUEST_RETENTION_DAYS = env_int("REQUEST_RETENTION_DAYS", 30)
WHOIS_RETENTION_DAYS = env_int("WHOIS_RETENTION_DAYS", 180)
IP_RETENTION_DAYS = env_int("IP_RETENTION_DAYS", 365)
INCIDENT_RETENTION_DAYS = env_int("INCIDENT_RETENTION_DAYS", 365)

IRAN_CIDR_SOURCE = env_str("IRAN_CIDR_SOURCE", "static")

# "null" (default) never populates geo fields - no offline geolocation
# dataset ships with this project (spec section 19: pluggable provider).
# Set to "maxmind" and GEOIP_DATABASE_PATH to a real GeoLite2-City.mmdb
# to enable real lookups.
GEOIP_PROVIDER = env_str("GEOIP_PROVIDER", "null")
GEOIP_DATABASE_PATH = env_str("GEOIP_DATABASE_PATH", "")

# SSH credential encryption key (Fernet). Generate with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
SSH_CREDENTIAL_ENCRYPTION_KEY = env_str("SSH_CREDENTIAL_ENCRYPTION_KEY", "")
SSH_CONNECT_TIMEOUT = env_int("SSH_CONNECT_TIMEOUT", 10)

# ---------------------------------------------------------------------------
# Logging (structured)
# ---------------------------------------------------------------------------

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "structured": {
            "format": (
                '{"time": "%(asctime)s", "level": "%(levelname)s", '
                '"logger": "%(name)s", "message": "%(message)s"}'
            ),
        },
        "console": {
            "format": "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": env_str("LOG_FORMAT", "console"),
        },
    },
    "root": {
        "handlers": ["console"],
        "level": env_str("LOG_LEVEL", "INFO"),
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": env_str("DJANGO_LOG_LEVEL", "INFO"), "propagate": False},
        "ipscout": {"handlers": ["console"], "level": env_str("LOG_LEVEL", "INFO"), "propagate": False},
    },
}
