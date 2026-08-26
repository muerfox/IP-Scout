from config.env import env_bool
from config.settings.base import *  # noqa: F401,F403

DEBUG = True

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS += ["debug_toolbar"]  # noqa: F405
MIDDLEWARE = ["debug_toolbar.middleware.DebugToolbarMiddleware"] + MIDDLEWARE  # noqa: F405

INTERNAL_IPS = ["127.0.0.1"]

SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

if env_bool("DJANGO_LOG_SQL", False):
    LOGGING["loggers"]["django.db.backends"] = {  # noqa: F405
        "handlers": ["console"],
        "level": "DEBUG",
        "propagate": False,
    }
