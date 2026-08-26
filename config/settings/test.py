"""Settings used by the test suite (`pytest`, `manage.py test`).

Still targets PostgreSQL (network field types are not portable), but
disables the debug toolbar/throttling noise and speeds up password hashing.
"""
from config.settings.base import *  # noqa: F401,F403

DEBUG = False

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"] = []  # noqa: F405

WHOIS_BINARY = "/usr/bin/whois"  # noqa: F405
# Fixed test-only Fernet key (must be valid: 32 url-safe base64 bytes).
SSH_CREDENTIAL_ENCRYPTION_KEY = "NnoRYXW2HCoNNQfvq6cLLoAz4OH__-_DyNQPpBD0MZA="  # noqa: F405
