from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models


def _fernet() -> Fernet:
    key = settings.SSH_CREDENTIAL_ENCRYPTION_KEY
    if not key:
        raise ImproperlyConfigured(
            "SSH_CREDENTIAL_ENCRYPTION_KEY must be set to store or read encrypted credentials."
        )
    return Fernet(key.encode())


class EncryptedTextField(models.TextField):
    """A TextField that is transparently Fernet-encrypted at rest.

    Python code always sees plaintext; only the database column holds
    ciphertext. Used for SSH credentials (spec section 42: "Encrypt
    sensitive SSH credentials at application level").
    """

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if not value:
            return value
        return _fernet().encrypt(value.encode()).decode()

    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return _fernet().decrypt(value.encode()).decode()
        except InvalidToken:
            # Ciphertext that doesn't decrypt under the current key (key
            # rotated, or corrupted data) - surface as empty rather than
            # crash every page that touches the row.
            return ""
