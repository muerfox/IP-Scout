from __future__ import annotations

import ipaddress

from cryptography.fernet import Fernet, InvalidToken

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
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


class CIDRField(models.Field):
    """Maps to PostgreSQL's native `cidr` type.

    Django has no built-in ORM field for `cidr` - only GenericIPAddressField,
    which maps to `inet` and rejects network/prefix notation (e.g.
    "1.2.3.0/24"). Spec section 5 requires storing IP networks as a native
    postgres type, never as plain text, so this project needs its own.
    Python-side values are plain strings like "1.2.3.0/24".
    """

    description = "PostgreSQL cidr (IPv4/IPv6 network address)"
    empty_strings_allowed = False

    def db_type(self, connection):
        return "cidr"

    def get_prep_value(self, value):
        if value in (None, ""):
            return None
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValidationError(f"{value!r} is not a valid CIDR network.") from exc

    def from_db_value(self, value, expression, connection):
        if value is None:
            return None
        return str(value)

    def to_python(self, value):
        if value is None or value == "":
            return None
        return str(value)
