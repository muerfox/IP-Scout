import unittest

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test import override_settings

from apps.common.fields import CIDRField, EncryptedTextField
from apps.common.locks import LockHeldError, redis_lock


class EncryptedTextFieldTests(unittest.TestCase):
    """No DB needed - exercises the field's (de)serialization directly."""

    def test_round_trip(self):
        field = EncryptedTextField()
        ciphertext = field.get_prep_value("hunter2")
        self.assertNotEqual(ciphertext, "hunter2")
        self.assertEqual(field.from_db_value(ciphertext, None, None), "hunter2")

    def test_empty_value_passthrough(self):
        field = EncryptedTextField()
        self.assertEqual(field.get_prep_value(""), "")
        self.assertEqual(field.from_db_value("", None, None), "")
        self.assertIsNone(field.from_db_value(None, None, None))

    def test_different_plaintexts_produce_different_ciphertexts(self):
        field = EncryptedTextField()
        self.assertNotEqual(field.get_prep_value("a"), field.get_prep_value("b"))

    @override_settings(SSH_CREDENTIAL_ENCRYPTION_KEY="")
    def test_raises_when_encryption_key_unset(self):
        field = EncryptedTextField()
        with self.assertRaises(ImproperlyConfigured):
            field.get_prep_value("hunter2")

    def test_from_db_value_returns_empty_on_key_rotation(self):
        """Ciphertext encrypted under an old key can't decrypt under the
        current one after a key rotation - from_db_value should surface
        empty string rather than crash."""
        old_key = Fernet.generate_key().decode()
        with override_settings(SSH_CREDENTIAL_ENCRYPTION_KEY=old_key):
            ciphertext = EncryptedTextField().get_prep_value("hunter2")

        new_key = Fernet.generate_key().decode()
        with override_settings(SSH_CREDENTIAL_ENCRYPTION_KEY=new_key):
            self.assertEqual(EncryptedTextField().from_db_value(ciphertext, None, None), "")


class CIDRFieldTests(unittest.TestCase):
    """No DB needed - exercises the field's (de)serialization directly."""

    def test_normalizes_bare_host_to_slash_32(self):
        self.assertEqual(CIDRField().get_prep_value("1.2.3.4"), "1.2.3.4/32")

    def test_preserves_network_prefix(self):
        self.assertEqual(CIDRField().get_prep_value("1.2.3.0/24"), "1.2.3.0/24")

    def test_none_and_empty_string_become_none(self):
        field = CIDRField()
        self.assertIsNone(field.get_prep_value(None))
        self.assertIsNone(field.get_prep_value(""))

    def test_invalid_value_raises(self):
        with self.assertRaises(ValidationError):
            CIDRField().get_prep_value("not-a-cidr")

    def test_from_db_value_stringifies_and_passes_none(self):
        field = CIDRField()
        self.assertEqual(field.from_db_value("1.2.3.0/24", None, None), "1.2.3.0/24")
        self.assertIsNone(field.from_db_value(None, None, None))

    def test_to_python(self):
        field = CIDRField()
        self.assertIsNone(field.to_python(None))
        self.assertIsNone(field.to_python(""))
        self.assertEqual(field.to_python("1.2.3.0/24"), "1.2.3.0/24")


_locmem_cache = override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
)


class RedisLockTests(unittest.TestCase):
    @_locmem_cache
    def test_lock_blocks_concurrent_acquisition(self):
        with redis_lock("test:lock:a", timeout=5):
            with self.assertRaises(LockHeldError):
                with redis_lock("test:lock:a", timeout=5):
                    pass

    @_locmem_cache
    def test_lock_released_on_exit(self):
        with redis_lock("test:lock:b", timeout=5):
            pass
        with redis_lock("test:lock:b", timeout=5):
            pass  # would raise LockHeldError if the first lock leaked
