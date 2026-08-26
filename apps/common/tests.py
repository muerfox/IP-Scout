import unittest

from django.test import override_settings

from apps.common.fields import EncryptedTextField
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
