import os
import unittest
from unittest.mock import patch

from config.env import env, env_bool, env_int, env_list, env_str, parse_database_url


class EnvHelperTests(unittest.TestCase):
    def test_env_returns_value_when_set(self):
        with patch.dict(os.environ, {"IPSCOUT_TEST_VAR": "value"}):
            self.assertEqual(env("IPSCOUT_TEST_VAR"), "value")

    def test_env_returns_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IPSCOUT_TEST_UNSET", None)
            self.assertIsNone(env("IPSCOUT_TEST_UNSET"))
            self.assertEqual(env("IPSCOUT_TEST_UNSET", "fallback"), "fallback")

    def test_env_str_returns_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IPSCOUT_TEST_UNSET", None)
            self.assertEqual(env_str("IPSCOUT_TEST_UNSET", "fallback"), "fallback")

    def test_env_bool_returns_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IPSCOUT_TEST_UNSET", None)
            self.assertFalse(env_bool("IPSCOUT_TEST_UNSET"))
            self.assertTrue(env_bool("IPSCOUT_TEST_UNSET", True))

    def test_env_bool_parses_truthy_strings(self):
        for value in ("1", "true", "YES", "on"):
            with patch.dict(os.environ, {"IPSCOUT_TEST_VAR": value}):
                self.assertTrue(env_bool("IPSCOUT_TEST_VAR"))

    def test_env_bool_parses_falsy_strings(self):
        with patch.dict(os.environ, {"IPSCOUT_TEST_VAR": "nope"}):
            self.assertFalse(env_bool("IPSCOUT_TEST_VAR"))

    def test_env_int_returns_default_when_unset_or_empty(self):
        with patch.dict(os.environ, {"IPSCOUT_TEST_VAR": ""}):
            self.assertEqual(env_int("IPSCOUT_TEST_VAR", 7), 7)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IPSCOUT_TEST_UNSET", None)
            self.assertEqual(env_int("IPSCOUT_TEST_UNSET", 7), 7)

    def test_env_int_parses_value(self):
        with patch.dict(os.environ, {"IPSCOUT_TEST_VAR": "42"}):
            self.assertEqual(env_int("IPSCOUT_TEST_VAR", 0), 42)

    def test_env_list_returns_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IPSCOUT_TEST_UNSET", None)
            self.assertEqual(env_list("IPSCOUT_TEST_UNSET"), [])
            self.assertEqual(env_list("IPSCOUT_TEST_UNSET", ["a"]), ["a"])

    def test_env_list_splits_and_strips(self):
        with patch.dict(os.environ, {"IPSCOUT_TEST_VAR": "a, b ,c"}):
            self.assertEqual(env_list("IPSCOUT_TEST_VAR"), ["a", "b", "c"])


class ParseDatabaseUrlTests(unittest.TestCase):
    def test_parses_standard_url(self):
        result = parse_database_url("postgres://scout:secret@db.internal:5433/ipscout")
        self.assertEqual(
            result,
            {
                "ENGINE": "django.db.backends.postgresql",
                "NAME": "ipscout",
                "USER": "scout",
                "PASSWORD": "secret",
                "HOST": "db.internal",
                "PORT": "5433",
            },
        )

    def test_defaults_port_5432(self):
        result = parse_database_url("postgresql://scout:secret@db.internal/ipscout")
        self.assertEqual(result["PORT"], "5432")

    def test_rejects_non_postgres_scheme(self):
        with self.assertRaises(ValueError):
            parse_database_url("mysql://scout:secret@db.internal/ipscout")
