import unittest

from config.env import parse_database_url


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
