import os
import unittest
from unittest.mock import patch

from auth import AuthSettings


class AuthSettingsTests(unittest.TestCase):
    def test_authentication_is_disabled_by_default(self):
        with patch("auth.google_credentials", return_value=("", "")):
            with patch.dict(os.environ, {}, clear=True):
                settings = AuthSettings.from_environment()
        self.assertFalse(settings.enabled)
        self.assertEqual(settings.providers, ())

    def test_enabled_authentication_requires_a_session_secret(self):
        with patch.dict(os.environ, {"AUTH_ENABLED": "true"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "AUTH_SESSION_SECRET"):
                AuthSettings.from_environment()

    def test_enabled_authentication_requires_a_configured_provider(self):
        with patch("auth.google_credentials", return_value=("", "")):
            with patch.dict(
                os.environ,
                {"AUTH_ENABLED": "true", "AUTH_SESSION_SECRET": "x" * 32},
                clear=True,
            ):
                with self.assertRaisesRegex(RuntimeError, "Google lub Microsoft"):
                    AuthSettings.from_environment()

    def test_google_provider_configuration_is_detected(self):
        with patch.dict(
            os.environ,
            {
                "AUTH_ENABLED": "true",
                "AUTH_SESSION_SECRET": "x" * 32,
                "AUTH_PUBLIC_URL": "https://nvr.example.test",
                "GOOGLE_CLIENT_ID": "id",
                "GOOGLE_CLIENT_SECRET": "secret",
            },
            clear=True,
        ):
            settings = AuthSettings.from_environment()
        self.assertTrue(settings.enabled)
        self.assertEqual(settings.providers, ("google",))

    def test_explicit_google_credentials_file_wins_over_auto_discovery(self):
        with patch.dict(
            os.environ,
            {
                "AUTH_ENABLED": "true",
                "AUTH_SESSION_SECRET": "x" * 32,
                "AUTH_PUBLIC_URL": "http://localhost:8000",
                "GOOGLE_CREDENTIALS_FILE": "/does-not-exist.json",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "Nie można odczytać"):
                AuthSettings.from_environment()
