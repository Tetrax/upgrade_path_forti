"""Regression gates for persisted operator transport choices; no network."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_notify as notify


class Microsoft365ConfigSafetyTests(unittest.TestCase):
    def test_corrupt_saved_transport_never_falls_back_to_working_smtp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "email-transport-settings.json"
            original = b'{"transport":"microsoft365",'
            path.write_bytes(original)
            settings = notify.NotificationSettings(
                enabled=True, minimum_severity="high", products={},
                recipients=("recipient@example.test",),
            )
            config = notify.load_email_config(
                {
                    "FORTIOS_SMTP_HOST": "smtp.example.test",
                    "FORTIOS_SMTP_FROM": "smtp@example.test",
                },
                settings=settings,
                settings_path=root / "notification-settings.json",
            )
            self.assertFalse(config.is_complete(), "A corrupt Graph choice must suspend delivery, not select SMTP")
            self.assertNotEqual(config.transport, "smtp")
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
