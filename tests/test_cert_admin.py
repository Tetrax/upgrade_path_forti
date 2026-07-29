"""Administrator credential tests for the certificate web interface."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CERT_ADMIN = ROOT / "scripts" / "cert_admin.py"
sys.path.insert(0, str(ROOT / "scripts"))
import cert_admin  # type: ignore[import-not-found]  # noqa: E402


class CertificateAdminTests(unittest.TestCase):
    def test_setup_from_stdin_stores_only_a_scrypt_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            password = "correct horse battery staple"
            result = subprocess.run(
                [
                    sys.executable,
                    str(CERT_ADMIN),
                    "setup",
                    "--credentials",
                    str(credentials),
                    "--username",
                    "valentin",
                    "--password-stdin",
                ],
                input=f"{password}\n{password}\n",
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(credentials.read_text())
            self.assertEqual(payload["username"], "valentin")
            self.assertEqual(payload["algorithm"], "scrypt")
            self.assertNotIn(password, credentials.read_text())
            self.assertEqual(credentials.stat().st_mode & 0o777, 0o600)

    def test_verification_accepts_only_the_configured_username_and_password(self) -> None:
        self.assertTrue(
            hasattr(cert_admin, "verify_credentials"),
            "cert_admin.verify_credentials doit être implémenté",
        )
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )

            self.assertTrue(
                cert_admin.verify_credentials(credentials, "valentin", "mot-de-passe-solide"),
            )
            self.assertFalse(
                cert_admin.verify_credentials(credentials, "intrus", "mot-de-passe-solide"),
            )
            self.assertFalse(
                cert_admin.verify_credentials(credentials, "valentin", "mauvais-mot-de-passe"),
            )
            self.assertFalse(
                cert_admin.verify_credentials(credentials, "válentin", "mot-de-passe-solide"),
                "un identifiant Unicode invalide doit être refusé sans exception",
            )

    def test_root_setup_makes_credentials_readable_only_by_the_runtime_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            with (
                mock.patch.object(cert_admin.os, "geteuid", return_value=0),
                mock.patch.object(cert_admin.os, "chown") as chown,
                mock.patch.object(cert_admin.os, "fchown") as fchown,
                mock.patch.dict(cert_admin.os.environ, {"PGID": "5678"}, clear=False),
            ):
                cert_admin.write_credentials(
                    credentials,
                    cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
                )

            self.assertEqual(credentials.stat().st_mode & 0o777, 0o640)
            self.assertEqual(cert_admin.credential_lock_path(credentials).stat().st_mode & 0o777, 0o640)
            self.assertEqual(credentials.parent.stat().st_mode & 0o777, 0o750)
            chown.assert_called_once_with(credentials.parent, 0, 5678)
            self.assertEqual(fchown.call_count, 2)
            self.assertTrue(all(call.args[1:] == (0, 5678) for call in fchown.call_args_list))

    def test_invalid_runtime_group_never_replaces_existing_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            original = cert_admin.credential_payload("valentin", "mot-de-passe-original")
            cert_admin.write_credentials(credentials, original)

            with (
                mock.patch.object(cert_admin.os, "geteuid", return_value=0),
                mock.patch.dict(cert_admin.os.environ, {"PGID": "invalide"}, clear=False),
                self.assertRaises(cert_admin.CredentialError),
            ):
                cert_admin.write_credentials(
                    credentials,
                    cert_admin.credential_payload("nouveau", "mot-de-passe-nouveau"),
                )

            self.assertEqual(json.loads(credentials.read_text(encoding="utf-8")), original)

    def test_password_length_matches_the_web_login_limit(self) -> None:
        accepted = cert_admin.credential_payload("valentin", "a" * 1024)
        self.assertEqual(accepted["algorithm"], "scrypt")
        with self.assertRaises(cert_admin.CredentialError):
            cert_admin.credential_payload("valentin", "a" * 1025)

        unicode_accepted = cert_admin.credential_payload("valentin", "😀" * 256)
        self.assertEqual(unicode_accepted["algorithm"], "scrypt")
        with self.assertRaises(cert_admin.CredentialError):
            cert_admin.credential_payload("valentin", "😀" * 257)

    def test_reset_waits_for_an_authorized_operation_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "initial-password"),
            )
            replacement = cert_admin.credential_payload("admin", "replacement-password")
            started = threading.Event()
            completed = threading.Event()

            def reset_credentials() -> None:
                started.set()
                cert_admin.write_credentials(credentials, replacement)
                completed.set()

            with cert_admin.credential_lock(credentials, exclusive=False):
                worker = threading.Thread(target=reset_credentials)
                worker.start()
                self.assertTrue(started.wait(timeout=2))
                self.assertFalse(completed.wait(timeout=0.1))

            worker.join(timeout=2)
            self.assertTrue(completed.is_set())
            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "replacement-password"),
            )


if __name__ == "__main__":
    unittest.main()
