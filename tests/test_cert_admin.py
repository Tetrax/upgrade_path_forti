"""Administrator credential tests for the certificate web interface."""

from __future__ import annotations

import json
import os
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
import cert_admin  # type: ignore[import-not-found]


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

    def test_rotate_credentials_replaces_only_the_authenticated_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-actuel"),
            )
            original = json.loads(credentials.read_text(encoding="utf-8"))
            original_revision = cert_admin.credentials_revision(credentials)

            new_revision = cert_admin.rotate_credentials(
                credentials,
                "admin",
                "mot-de-passe-actuel",
                "nouveau-mot-de-passe",
                "nouveau-mot-de-passe",
                expected_revision=original_revision,
            )

            rotated = json.loads(credentials.read_text(encoding="utf-8"))
            self.assertEqual(rotated["username"], "admin")
            self.assertNotEqual(rotated["salt"], original["salt"])
            self.assertNotEqual(rotated["digest"], original["digest"])
            self.assertNotEqual(new_revision, original_revision)
            self.assertEqual(new_revision, cert_admin.credentials_revision(credentials))
            self.assertFalse(
                cert_admin.verify_credentials(
                    credentials, "admin", "mot-de-passe-actuel"
                )
            )
            self.assertTrue(
                cert_admin.verify_credentials(
                    credentials, "admin", "nouveau-mot-de-passe"
                )
            )
            self.assertNotIn(
                "nouveau-mot-de-passe",
                credentials.read_text(encoding="utf-8"),
            )

    def test_rotate_credentials_rejects_a_mismatched_confirmation_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-actuel"),
            )
            original = credentials.read_bytes()

            with self.assertRaisesRegex(
                cert_admin.CredentialValidationError,
                "Les mots de passe ne correspondent pas",
            ):
                cert_admin.rotate_credentials(
                    credentials,
                    "admin",
                    "mot-de-passe-actuel",
                    "nouveau-mot-de-passe",
                    "confirmation-differente",
                    expected_revision=cert_admin.credentials_revision(credentials),
                )

            self.assertEqual(credentials.read_bytes(), original)

    def test_rotate_credentials_rejects_an_incorrect_current_password_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-actuel"),
            )
            original = credentials.read_bytes()

            with self.assertRaisesRegex(
                cert_admin.CredentialAuthenticationError,
                "Mot de passe actuel incorrect",
            ):
                cert_admin.rotate_credentials(
                    credentials,
                    "admin",
                    "mot-de-passe-incorrect",
                    "nouveau-mot-de-passe",
                    "nouveau-mot-de-passe",
                    expected_revision=cert_admin.credentials_revision(credentials),
                )

            self.assertEqual(credentials.read_bytes(), original)

    def test_rotate_credentials_rejects_the_current_password_as_the_new_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-actuel"),
            )
            original = credentials.read_bytes()

            with self.assertRaisesRegex(
                cert_admin.CredentialValidationError,
                "doit être différent",
            ):
                cert_admin.rotate_credentials(
                    credentials,
                    "admin",
                    "mot-de-passe-actuel",
                    "mot-de-passe-actuel",
                    "mot-de-passe-actuel",
                    expected_revision=cert_admin.credentials_revision(credentials),
                )

            self.assertEqual(credentials.read_bytes(), original)

    def test_rotate_credentials_reuses_the_utf8_minimum_password_length(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-actuel"),
            )
            original = credentials.read_bytes()

            with self.assertRaisesRegex(
                cert_admin.CredentialValidationError,
                "entre 12 et 1024 octets UTF-8",
            ):
                cert_admin.rotate_credentials(
                    credentials,
                    "admin",
                    "mot-de-passe-actuel",
                    "😀😀",
                    "😀😀",
                    expected_revision=cert_admin.credentials_revision(credentials),
                )

            self.assertEqual(credentials.read_bytes(), original)

    def test_rotate_credentials_reuses_the_utf8_maximum_password_length(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-actuel"),
            )
            original = credentials.read_bytes()

            with self.assertRaisesRegex(
                cert_admin.CredentialValidationError,
                "entre 12 et 1024 octets UTF-8",
            ):
                cert_admin.rotate_credentials(
                    credentials,
                    "admin",
                    "mot-de-passe-actuel",
                    "😀" * 257,
                    "😀" * 257,
                    expected_revision=cert_admin.credentials_revision(credentials),
                )

            self.assertEqual(credentials.read_bytes(), original)

    def test_concurrent_web_rotation_and_cli_reset_remain_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "current-password"),
            )
            revision = cert_admin.credentials_revision(credentials)
            barrier = threading.Barrier(2)
            rotation_result: list[str] = []

            def rotate() -> None:
                barrier.wait(timeout=5)
                try:
                    rotation_result.append(
                        cert_admin.rotate_credentials(
                            credentials,
                            "admin",
                            "current-password",
                            "web-replacement-password",
                            "web-replacement-password",
                            expected_revision=revision,
                        )
                    )
                except cert_admin.CredentialRevisionError:
                    rotation_result.append("conflict")

            def reset() -> None:
                barrier.wait(timeout=5)
                cert_admin.write_credentials(
                    credentials,
                    cert_admin.credential_payload("admin", "cli-reset-password"),
                )

            threads = [threading.Thread(target=rotate), threading.Thread(target=reset)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)

            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(len(rotation_result), 1)
            self.assertFalse(
                cert_admin.verify_credentials(credentials, "admin", "current-password")
            )
            self.assertFalse(
                cert_admin.verify_credentials(credentials, "admin", "web-replacement-password")
            )
            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "cli-reset-password")
            )

    def test_failed_atomic_rotation_preserves_credentials_and_removes_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "current-password"),
            )
            original = credentials.read_bytes()
            revision = cert_admin.credentials_revision(credentials)

            with (
                mock.patch.object(
                    cert_admin.os,
                    "replace",
                    side_effect=OSError("replace failed"),
                ),
                self.assertRaises(OSError),
            ):
                cert_admin.rotate_credentials(
                    credentials,
                    "admin",
                    "current-password",
                    "replacement-password",
                    "replacement-password",
                    expected_revision=revision,
                )

            self.assertEqual(credentials.read_bytes(), original)
            self.assertCountEqual(
                [path.name for path in credentials.parent.iterdir()],
                ["credentials.json", ".credentials.json.lock"],
            )

    def test_rotation_rejects_a_stale_revision_and_a_different_account(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "current-password"),
            )
            original = credentials.read_bytes()

            for username, revision in (
                ("admin", "0" * 64),
                ("another-admin", cert_admin.credentials_revision(credentials)),
            ):
                with self.subTest(username=username, revision=revision):
                    with self.assertRaises(cert_admin.CredentialRevisionError):
                        cert_admin.rotate_credentials(
                            credentials,
                            username,
                            "current-password",
                            "replacement-password",
                            "replacement-password",
                            expected_revision=revision,
                        )
                    self.assertEqual(credentials.read_bytes(), original)

    def test_rotation_changes_only_credentials_and_its_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "admin" / "credentials.json"
            active = root / "active"
            active.mkdir()
            notification_settings = root / "notification-settings.json"
            smtp_settings = root / "smtp-settings.json"
            (active / "fullchain.pem").write_bytes(b"certificate")
            (active / "privkey.pem").write_bytes(b"private-key")
            notification_settings.write_bytes(b'{"enabled":true}\n')
            smtp_settings.write_bytes(b'{"host":"smtp.example"}\n')
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "current-password"),
            )
            protected = {
                active / "fullchain.pem": (active / "fullchain.pem").read_bytes(),
                active / "privkey.pem": (active / "privkey.pem").read_bytes(),
                notification_settings: notification_settings.read_bytes(),
                smtp_settings: smtp_settings.read_bytes(),
            }

            cert_admin.rotate_credentials(
                credentials,
                "admin",
                "current-password",
                "replacement-password",
                "replacement-password",
                expected_revision=cert_admin.credentials_revision(credentials),
            )

            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "replacement-password")
            )
            for path, before in protected.items():
                with self.subTest(path=path):
                    self.assertEqual(path.read_bytes(), before)

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
            self.assertEqual(cert_admin.credential_lock_path(credentials).stat().st_mode & 0o777, 0o660)
            self.assertEqual(credentials.parent.stat().st_mode & 0o777, 0o750)
            chown.assert_called_once_with(credentials.parent, 0, 5678)
            self.assertEqual(fchown.call_count, 2)
            self.assertTrue(all(call.args[1:] == (0, 5678) for call in fchown.call_args_list))

    def test_non_root_exclusive_lock_preserves_a_group_owned_lock_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-original"),
            )

            different_uid = os.geteuid() + 1
            with (
                mock.patch.object(cert_admin.os, "geteuid", return_value=different_uid),
                mock.patch.object(cert_admin.os, "fchmod") as fchmod,
                cert_admin.credential_lock(credentials, exclusive=True),
            ):
                pass

            fchmod.assert_not_called()

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

    def test_existing_credentials_recreate_only_the_missing_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-original"),
            )
            original = credentials.read_bytes()
            lock_path = cert_admin.credential_lock_path(credentials)
            lock_path.unlink()

            self.assertTrue(cert_admin.ensure_credential_lock(credentials))

            self.assertEqual(credentials.read_bytes(), original)
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(
                cert_admin.verify_credentials(
                    credentials, "admin", "mot-de-passe-original"
                )
            )

    def test_root_upgrade_repairs_an_existing_lock_via_its_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-original"),
            )

            with (
                mock.patch.object(cert_admin.os, "geteuid", return_value=0),
                mock.patch.dict(cert_admin.os.environ, {"PGID": "5678"}, clear=False),
                mock.patch.object(cert_admin.os, "fchmod") as fchmod,
                mock.patch.object(cert_admin.os, "fchown") as fchown,
            ):
                self.assertFalse(cert_admin.ensure_credential_lock(credentials))

            fchmod.assert_called_once_with(mock.ANY, 0o660)
            fchown.assert_called_once_with(mock.ANY, 0, 5678)

    def test_upgrade_does_not_follow_an_existing_lock_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-original"),
            )
            lock_path = cert_admin.credential_lock_path(credentials)
            lock_path.unlink()
            outside = root / "outside"
            outside.write_text("protected", encoding="utf-8")
            outside_mode = outside.stat().st_mode & 0o777
            lock_path.symlink_to(outside)

            with self.assertRaises(cert_admin.CredentialError):
                cert_admin.ensure_credential_lock(credentials)

            self.assertTrue(lock_path.is_symlink())
            self.assertEqual(outside.read_text(encoding="utf-8"), "protected")
            self.assertEqual(outside.stat().st_mode & 0o777, outside_mode)

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
