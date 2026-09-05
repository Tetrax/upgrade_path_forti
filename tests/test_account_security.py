"""TDD coverage for the administrator account and recovery lifecycle."""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from unittest.mock import Mock, patch

import cert_admin  # type: ignore[import-not-found]
import cert_helper  # type: ignore[import-not-found]
import cert_helper_protocol  # type: ignore[import-not-found]
import cert_web  # type: ignore[import-not-found]
import fortios_notify  # type: ignore[import-not-found]
import fortios_server  # type: ignore[import-not-found]

from tests.test_cert_web import running_server


class HelperProtocolTests(unittest.TestCase):
    def test_setup_client_carries_optional_recovery_email_only_when_supplied(self) -> None:
        with patch.object(
            cert_helper_protocol,
            "request_helper",
            return_value={"ok": True, "credentialsRevision": "a" * 64},
        ) as request:
            cert_helper_protocol.setup_via_helper(
                Path("/run/fortios-cert-helper/helper.sock"),
                "admin",
                "initial-password",
                recovery_email="recover@example.test",
            )

        sent = request.call_args.args[1]
        self.assertEqual(sent["recoveryEmail"], "recover@example.test")

    def test_helper_recovery_clients_use_strict_explicit_operations(self) -> None:
        with patch.object(
            cert_helper_protocol,
            "request_helper",
            return_value={
                "ok": True,
                "token": "t" * 43,
                "expiresAt": "2026-01-02T03:34:05+00:00",
            },
        ) as request:
            token, expires_at = cert_helper_protocol.issue_verification_via_helper(
                Path("/run/fortios-cert-helper/helper.sock"),
                credentials_revision="a" * 64,
                recovery_email="pending@example.test",
            )

        self.assertEqual(token, "t" * 43)
        self.assertEqual(expires_at, "2026-01-02T03:34:05+00:00")
        self.assertEqual(
            request.call_args.args[1],
            {
                "version": cert_helper_protocol.PROTOCOL_VERSION,
                "action": "issue_verification",
                "credentialsRevision": "a" * 64,
                "recoveryEmail": "pending@example.test",
            },
        )

    def test_helper_reset_issuance_is_bound_to_the_observed_recipient(self) -> None:
        with patch.object(
            cert_helper_protocol,
            "request_helper",
            return_value={
                "ok": True,
                "token": "t" * 43,
                "expiresAt": "2026-01-02T03:19:05+00:00",
            },
        ) as request:
            cert_helper_protocol.issue_reset_via_helper(
                Path("/run/fortios-cert-helper/helper.sock"),
                credentials_revision="a" * 64,
                recovery_email="verified@example.test",
            )

        self.assertEqual(
            request.call_args.args[1],
            {
                "version": cert_helper_protocol.PROTOCOL_VERSION,
                "action": "issue_reset",
                "credentialsRevision": "a" * 64,
                "recoveryEmail": "verified@example.test",
            },
        )

    def test_helper_setup_persists_recovery_without_touching_certificates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "admin" / "credentials.json"
            active = root / "active"
            active.mkdir()
            (active / "fullchain.pem").write_bytes(b"certificate")
            (active / "privkey.pem").write_bytes(b"private-key")
            before = {path.name: path.read_bytes() for path in active.iterdir()}
            processor = cert_helper.CertificateInstallProcessor(
                hostname="example.test",
                output_dir=active,
                credentials_file=credentials,
                allowed_uid=1000,
                allowed_gid=1000,
            )
            response = processor.process(
                {
                    "version": cert_helper_protocol.PROTOCOL_VERSION,
                    "action": "setup",
                    "username": "admin",
                    "password": "initial-password",
                    "recoveryEmail": "recover@example.test",
                },
                peer_uid=1000,
                peer_gid=1000,
            )
            state = cert_admin.load_admin_state(credentials)
            after = {path.name: path.read_bytes() for path in active.iterdir()}

        self.assertTrue(response["ok"])
        self.assertEqual(state["pendingRecoveryEmail"], "recover@example.test")
        self.assertEqual(after, before)


    def test_helper_can_issue_verification_without_persisting_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "admin" / "credentials.json"
            processor = cert_helper.CertificateInstallProcessor(
                hostname="example.test",
                output_dir=root / "active",
                credentials_file=credentials,
                allowed_uid=1000,
                allowed_gid=1000,
            )
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="recover@example.test",
            )
            revision = cert_admin.credentials_revision(credentials)
            response = processor.process(
                {
                    "version": cert_helper_protocol.PROTOCOL_VERSION,
                    "action": "issue_verification",
                    "credentialsRevision": revision,
                    "recoveryEmail": "recover@example.test",
                },
                peer_uid=1000,
                peer_gid=1000,
            )
            state_text = cert_admin.admin_state_path(credentials).read_text(encoding="utf-8")

        self.assertTrue(response["ok"])
        self.assertRegex(response["token"], r"^[A-Za-z0-9_-]{43,128}$")
        self.assertNotIn(response["token"], state_text)
        self.assertEqual(len(json.loads(state_text)["tokens"]), 1)

    def test_helper_executes_the_complete_recovery_lifecycle_without_touching_certificates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "admin" / "credentials.json"
            active = root / "active"
            active.mkdir()
            (active / "fullchain.pem").write_bytes(b"certificate")
            (active / "privkey.pem").write_bytes(b"private-key")
            before = {path.name: path.read_bytes() for path in active.iterdir()}
            processor = cert_helper.CertificateInstallProcessor(
                hostname="example.test",
                output_dir=active,
                credentials_file=credentials,
                allowed_uid=1000,
                allowed_gid=1000,
            )
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="recover@example.test",
            )
            revision = cert_admin.credentials_revision(credentials)
            verification = processor.process(
                {
                    "version": cert_helper_protocol.PROTOCOL_VERSION,
                    "action": "issue_verification",
                    "credentialsRevision": revision,
                    "recoveryEmail": "recover@example.test",
                },
                peer_uid=1000,
                peer_gid=1000,
            )
            processor.process(
                {
                    "version": cert_helper_protocol.PROTOCOL_VERSION,
                    "action": "verify_recovery",
                    "token": verification["token"],
                    "credentialsRevision": revision,
                },
                peer_uid=1000,
                peer_gid=1000,
            )
            reset = processor.process(
                {
                    "version": cert_helper_protocol.PROTOCOL_VERSION,
                    "action": "issue_reset",
                    "credentialsRevision": revision,
                    "recoveryEmail": "recover@example.test",
                },
                peer_uid=1000,
                peer_gid=1000,
            )
            result = processor.process(
                {
                    "version": cert_helper_protocol.PROTOCOL_VERSION,
                    "action": "reset_password",
                    "token": reset["token"],
                    "newPassword": "replacement-password",
                    "confirmation": "replacement-password",
                    "credentialsRevision": revision,
                },
                peer_uid=1000,
                peer_gid=1000,
            )
            after = {path.name: path.read_bytes() for path in active.iterdir()}

            self.assertTrue(result["ok"])
            self.assertNotEqual(result["credentialsRevision"], revision)
            self.assertFalse(
                cert_admin.verify_credentials(credentials, "admin", "initial-password")
            )
            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "replacement-password")
            )
            self.assertEqual(after, before)

    def test_revoke_all_returns_count_and_invalidates_every_session(self) -> None:
        store = cert_web.SessionStore()
        first_id, _ = store.create("admin", "a" * 64)
        second_id, _ = store.create("admin", "b" * 64)

        count = store.revoke_all()

        self.assertEqual(count, 2)
        self.assertIsNone(store.get(first_id))
        self.assertIsNone(store.get(second_id))

    def test_anonymous_rate_limiter_applies_client_and_global_caps(self) -> None:
        limiter = cert_web.AnonymousRateLimiter(
            max_per_client=2,
            max_global=3,
            window_seconds=60,
        )

        self.assertTrue(limiter.try_record("192.0.2.1"))
        self.assertTrue(limiter.try_record("192.0.2.1"))
        self.assertFalse(limiter.try_record("192.0.2.1"))
        self.assertTrue(limiter.try_record("192.0.2.2"))
        self.assertFalse(limiter.try_record("192.0.2.3"))


class AdminStateTests(unittest.TestCase):
    def test_initial_setup_records_an_unverified_recovery_email_in_private_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"

            revision = cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="Admin@Example.test",
            )

            state_path = cert_admin.admin_state_path(credentials)
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state_mode = state_path.stat().st_mode & 0o777

        self.assertEqual(len(revision), 64)
        self.assertEqual(
            set(state),
            {"version", "passwordChangedAt", "currentRecoveryEmail", "pendingRecoveryEmail", "tokens"},
        )
        self.assertEqual(state["version"], 1)
        self.assertEqual(state["currentRecoveryEmail"], "")
        self.assertEqual(state["pendingRecoveryEmail"], "Admin@Example.test")
        self.assertEqual(state["tokens"], [])
        self.assertTrue(state["passwordChangedAt"].endswith("+00:00"))
        self.assertEqual(state_mode, 0o600)
    def test_existing_credentials_without_state_use_mtime_without_creating_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "initial-password"),
            )
            state_path = cert_admin.admin_state_path(credentials)
            state_path.unlink(missing_ok=True)
            expected_mtime = credentials.stat().st_mtime

            state = cert_admin.load_admin_state(credentials)

            self.assertEqual(state["currentRecoveryEmail"], "")
            self.assertEqual(state["pendingRecoveryEmail"], "")
            self.assertEqual(state["tokens"], [])
            self.assertAlmostEqual(
                __import__("datetime").datetime.fromisoformat(
                    state["passwordChangedAt"]
                ).timestamp(),
                expected_mtime,
                delta=1,
            )
            self.assertFalse(state_path.exists())

    def test_corrupt_state_fails_closed_instead_of_reenabling_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "initial-password"),
            )
            state_path = cert_admin.admin_state_path(credentials)
            state_path.write_text('{"version": 1, "tokens": "bad"}', encoding="utf-8")

            with self.assertRaises(cert_admin.CredentialError):
                cert_admin.load_admin_state(credentials)

    def test_corrupt_recovery_state_does_not_block_password_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            revision = cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
            )
            cert_admin.admin_state_path(credentials).write_text("{broken", encoding="utf-8")

            new_revision = cert_admin.rotate_credentials(
                credentials,
                "admin",
                "initial-password",
                "new-password-123",
                "new-password-123",
                expected_revision=revision,
            )

            self.assertNotEqual(new_revision, revision)
            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "new-password-123")
            )
            with self.assertRaises(cert_admin.CredentialError):
                cert_admin.load_admin_state(credentials)

    def test_optional_recovery_state_failure_keeps_created_account_usable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"

            with patch.object(
                cert_admin,
                "_write_admin_state_unlocked",
                side_effect=OSError("state unavailable"),
            ):
                revision = cert_admin.create_initial_credentials(
                    credentials,
                    "admin",
                    "initial-password",
                    recovery_email="recover@example.test",
                )

            self.assertEqual(revision, cert_admin.credentials_revision(credentials))
            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "initial-password")
            )

    def test_optional_custom_state_directory_failure_keeps_created_account_usable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            state_file = Path(tmp) / "unavailable" / "account-state.json"
            real_prepare = cert_admin._prepare_credentials_directory

            def prepare(path: Path, runtime_gid: int | None) -> None:
                if path == state_file:
                    raise OSError("simulated state directory failure")
                real_prepare(path, runtime_gid)

            with patch.object(cert_admin, "_prepare_credentials_directory", side_effect=prepare):
                revision = cert_admin.create_initial_credentials(
                    credentials,
                    "admin",
                    "initial-password",
                    recovery_email="pending@example.test",
                    state_file=state_file,
                )

            self.assertEqual(revision, cert_admin.credentials_revision(credentials))
            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "initial-password")
            )
            self.assertFalse(state_file.exists())

    def test_changing_recovery_email_keeps_the_verified_address_current_until_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
            )
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "old@example.test"
            cert_admin.save_admin_state(credentials, state)

            result = cert_admin.set_recovery_email(credentials, "new@example.test")
            updated = cert_admin.load_admin_state(credentials)

        self.assertEqual(result["currentRecoveryEmail"], "old@example.test")
        self.assertEqual(result["pendingRecoveryEmail"], "new@example.test")
        self.assertEqual(updated["currentRecoveryEmail"], "old@example.test")
        self.assertEqual(updated["pendingRecoveryEmail"], "new@example.test")

    def test_verification_token_is_hashed_and_bound_to_pending_email_and_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="pending@example.test",
            )
            now = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)

            token = cert_admin.issue_verification_token(credentials, now=now)
            state = cert_admin.load_admin_state(credentials)
            serialized_state = cert_admin.admin_state_path(credentials).read_text(
                encoding="utf-8"
            )
            revision = cert_admin.credentials_revision(credentials)

        self.assertGreaterEqual(len(token), 43)
        self.assertNotIn(token, serialized_state)
        self.assertEqual(len(state["tokens"]), 1)
        record = state["tokens"][0]
        self.assertEqual(record["purpose"], cert_admin.RECOVERY_PURPOSE_VERIFY)
        self.assertEqual(record["digest"], hashlib.sha256(token.encode()).hexdigest())
        self.assertEqual(record["credentialsRevision"], revision)
        self.assertEqual(record["email"], "pending@example.test")
        self.assertEqual(
            dt.datetime.fromisoformat(record["expiresAt"])
            - dt.datetime.fromisoformat(record["createdAt"]),
            dt.timedelta(minutes=30),
        )

    def test_verification_token_promotes_pending_email_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="pending@example.test",
            )
            now = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
            token = cert_admin.issue_verification_token(credentials, now=now)

            promoted = cert_admin.consume_verification_token(
                credentials,
                token,
                now=now + dt.timedelta(minutes=1),
            )
            state = cert_admin.load_admin_state(credentials)

            with self.assertRaises(cert_admin.RecoveryTokenError):
                cert_admin.consume_verification_token(
                    credentials,
                    token,
                    now=now + dt.timedelta(minutes=2),
                )

        self.assertEqual(promoted["currentRecoveryEmail"], "pending@example.test")
        self.assertEqual(promoted["pendingRecoveryEmail"], "")
        self.assertEqual(state["currentRecoveryEmail"], "pending@example.test")
        self.assertEqual(state["tokens"], [])

    def test_reset_token_replaces_password_without_old_password_and_clears_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
            )
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "verified@example.test"
            cert_admin.save_admin_state(credentials, state)
            now = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
            token = cert_admin.issue_password_reset_token(credentials, now=now)

            revision = cert_admin.reset_credentials_with_token(
                credentials,
                token,
                "new-password-123",
                "new-password-123",
                now=now + dt.timedelta(minutes=1),
            )
            old_password_works = cert_admin.verify_credentials(
                credentials, "admin", "initial-password"
            )
            new_password_works = cert_admin.verify_credentials(
                credentials, "admin", "new-password-123"
            )
            with self.assertRaises(cert_admin.RecoveryTokenError):
                cert_admin.reset_credentials_with_token(
                    credentials,
                    token,
                    "another-password-123",
                    "another-password-123",
                    now=now + dt.timedelta(minutes=2),
                )

        self.assertEqual(len(revision), 64)
        self.assertFalse(old_password_works)
        self.assertTrue(new_password_works)

    def test_changing_recovery_email_invalidates_existing_reset_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            revision = cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="old@example.test",
            )
            verification = cert_admin.issue_verification_token(
                credentials,
                expected_revision=revision,
                expected_recovery_email="old@example.test",
            )
            cert_admin.consume_verification_token(
                credentials,
                verification,
                expected_revision=revision,
            )
            old_reset = cert_admin.issue_password_reset_token(
                credentials,
                expected_revision=revision,
                expected_recovery_email="old@example.test",
            )

            cert_admin.set_recovery_email(
                credentials,
                "new@example.test",
                expected_revision=revision,
            )
            new_verification = cert_admin.issue_verification_token(
                credentials,
                expected_revision=revision,
                expected_recovery_email="new@example.test",
            )
            cert_admin.consume_verification_token(
                credentials,
                new_verification,
                expected_revision=revision,
            )

            with self.assertRaises(cert_admin.RecoveryTokenError):
                cert_admin.reset_credentials_with_token(
                    credentials,
                    old_reset,
                    "replacement-password-123",
                    "replacement-password-123",
                    expected_revision=revision,
                )

            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "initial-password")
            )
            self.assertFalse(
                cert_admin.verify_credentials(
                    credentials,
                    "admin",
                    "replacement-password-123",
                )
            )

    def test_reset_success_is_not_reported_as_failure_when_optional_state_cleanup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            credentials = Path(directory) / "admin" / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password-value",
            )
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "verified@example.test"
            cert_admin.save_admin_state(credentials, state)
            revision = cert_admin.credentials_revision(credentials)
            token = cert_admin.issue_password_reset_token(
                credentials,
                expected_revision=revision,
            )

            with patch.object(
                cert_admin,
                "_write_admin_state_unlocked",
                side_effect=OSError("simulated state write failure"),
            ):
                cert_admin.reset_credentials_with_token(
                    credentials,
                    token,
                    "replacement-password-value",
                    "replacement-password-value",
                )

            self.assertTrue(
                cert_admin.verify_credentials(
                    credentials,
                    "admin",
                    "replacement-password-value",
                )
            )
            with self.assertRaises(cert_admin.RecoveryTokenError):
                cert_admin.reset_credentials_with_token(
                    credentials,
                    token,
                    "another-password-value",
                    "another-password-value",
                )

    def test_expired_reset_token_is_rejected_without_changing_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(credentials, "admin", "initial-password")
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "verified@example.test"
            cert_admin.save_admin_state(credentials, state)
            now = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
            token = cert_admin.issue_password_reset_token(credentials, now=now)

            with self.assertRaises(cert_admin.RecoveryTokenError):
                cert_admin.reset_credentials_with_token(
                    credentials,
                    token,
                    "replacement-password",
                    "replacement-password",
                    now=now + dt.timedelta(seconds=cert_admin.PASSWORD_RESET_TTL_SECONDS),
                )

            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "initial-password")
            )

    def test_wrong_reset_token_is_rejected_without_changing_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(credentials, "admin", "initial-password")
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "verified@example.test"
            cert_admin.save_admin_state(credentials, state)
            cert_admin.issue_password_reset_token(credentials)

            with self.assertRaises(cert_admin.RecoveryTokenError):
                cert_admin.reset_credentials_with_token(
                    credentials,
                    "x" * 43,
                    "replacement-password",
                    "replacement-password",
                )

            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "initial-password")
            )

    def test_reset_token_is_not_issued_when_the_verified_recipient_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(credentials, "admin", "initial-password")
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "old@example.test"
            cert_admin.save_admin_state(credentials, state)
            observed_recipient = state["currentRecoveryEmail"]
            state["currentRecoveryEmail"] = "new@example.test"
            cert_admin.save_admin_state(credentials, state)

            with self.assertRaises(cert_admin.RecoveryTokenError):
                cert_admin.issue_password_reset_token(
                    credentials,
                    expected_recovery_email=observed_recipient,
                )

            self.assertEqual(cert_admin.load_admin_state(credentials)["tokens"], [])

    def test_verification_token_is_not_issued_when_the_pending_recipient_changed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="first@example.test",
            )
            observed_recipient = "first@example.test"
            cert_admin.set_recovery_email(credentials, "second@example.test")

            with self.assertRaises(cert_admin.RecoveryTokenError):
                cert_admin.issue_verification_token(
                    credentials,
                    expected_recovery_email=observed_recipient,
                )

            self.assertEqual(cert_admin.load_admin_state(credentials)["tokens"], [])

    def test_stale_revision_reset_token_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(credentials, "admin", "initial-password")
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "verified@example.test"
            cert_admin.save_admin_state(credentials, state)
            token = cert_admin.issue_password_reset_token(credentials)
            cert_admin.rotate_credentials(
                credentials,
                "admin",
                "initial-password",
                "rotated-password-value",
                "rotated-password-value",
                expected_revision=cert_admin.credentials_revision(credentials),
            )

            with self.assertRaises(cert_admin.RecoveryTokenError):
                cert_admin.reset_credentials_with_token(
                    credentials,
                    token,
                    "replacement-password",
                    "replacement-password",
                )

            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "rotated-password-value")
            )

    def test_password_rotation_updates_state_and_invalidates_recovery_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="pending@example.test",
            )
            issued_at = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
            cert_admin.issue_verification_token(credentials, now=issued_at)
            before = cert_admin.load_admin_state(credentials)
            old_revision = cert_admin.credentials_revision(credentials)

            new_revision = cert_admin.rotate_credentials(
                credentials,
                "admin",
                "initial-password",
                "rotated-password-123",
                "rotated-password-123",
                expected_revision=old_revision,
            )
            after = cert_admin.load_admin_state(credentials)

        self.assertNotEqual(new_revision, old_revision)
        self.assertNotEqual(after["passwordChangedAt"], before["passwordChangedAt"])
        self.assertEqual(after["tokens"], [])


    def test_cli_setup_accepts_optional_recovery_email(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            with patch.object(
                sys,
                "stdin",
                io.StringIO("initial-password\ninitial-password\n"),
            ):
                exit_code = cert_admin.main(
                    [
                        "setup",
                        "--credentials",
                        str(credentials),
                        "--username",
                        "admin",
                        "--password-stdin",
                        "--recovery-email",
                        "cli@example.test",
                    ]
                )
            state = cert_admin.load_admin_state(credentials)

        self.assertEqual(exit_code, 0)
        self.assertEqual(state["pendingRecoveryEmail"], "cli@example.test")


    def test_cli_reset_invalidates_existing_recovery_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="pending@example.test",
            )
            cert_admin.issue_verification_token(credentials)
            with patch.object(
                sys,
                "stdin",
                io.StringIO("reset-password-123\nreset-password-123\n"),
            ):
                exit_code = cert_admin.main(
                    [
                        "reset",
                        "--credentials",
                        str(credentials),
                        "--username",
                        "admin",
                        "--password-stdin",
                    ]
                )
            state = cert_admin.load_admin_state(credentials)
            new_password_works = cert_admin.verify_credentials(
                credentials, "admin", "reset-password-123"
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(new_password_works)
        self.assertEqual(state["tokens"], [])


class HttpAccountSecurityTests(unittest.TestCase):
    def test_recovery_tokens_are_redacted_from_http_access_logs(self) -> None:
        token = "s" * 43
        handler = object.__new__(fortios_server.FortiosHandler)
        handler.requestline = f"GET /cert/reset-password?token={token} HTTP/1.1"
        handler.log_date_time_string = lambda: "test-time"
        output = io.StringIO()

        with patch.object(sys, "stderr", output):
            handler.log_request(200, 123)

        self.assertNotIn(token, output.getvalue())
        self.assertIn("[REDACTED]", output.getvalue())

    def test_first_run_uses_the_configured_private_state_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            state_file = Path(tmp) / "private" / "account-state.json"
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_ADMIN_STATE_FILE": str(state_file),
            }
            with running_server(environment) as base_url:
                request = urllib.request.Request(
                    f"{base_url}/api/cert/setup",
                    data=json.dumps(
                        {
                            "username": "admin",
                            "password": "initial-password",
                            "passwordConfirmation": "initial-password",
                            "recoveryEmail": "person@example.test",
                        }
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 200)

            state = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(state["pendingRecoveryEmail"], "person@example.test")
            self.assertFalse(cert_admin.admin_state_path(credentials).exists())

    def test_first_run_recovery_email_is_optional_and_status_is_masked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                request = urllib.request.Request(
                    f"{base_url}/api/cert/setup",
                    data=json.dumps(
                        {
                            "username": "admin",
                            "password": "initial-password",
                            "passwordConfirmation": "initial-password",
                            "recoveryEmail": "person@example.test",
                        }
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    setup_payload = json.load(response)
                    cookie = response.headers["Set-Cookie"].split(";", 1)[0]

                status_request = urllib.request.Request(
                    f"{base_url}/api/cert/status",
                    headers={"Cookie": cookie},
                )
                with urllib.request.urlopen(status_request, timeout=5) as response:
                    status_payload = json.load(response)

        self.assertTrue(setup_payload["authenticated"])
        self.assertEqual(status_payload["username"], "admin")
        self.assertFalse(status_payload["recoveryEmailVerified"])
        self.assertTrue(status_payload["pendingRecoveryEmailPresent"])
        self.assertNotIn("person@example.test", json.dumps(status_payload))

    def test_corrupt_recovery_state_disables_recovery_without_blocking_admin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            cert_admin.create_initial_credentials(credentials, "admin", "initial-password")
            cert_admin.admin_state_path(credentials).write_text("{broken", encoding="utf-8")
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }

            with running_server(environment) as base_url:
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "admin", "password": "initial-password"}
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(login, timeout=5) as response:
                    cookie = response.headers["Set-Cookie"].split(";", 1)[0]
                status = urllib.request.Request(
                    f"{base_url}/api/cert/status",
                    headers={"Cookie": cookie},
                )
                with urllib.request.urlopen(status, timeout=5) as response:
                    payload = json.load(response)

            self.assertTrue(payload["authenticated"])
            self.assertFalse(payload["recoveryStateAvailable"])
            self.assertFalse(payload["recoveryEmailVerified"])
            self.assertFalse(payload["pendingRecoveryEmailPresent"])

    def test_forgot_password_is_generic_when_account_exists_or_not(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
            )
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "verified@example.test"
            cert_admin.save_admin_state(credentials, state)
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                responses = []
                for username in ("admin", "does-not-exist"):
                    request = urllib.request.Request(
                        f"{base_url}/api/cert/forgot-password",
                        data=json.dumps({"username": username}).encode(),
                        method="POST",
                        headers={"Content-Type": "application/json", "Origin": base_url},
                    )
                    try:
                        with urllib.request.urlopen(request, timeout=5) as response:
                            responses.append((response.status, response.read()))
                    except urllib.error.HTTPError as error:
                        with error:
                            responses.append((error.code, error.read()))

        self.assertEqual(responses[0], responses[1])
        self.assertEqual(responses[0][0], 202)
        self.assertEqual(
            json.loads(responses[0][1]),
            {"message": "Si ce compte peut être récupéré, un email sera envoyé."},
        )

    def test_forgot_password_does_not_issue_a_token_without_complete_smtp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            cert_admin.create_initial_credentials(credentials, "admin", "initial-password")
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "verified@example.test"
            cert_admin.save_admin_state(credentials, state)
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(Path(tmp) / "data"),
            }

            with running_server(environment) as base_url:
                request = urllib.request.Request(
                    f"{base_url}/api/cert/forgot-password",
                    data=json.dumps({"username": "admin"}).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 202)

            self.assertEqual(cert_admin.load_admin_state(credentials)["tokens"], [])

    def test_forgot_password_limiter_is_shared_across_http_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "admin" / "credentials.json"
            cert_admin.create_initial_credentials(credentials, "admin", "initial-password")
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "verified@example.test"
            cert_admin.save_admin_state(credentials, state)
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(root / "data"),
                "FORTIOS_SMTP_HOST": "127.0.0.1",
                "FORTIOS_SMTP_PORT": "9",
                "FORTIOS_SMTP_STARTTLS": "false",
                "FORTIOS_SMTP_FROM": "fortiupgrade@example.test",
                "FORTIOS_APP_URL": "https://fortiupgrade.example.test/app/",
            }

            digests: list[str] = []
            with running_server(environment) as base_url:
                for _ in range(6):
                    request = urllib.request.Request(
                        f"{base_url}/api/cert/forgot-password",
                        data=json.dumps({"username": "admin"}).encode(),
                        method="POST",
                        headers={"Content-Type": "application/json", "Origin": base_url},
                    )
                    with urllib.request.urlopen(request, timeout=5) as response:
                        self.assertEqual(response.status, 202)
                    records = cert_admin.load_admin_state(credentials)["tokens"]
                    digests.append(records[-1]["digest"])

            self.assertEqual(len(set(digests[:5])), 5)
            self.assertEqual(digests[5], digests[4])

    def test_direct_verification_resend_binds_token_to_observed_pending_email(
        self,
    ) -> None:
        handler = object.__new__(fortios_server.FortiosHandler)
        handler.cert_admin_file = Path("/certificates/admin/credentials.json")
        handler.cert_admin_state_file = None
        handler.cert_helper_socket = None
        handler.cert_recovery_email_limiter = Mock()
        handler.cert_recovery_email_limiter.try_record.return_value = True
        handler.cert_session_id = lambda: "session-id"
        session = Mock(credentials_revision="a" * 64)
        handler.require_admin_session = lambda **_kwargs: session
        handler.read_json_body = lambda **_kwargs: {}
        handler._recovery_delivery_ready = lambda _recipient: True
        handler._queue_recovery_email = Mock()
        handler.write_json_response = Mock()
        token = "t" * 43
        state_before = {"pendingRecoveryEmail": "pending@example.test"}
        state_after = {
            "tokens": [
                {
                    "purpose": cert_admin.RECOVERY_PURPOSE_VERIFY,
                    "expiresAt": "2026-01-02T03:34:05+00:00",
                }
            ]
        }

        with (
            patch.object(
                fortios_server,
                "load_admin_state",
                side_effect=[state_before, state_after],
            ),
            patch.object(
                fortios_server,
                "issue_verification_token",
                return_value=token,
            ) as direct_issue,
        ):
            handler.handle_cert_recovery_email_resend()

        direct_issue.assert_called_once_with(
            handler.cert_admin_file,
            state_file=handler.cert_admin_state_file,
            expected_revision="a" * 64,
            expected_recovery_email="pending@example.test",
        )
        handler._queue_recovery_email.assert_called_once_with(
            purpose="verify_recovery_email",
            token=token,
            recipient="pending@example.test",
            expires_at="2026-01-02T03:34:05+00:00",
        )

    def test_helper_verification_resend_binds_token_to_observed_pending_email(
        self,
    ) -> None:
        handler = object.__new__(fortios_server.FortiosHandler)
        handler.cert_admin_file = Path("/certificates/admin/credentials.json")
        handler.cert_admin_state_file = None
        handler.cert_helper_socket = Path("/run/fortios-cert-helper/helper.sock")
        handler.cert_recovery_email_limiter = Mock()
        handler.cert_recovery_email_limiter.try_record.return_value = True
        handler.cert_session_id = lambda: "session-id"
        session = Mock(credentials_revision="a" * 64)
        handler.require_admin_session = lambda **_kwargs: session
        handler.read_json_body = lambda **_kwargs: {}
        handler._recovery_delivery_ready = lambda _recipient: True
        handler._queue_recovery_email = Mock()
        handler.write_json_response = Mock()
        token = "t" * 43

        with (
            patch.object(
                fortios_server,
                "load_admin_state",
                return_value={"pendingRecoveryEmail": "pending@example.test"},
            ),
            patch.object(
                fortios_server,
                "issue_verification_via_helper",
                return_value=(token, "2026-01-02T03:34:05+00:00"),
            ) as helper_issue,
        ):
            handler.handle_cert_recovery_email_resend()

        helper_issue.assert_called_once_with(
            handler.cert_helper_socket,
            credentials_revision="a" * 64,
            recovery_email="pending@example.test",
        )
        handler._queue_recovery_email.assert_called_once()

    def test_direct_forgot_password_binds_reset_to_observed_account_state(self) -> None:
        handler = object.__new__(fortios_server.FortiosHandler)
        handler.cert_admin_file = Path("/certificates/admin/credentials.json")
        handler.cert_admin_state_file = None
        handler.cert_helper_socket = None
        handler.cert_recovery_limiter = Mock()
        handler.cert_recovery_limiter.try_record.return_value = True
        handler.cert_client_identity = lambda: "192.0.2.1"
        handler.read_json_body = lambda **_kwargs: {"username": "admin"}
        handler._recovery_response = Mock()
        handler._recovery_delivery_ready = lambda _recipient: True
        handler._queue_recovery_email = Mock()
        token = "t" * 43
        state_before = {"currentRecoveryEmail": "verified@example.test"}
        state_after = {
            "tokens": [
                {
                    "purpose": cert_admin.RECOVERY_PURPOSE_RESET,
                    "expiresAt": "2026-01-02T03:19:05+00:00",
                }
            ]
        }

        with (
            patch.object(fortios_server.os.path, "lexists", return_value=True),
            patch.object(
                fortios_server,
                "load_credentials_with_revision",
                return_value=({"username": "admin"}, "a" * 64),
            ),
            patch.object(
                fortios_server,
                "load_admin_state",
                side_effect=[state_before, state_after],
            ),
            patch.object(
                fortios_server,
                "issue_password_reset_token",
                return_value=token,
            ) as direct_issue,
            patch.object(fortios_server, "credential_lock") as lock,
        ):
            lock.return_value.__enter__.return_value = None
            handler.handle_cert_forgot_password()

        direct_issue.assert_called_once_with(
            handler.cert_admin_file,
            state_file=handler.cert_admin_state_file,
            expected_revision="a" * 64,
            expected_recovery_email="verified@example.test",
        )
        handler._queue_recovery_email.assert_called_once_with(
            purpose="password_reset",
            token=token,
            recipient="verified@example.test",
            expires_at="2026-01-02T03:19:05+00:00",
        )

    def test_helper_mode_forgot_password_issues_reset_through_the_helper(self) -> None:
        handler = object.__new__(fortios_server.FortiosHandler)
        handler.cert_admin_file = Path("/certificates/admin/credentials.json")
        handler.cert_admin_state_file = None
        handler.cert_helper_socket = Path("/run/fortios-cert-helper/helper.sock")
        handler.cert_recovery_limiter = Mock()
        handler.cert_recovery_limiter.try_record.return_value = True
        handler.cert_client_identity = lambda: "192.0.2.1"
        handler.read_json_body = lambda **_kwargs: {"username": "admin"}
        handler._recovery_response = Mock()
        handler._queue_recovery_email = Mock()
        config = fortios_notify.EmailConfig(
            enabled=False,
            smtp_host="smtp.example.test",
            smtp_port=25,
            smtp_username="",
            smtp_password="",
            smtp_from="fortiupgrade@example.test",
            smtp_to=(),
            smtp_starttls=False,
            smtp_timeout=5,
            app_url="https://fortiupgrade.example.test/app/",
            smtp_allow_insecure=True,
        )

        with (
            patch.object(fortios_server.os.path, "lexists", return_value=True),
            patch.object(
                fortios_server,
                "load_credentials_with_revision",
                return_value=({"username": "admin"}, "a" * 64),
            ),
            patch.object(
                fortios_server,
                "load_admin_state",
                return_value={"currentRecoveryEmail": "verified@example.test"},
            ),
            patch.object(
                fortios_server.fortios_notify,
                "load_smtp_preview_snapshot",
                return_value=(Mock(), config),
            ),
            patch.object(
                fortios_server,
                "issue_reset_via_helper",
                return_value=("t" * 43, "2026-01-02T03:19:05+00:00"),
            ) as helper_issue,
            patch.object(fortios_server, "issue_password_reset_token") as direct_issue,
            patch.object(fortios_server, "credential_lock") as lock,
        ):
            lock.return_value.__enter__.return_value = None
            handler.handle_cert_forgot_password()

        helper_issue.assert_called_once_with(
            handler.cert_helper_socket,
            credentials_revision="a" * 64,
            recovery_email="verified@example.test",
        )
        direct_issue.assert_not_called()
        handler._queue_recovery_email.assert_called_once()

    def test_http_verification_promotes_email_and_rejects_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
                recovery_email="pending@example.test",
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                token = cert_admin.issue_verification_token(credentials)
                request = urllib.request.Request(
                    f"{base_url}/api/cert/verify-email",
                    data=json.dumps({"token": token}).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    first_status = response.status
                    first_payload = json.load(response)
                try:
                    with urllib.request.urlopen(request, timeout=5) as response:
                        second_status = response.status
                        second_payload = json.load(response)
                except urllib.error.HTTPError as error:
                    with error:
                        second_status = error.code
                        second_payload = json.load(error)
                state = cert_admin.load_admin_state(credentials)

        self.assertEqual(first_status, 200)
        self.assertEqual(first_payload, {"verified": True})
        self.assertEqual(second_status, 400)
        self.assertEqual(second_payload, {"error": "Lien de récupération invalide ou expiré."})
        self.assertEqual(state["currentRecoveryEmail"], "pending@example.test")
    def test_authenticated_recovery_change_keeps_current_address_and_sets_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            cert_admin.create_initial_credentials(
                credentials,
                "admin",
                "initial-password",
            )
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "old@example.test"
            cert_admin.save_admin_state(credentials, state)
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "admin", "password": "initial-password"}
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(login, timeout=5) as response:
                    login_payload = json.load(response)
                    cookie = response.headers["Set-Cookie"].split(";", 1)[0]
                change = urllib.request.Request(
                    f"{base_url}/api/cert/recovery-email",
                    data=json.dumps({"email": "new@example.test"}).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "Cookie": cookie,
                        "X-CSRF-Token": login_payload["csrfToken"],
                    },
                )
                with urllib.request.urlopen(change, timeout=5) as response:
                    change_status = response.status
                    change_payload = json.load(response)
                updated = cert_admin.load_admin_state(credentials)

        self.assertEqual(change_status, 200)
        self.assertTrue(change_payload["recoveryEmailVerified"])
        self.assertTrue(change_payload["pendingRecoveryEmailPresent"])
        self.assertEqual(updated["currentRecoveryEmail"], "old@example.test")
        self.assertEqual(updated["pendingRecoveryEmail"], "new@example.test")

    def test_anonymous_verify_and_reset_endpoints_are_rate_limited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            cert_admin.create_initial_credentials(credentials, "admin", "initial-password")
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            payloads = {
                "/api/cert/verify-email": {"token": "t" * 43},
                "/api/cert/reset-password": {
                    "token": "t" * 43,
                    "newPassword": "new-password-123",
                    "confirmation": "new-password-123",
                },
            }

            for path, payload in payloads.items():
                with self.subTest(path=path), running_server(environment) as base_url:
                    statuses = []
                    for _ in range(6):
                        request = urllib.request.Request(
                            base_url + path,
                            data=json.dumps(payload).encode(),
                            method="POST",
                            headers={"Content-Type": "application/json", "Origin": base_url},
                        )
                        try:
                            with urllib.request.urlopen(request, timeout=5) as response:
                                statuses.append(response.status)
                        except urllib.error.HTTPError as error:
                            statuses.append(error.code)
                    self.assertEqual(statuses[:5], [400] * 5)
                    self.assertEqual(statuses[5], 429)

        with running_server({"FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1"}) as base_url:
            for path in (
                "/cert/verify-email?token=" + "t" * 43,
                "/cert/reset-password?token=" + "t" * 43,
            ):
                with self.subTest(path=path), urllib.request.urlopen(
                    base_url + path, timeout=5
                ) as response:
                    body = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertIn('id="login-form"', body)

    def test_recovery_email_uses_safe_fixed_link_and_escapes_appearance(self) -> None:
        expires_at = "2026-01-02T03:19:05+00:00"
        rendered = fortios_notify.compose_recovery_email(
            "verify_recovery_email",
            "t" * 43,
            "https://example.test:9443/app/?return=https://evil.test/#fragment",
            expires_at,
            appearance=fortios_notify.EmailAppearance(
                display_name="<FortiUpgrade>",
                introduction="<script>alert(1)</script>",
                signature="<&>",
            ),
        )

        self.assertEqual(
            rendered["link"],
            "https://example.test:9443/cert/verify-email?token=" + "t" * 43,
        )
        self.assertIn(rendered["link"], rendered["text"])
        self.assertIn(rendered["link"], rendered["html"])
        self.assertNotIn("return=https://evil.test", rendered["text"])
        self.assertNotIn("<script>", rendered["html"])
        self.assertIn("&lt;script&gt;", rendered["html"])
        self.assertEqual(rendered["text"].count("t" * 43), 1)

    def test_http_reset_revokes_sessions_and_accepts_only_new_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            cert_admin.create_initial_credentials(credentials, "admin", "initial-password")
            state = cert_admin.load_admin_state(credentials)
            state["currentRecoveryEmail"] = "verified@example.test"
            cert_admin.save_admin_state(credentials, state)
            reset_token = cert_admin.issue_password_reset_token(credentials)
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "admin", "password": "initial-password"}
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(login, timeout=5) as response:
                    response.read()
                    cookie = response.headers["Set-Cookie"].split(";", 1)[0]
                reset = urllib.request.Request(
                    f"{base_url}/api/cert/reset-password",
                    data=json.dumps(
                        {
                            "token": reset_token,
                            "newPassword": "new-password-123",
                            "confirmation": "new-password-123",
                        }
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(reset, timeout=5) as response:
                    reset_status = response.status
                    reset_payload = json.load(response)
                    expired_cookie = response.headers["Set-Cookie"]
                status = urllib.request.Request(
                    f"{base_url}/api/cert/status",
                    headers={"Cookie": cookie},
                )
                try:
                    with urllib.request.urlopen(status, timeout=5) as response:
                        old_session_status = response.status
                except urllib.error.HTTPError as error:
                    old_session_status = error.code
                old_login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "admin", "password": "initial-password"}
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                try:
                    with urllib.request.urlopen(old_login, timeout=5) as response:
                        old_login_status = response.status
                except urllib.error.HTTPError as error:
                    old_login_status = error.code
                new_login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "admin", "password": "new-password-123"}
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(new_login, timeout=5) as response:
                    new_login_status = response.status

        self.assertEqual(reset_status, 200)
        self.assertEqual(reset_payload, {"reset": True, "authenticated": False})
        self.assertIn("Max-Age=0", expired_cookie)
        self.assertEqual(old_session_status, 401)
        self.assertEqual(old_login_status, 401)
        self.assertEqual(new_login_status, 200)
