"""SMTP administration persistence, API security, and delivery tests."""

from __future__ import annotations

import http.cookiejar
import io
import json
import smtplib
import socketserver
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stderr
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_notify as notify

from tests.test_cert_web import cert_admin, running_server


def smtp_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "host": "smtp.saved.example",
        "port": 587,
        "security": "starttls",
        "allowInsecure": False,
        "username": "mailer@example.com",
        "from": "fortiupgrade@example.com",
        "appUrl": "https://fortiupgrade.example/app/",
        "timeout": 12,
        "emailAppearance": {
            "displayName": "FortiUpgrade",
            "introduction": "Alerte de sécurité Fortinet.",
            "signature": "Équipe sécurité",
        },
    }
    payload.update(overrides)
    return payload


def notification_settings() -> notify.NotificationSettings:
    return notify.validate_notification_settings(
        {
            "enabled": True,
            "minimumSeverity": "high",
            "products": {
                "fortigate-fortios": True,
                "fortimanager": True,
                "fortianalyzer": True,
                "forticlient-ems": True,
                "forticlient": {"windows": True, "macos": True, "linux": True},
            },
            "recipients": ["security@example.com"],
        }
    )


def email_config(*, security: str = "starttls") -> notify.EmailConfig:
    return notify.EmailConfig(
        enabled=True,
        smtp_host="smtp.saved.example",
        smtp_port=465 if security == "tls" else 587,
        smtp_username="mailer@example.com",
        smtp_password="smtp-secret-value",
        smtp_from="fortiupgrade@example.com",
        smtp_to=("security@example.com",),
        smtp_starttls=security == "starttls",
        smtp_timeout=12,
        app_url="https://fortiupgrade.example/app/",
        smtp_security=security,
    )


def authenticated_opener(base_url: str) -> tuple[urllib.request.OpenerDirector, str]:
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    login = urllib.request.Request(
        f"{base_url}/api/cert/login",
        data=json.dumps(
            {"username": "valentin", "password": "mot-de-passe-solide"}
        ).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Origin": base_url},
    )
    with opener.open(login, timeout=3) as response:
        return opener, json.load(response)["csrfToken"]


class RecordingSmtpServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self) -> None:
        self.messages: list[bytes] = []
        super().__init__(("127.0.0.1", 0), RecordingSmtpHandler)


class RecordingSmtpHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write(b"220 local.test ESMTP\r\n")
        while line := self.rfile.readline():
            command = line.decode("ascii", errors="replace").upper()
            if command.startswith(("EHLO ", "HELO ")):
                self.wfile.write(b"250-local.test\r\n250 HELP\r\n")
            elif command.startswith(("MAIL FROM:", "RCPT TO:")):
                self.wfile.write(b"250 accepted\r\n")
            elif command.startswith("DATA"):
                self.wfile.write(b"354 end with dot\r\n")
                message = bytearray()
                while data_line := self.rfile.readline():
                    if data_line == b".\r\n":
                        break
                    message.extend(data_line[1:] if data_line.startswith(b"..") else data_line)
                self.server.messages.append(bytes(message))  # type: ignore[attr-defined]
                self.wfile.write(b"250 queued\r\n")
            elif command.startswith("QUIT"):
                self.wfile.write(b"221 bye\r\n")
                break
            else:
                self.wfile.write(b"250 accepted\r\n")


@contextmanager
def running_smtp_server() -> Iterator[RecordingSmtpServer]:
    server = RecordingSmtpServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class SmtpSettingsPersistenceTests(unittest.TestCase):
    def test_hidden_private_backup_uses_a_single_dot_temporary_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / ".smtp-password.transaction-backup"
            with (
                patch("os.open", side_effect=OSError("stop")) as open_file,
                self.assertRaises(OSError),
            ):
                notify._atomic_write_private(backup, "test-secret", 0o600)

            temporary = Path(open_file.call_args.args[0])
            self.assertTrue(
                temporary.name.startswith(
                    ".smtp-password.transaction-backup.tmp-"
                )
            )
            self.assertFalse(temporary.name.startswith(".."))

    def test_unknown_starttls_environment_value_fails_closed(self) -> None:
        smtp = notify._smtp_settings_from_env(
            {"FORTIOS_SMTP_STARTTLS": "unexpected-value"}
        )

        self.assertEqual(smtp.security, "starttls")
        self.assertFalse(smtp.allow_insecure)

    def test_saved_settings_override_environment_and_keep_password_out_of_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings_path = root / "smtp-settings.json"
            env_secret = root / "legacy-password"
            env_secret.write_text("legacy-secret\n", encoding="utf-8")
            environment = {
                "FORTIOS_SMTP_HOST": "smtp.environment.example",
                "FORTIOS_SMTP_FROM": "legacy@example.com",
                "FORTIOS_SMTP_PASSWORD_FILE": str(env_secret),
            }

            notify.save_smtp_settings(
                settings_path,
                smtp_payload(),
                password="saved-secret-value",
            )
            config = notify.load_email_config(
                environment,
                settings=notification_settings(),
                smtp_settings_path=settings_path,
            )

            persisted = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertEqual(config.smtp_host, "smtp.saved.example")
            self.assertEqual(config.smtp_password, "saved-secret-value")
            self.assertEqual(
                config.email_appearance,
                notify.EmailAppearance(
                    display_name="FortiUpgrade",
                    introduction="Alerte de sécurité Fortinet.",
                    signature="Équipe sécurité",
                ),
            )
            self.assertNotIn("password", json.dumps(persisted).lower())
            self.assertNotIn("saved-secret-value", json.dumps(persisted))
            self.assertEqual(stat.S_IMODE(settings_path.stat().st_mode), 0o640)
            self.assertEqual(
                stat.S_IMODE(notify.smtp_password_path(settings_path).stat().st_mode),
                0o600,
            )

    def test_invalid_host_port_and_sender_are_rejected(self) -> None:
        invalid_payloads = (
            smtp_payload(host=""),
            smtp_payload(host="https://smtp.example.com"),
            smtp_payload(port=0),
            smtp_payload(port=65536),
            smtp_payload(**{"from": "sender\nBcc: attacker@example.com"}),
        )

        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                notify.validate_smtp_settings(payload)

    def test_blank_password_preserves_secret_and_nonblank_replaces_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings_path = Path(tmp) / "smtp-settings.json"
            notify.save_smtp_settings(
                settings_path, smtp_payload(), password="initial-secret"
            )

            notify.save_smtp_settings(
                settings_path,
                smtp_payload(host="smtp.changed.example"),
                password="",
            )
            preserved = notify.load_email_config(
                {},
                settings=notification_settings(),
                smtp_settings_path=settings_path,
            )
            self.assertEqual(preserved.smtp_password, "initial-secret")

            notify.save_smtp_settings(
                settings_path,
                smtp_payload(host="smtp.changed.example"),
                password="replacement-secret",
            )
            replaced = notify.load_email_config(
                {},
                settings=notification_settings(),
                smtp_settings_path=settings_path,
            )
            self.assertEqual(replaced.smtp_password, "replacement-secret")

    def test_environment_is_bootstrap_only_until_saved_file_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings_path = root / "smtp-settings.json"
            env_secret = root / "environment-secret"
            env_secret.write_text("bootstrap-secret\n", encoding="utf-8")
            environment = {
                "FORTIOS_SMTP_HOST": "smtp.bootstrap.example",
                "FORTIOS_SMTP_PORT": "2525",
                "FORTIOS_SMTP_USERNAME": "bootstrap-user",
                "FORTIOS_SMTP_PASSWORD_FILE": str(env_secret),
                "FORTIOS_SMTP_STARTTLS": "true",
                "FORTIOS_SMTP_TIMEOUT": "20",
                "FORTIOS_SMTP_FROM": "bootstrap@example.com",
                "FORTIOS_APP_URL": "https://bootstrap.example/app/",
            }

            bootstrapped = notify.load_email_config(
                environment,
                settings=notification_settings(),
                smtp_settings_path=settings_path,
            )
            self.assertEqual(bootstrapped.smtp_host, "smtp.bootstrap.example")
            self.assertEqual(bootstrapped.smtp_password, "bootstrap-secret")

            notify.save_smtp_settings(
                settings_path, smtp_payload(), password="saved-secret"
            )
            saved = notify.load_email_config(
                environment,
                settings=notification_settings(),
                smtp_settings_path=settings_path,
            )
            self.assertEqual(saved.smtp_host, "smtp.saved.example")
            self.assertEqual(saved.smtp_password, "saved-secret")

    def test_first_web_save_with_blank_password_migrates_bootstrap_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings_path = root / "smtp-settings.json"
            bootstrap_secret = root / "bootstrap-password"
            bootstrap_secret.write_text("bootstrap-secret\n", encoding="utf-8")
            environment = {
                "FORTIOS_SMTP_PASSWORD_FILE": str(bootstrap_secret),
            }

            notify.save_smtp_settings(
                settings_path,
                smtp_payload(),
                password="",
                env=environment,
            )
            config = notify.load_email_config(
                environment,
                settings=notification_settings(),
                smtp_settings_path=settings_path,
            )

            self.assertEqual(config.smtp_password, "bootstrap-secret")
            self.assertEqual(
                stat.S_IMODE(notify.smtp_password_path(settings_path).stat().st_mode),
                0o600,
            )

    def test_runtime_never_reads_settings_and_secret_from_different_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings_path = Path(tmp) / "smtp-settings.json"
            notify.save_smtp_settings(
                settings_path,
                smtp_payload(host="smtp-a.example"),
                password="secret-a",
            )
            secret_read_started = threading.Event()
            original_env_secret = notify._env_secret

            def delayed_env_secret(
                env: dict[str, str], key: str
            ) -> tuple[str, str, str]:
                if env.get("FORTIOS_SMTP_PASSWORD_FILE") == str(
                    notify.smtp_password_path(settings_path)
                ):
                    secret_read_started.set()
                    time.sleep(0.1)
                return original_env_secret(env, key)

            loaded: list[notify.EmailConfig] = []
            with patch.object(notify, "_env_secret", delayed_env_secret):
                reader = threading.Thread(
                    target=lambda: loaded.append(
                        notify.load_email_config(
                            {},
                            settings=notification_settings(),
                            smtp_settings_path=settings_path,
                        )
                    )
                )
                reader.start()
                self.assertTrue(secret_read_started.wait(timeout=1))
                writer = threading.Thread(
                    target=lambda: notify.save_smtp_settings(
                        settings_path,
                        smtp_payload(host="smtp-b.example"),
                        password="secret-b",
                    )
                )
                writer.start()
                reader.join(timeout=2)
                writer.join(timeout=2)

            self.assertFalse(reader.is_alive())
            self.assertFalse(writer.is_alive())
            self.assertIn(
                (loaded[0].smtp_host, loaded[0].smtp_password),
                {
                    ("smtp-a.example", "secret-a"),
                    ("smtp-b.example", "secret-b"),
                },
            )

    def test_failed_settings_write_rolls_back_secret_and_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings_path = Path(tmp) / "smtp-settings.json"
            notify.save_smtp_settings(
                settings_path,
                smtp_payload(host="smtp-old.example"),
                password="old-secret",
            )
            original_write = notify._atomic_write_private

            def fail_new_settings_write(path: Path, content: str, mode: int) -> None:
                if path == settings_path and "smtp-new.example" in content:
                    raise OSError("injected settings write failure")
                original_write(path, content, mode)

            with patch.object(
                notify, "_atomic_write_private", side_effect=fail_new_settings_write
            ), self.assertRaises(OSError):
                notify.save_smtp_settings(
                    settings_path,
                    smtp_payload(host="smtp-new.example"),
                    password="new-secret",
                )

            config = notify.load_email_config(
                {},
                settings=notification_settings(),
                smtp_settings_path=settings_path,
            )
            self.assertEqual(config.smtp_host, "smtp-old.example")
            self.assertEqual(config.smtp_password, "old-secret")
            self.assertFalse(
                any("transaction" in path.name for path in settings_path.parent.iterdir())
            )

    def test_load_recovers_transaction_interrupted_after_both_replacements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings_path = Path(tmp) / "smtp-settings.json"
            notify.save_smtp_settings(
                settings_path,
                smtp_payload(host="smtp-old.example"),
                password="old-secret",
            )
            with notify.cross_process_lock(settings_path):
                notify._begin_smtp_transaction_unlocked(settings_path)
                notify._atomic_write_private(
                    notify.smtp_password_path(settings_path), "new-secret", 0o600
                )
                notify._atomic_write_private(
                    settings_path,
                    json.dumps(
                        smtp_payload(host="smtp-new.example"),
                        indent=2,
                        ensure_ascii=False,
                    )
                    + "\n",
                    0o640,
                )

            config = notify.load_email_config(
                {},
                settings=notification_settings(),
                smtp_settings_path=settings_path,
            )
            self.assertEqual(config.smtp_host, "smtp-old.example")
            self.assertEqual(config.smtp_password, "old-secret")
            self.assertFalse(
                any("transaction" in path.name for path in settings_path.parent.iterdir())
            )

    def test_smtp_snapshot_keeps_settings_and_secret_from_one_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings_path = Path(tmp) / "smtp-settings.json"
            notify.save_smtp_settings(
                settings_path,
                smtp_payload(host="smtp-a.example"),
                password="secret-a",
            )
            read_started = threading.Event()
            original_env_secret = notify._env_secret

            def delayed_env_secret(
                env: dict[str, str], key: str
            ) -> tuple[str, str, str]:
                if env.get("FORTIOS_SMTP_PASSWORD_FILE") == str(
                    notify.smtp_password_path(settings_path)
                ):
                    read_started.set()
                    time.sleep(0.1)
                return original_env_secret(env, key)

            snapshots: list[tuple[notify.SmtpSettings, notify.EmailConfig]] = []
            with patch.object(notify, "_env_secret", delayed_env_secret):
                reader = threading.Thread(
                    target=lambda: snapshots.append(
                        notify.load_smtp_snapshot(
                            {},
                            settings=notification_settings(),
                            smtp_settings_path=settings_path,
                        )
                    )
                )
                reader.start()
                self.assertTrue(read_started.wait(timeout=1))
                writer = threading.Thread(
                    target=lambda: notify.save_smtp_settings(
                        settings_path,
                        smtp_payload(host="smtp-b.example"),
                        password="secret-b",
                    )
                )
                writer.start()
                reader.join(timeout=2)
                writer.join(timeout=2)

            self.assertFalse(reader.is_alive())
            self.assertFalse(writer.is_alive())
            smtp, config = snapshots[0]
            self.assertEqual(smtp.host, config.smtp_host)
            self.assertIn(
                (smtp.host, config.smtp_password),
                {
                    ("smtp-a.example", "secret-a"),
                    ("smtp-b.example", "secret-b"),
                },
            )


class SmtpDeliveryTests(unittest.TestCase):
    @staticmethod
    def smtp_client() -> MagicMock:
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        return client

    def test_implicit_tls_uses_smtp_ssl_and_reports_successful_stages(self) -> None:
        client = self.smtp_client()
        with patch("smtplib.SMTP_SSL", return_value=client) as smtp_ssl, patch(
            "smtplib.SMTP"
        ) as smtp_plain:
            result = notify.send_email_result(
                email_config(security="tls"),
                "Sujet",
                "Corps",
                force=True,
            )

        self.assertTrue(result.sent)
        smtp_ssl.assert_called_once()
        smtp_plain.assert_not_called()
        self.assertEqual(
            result.checks,
            (
                "Résolution DNS",
                "Connexion TCP",
                "TLS implicite",
                "Authentification",
                "Expéditeur et destinataire acceptés",
                "Message accepté par le serveur SMTP",
            ),
        )

    def test_authentication_failure_is_precise_and_never_leaks_secret(self) -> None:
        client = self.smtp_client()
        client.login.side_effect = smtplib.SMTPAuthenticationError(
            535, b"smtp-secret-value"
        )
        stderr = io.StringIO()
        with patch("smtplib.SMTP", return_value=client), redirect_stderr(stderr):
            result = notify.send_email_result(
                email_config(), "Sujet", "Corps", force=True
            )

        self.assertFalse(result.sent)
        self.assertEqual(result.message, "Authentification SMTP refusée.")
        self.assertNotIn("smtp-secret-value", result.message)
        self.assertNotIn("smtp-secret-value", stderr.getvalue())

    def test_tls_failure_is_precise_and_never_leaks_secret(self) -> None:
        client = self.smtp_client()
        client.starttls.side_effect = smtplib.SMTPException("smtp-secret-value")
        stderr = io.StringIO()
        with patch("smtplib.SMTP", return_value=client), redirect_stderr(stderr):
            result = notify.send_email_result(
                email_config(), "Sujet", "Corps", force=True
            )

        self.assertFalse(result.sent)
        self.assertEqual(result.message, "Négociation STARTTLS impossible.")
        self.assertNotIn("smtp-secret-value", result.message)
        self.assertNotIn("smtp-secret-value", stderr.getvalue())

    def test_test_email_uses_selected_recipient_subject_and_appearance(self) -> None:
        client = self.smtp_client()
        appearance = notify.EmailAppearance(
            display_name="FortiUpgrade SOC",
            introduction="Introduction personnalisée.",
            signature="Signature personnalisée.",
        )
        with patch("smtplib.SMTP", return_value=client):
            result = notify.send_test_email_result(
                email_config(),
                recipient="test-recipient@example.com",
                appearance=appearance,
            )

        self.assertTrue(result.sent)
        message = client.send_message.call_args.args[0]
        self.assertEqual(message["Subject"], "[FortiUpgrade][TEST] Validation SMTP")
        self.assertEqual(message["To"], "test-recipient@example.com")
        body = message.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("FortiUpgrade SOC", body)
        self.assertIn("Introduction personnalisée.", body)
        self.assertIn("Signature personnalisée.", body)
        self.assertIn("test", body.lower())
        self.assertIn("Message accepté par le serveur SMTP", result.checks)

    def test_custom_appearance_surrounds_but_cannot_remove_security_content(self) -> None:
        event = notify.NotificationEvent(
            category=notify.CATEGORY_CRITICAL,
            dedup_key="new-cve|psirt|CVE-2026-12345|critical",
            summary="CVE critique",
            severity="critical",
            details={
                "kind": "cve",
                "id": "CVE-2026-12345",
                "title": "Vulnérabilité critique",
                "url": "https://fortiguard.example/CVE-2026-12345",
                "productLabels": ["FortiGate / FortiOS"],
                "affected": [{"product": "fortigate-fortios", "branch": "7.4"}],
            },
        )
        appearance = notify.EmailAppearance(
            display_name="SOC Tetrax",
            introduction="Introduction contrôlée.",
            signature="Signature contrôlée.",
        )

        composed = notify.compose_email(
            [event],
            app_url="https://fortiupgrade.example/app/",
            run_timestamp="2026-09-02T10:00:00Z",
            appearance=appearance,
        )

        self.assertIsNotNone(composed)
        _subject, text_body, html_body = composed or ("", "", "")
        for body in (text_body, html_body):
            self.assertIn("SOC Tetrax", body)
            self.assertIn("Introduction contrôlée.", body)
            self.assertIn("Signature contrôlée.", body)
            self.assertIn("CVE-2026-12345", body)
            self.assertIn("FortiGate / FortiOS", body)
            self.assertIn("fortiguard.example", body)


class SmtpAdminApiTests(unittest.TestCase):
    def test_smtp_api_requires_login_and_csrf_and_never_returns_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            data_dir = root / "data"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload(
                    "valentin", "mot-de-passe-solide"
                ),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(data_dir),
            }
            with running_server(environment) as base_url:
                with self.assertRaises(urllib.error.HTTPError) as anonymous:
                    urllib.request.urlopen(
                        f"{base_url}/api/cert/smtp", timeout=3
                    )
                self.assertEqual(anonymous.exception.code, 401)

                opener, csrf_token = authenticated_opener(base_url)
                body = {**smtp_payload(), "password": "browser-secret-value"}
                without_csrf = urllib.request.Request(
                    f"{base_url}/api/cert/smtp",
                    data=json.dumps(body).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    opener.open(without_csrf, timeout=3)
                self.assertEqual(rejected.exception.code, 403)

                write = urllib.request.Request(
                    f"{base_url}/api/cert/smtp",
                    data=json.dumps(body).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    },
                )
                with opener.open(write, timeout=3) as response:
                    written = json.load(response)
                with opener.open(
                    f"{base_url}/api/cert/smtp", timeout=3
                ) as response:
                    loaded = json.load(response)
                with opener.open(
                    f"{base_url}/api/cert/notifications", timeout=3
                ) as response:
                    notification_projection = json.load(response)

            self.assertTrue(written["smtp"]["passwordConfigured"])
            self.assertEqual(written, loaded)
            self.assertEqual(
                notification_projection["smtp"]["host"], "smtp.saved.example"
            )
            serialized = json.dumps(written)
            self.assertNotIn("browser-secret-value", serialized)
            self.assertNotIn('"password"', serialized.lower())

    def test_test_endpoint_sends_without_touching_notification_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, running_smtp_server() as smtp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            data_dir = root / "data"
            data_dir.mkdir()
            history = data_dir / "fortios-notify-history.json"
            history.write_text(
                '{"checkpoint":{"marker":"unchanged"},"sentKeys":{},"outbox":[]}\n',
                encoding="utf-8",
            )
            history_before = history.read_bytes()
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload(
                    "valentin", "mot-de-passe-solide"
                ),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(data_dir),
            }
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)
                smtp_body = smtp_payload(
                    host="127.0.0.1",
                    port=smtp.server_address[1],
                    security="none",
                    allowInsecure=True,
                    username="",
                )
                save = urllib.request.Request(
                    f"{base_url}/api/cert/smtp",
                    data=json.dumps(smtp_body).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    },
                )
                with opener.open(save, timeout=3):
                    pass

                def send_test_email() -> dict[str, Any]:
                    request = urllib.request.Request(
                        f"{base_url}/api/cert/notifications/test",
                        data=json.dumps(
                            {"recipient": "smtp-test@example.com"}
                        ).encode(),
                        method="POST",
                        headers={
                            "Content-Type": "application/json",
                            "Origin": base_url,
                            "X-CSRF-Token": csrf_token,
                        },
                    )
                    with opener.open(request, timeout=3) as response:
                        return json.load(response)

                result = send_test_email()
                self.assertTrue(send_test_email()["sent"])
                self.assertTrue(send_test_email()["sent"])
                with self.assertRaises(urllib.error.HTTPError) as limited:
                    send_test_email()
                self.assertEqual(limited.exception.code, 429)

            self.assertTrue(result["sent"])
            self.assertIn("Message accepté par le serveur SMTP", result["checks"])
            self.assertEqual(result["summary"]["recipient"], "smtp-test@example.com")
            self.assertEqual(history.read_bytes(), history_before)
            self.assertEqual(len(smtp.messages), 3)
            message = BytesParser(policy=policy.default).parsebytes(smtp.messages[0])
            self.assertEqual(message["Subject"], "[FortiUpgrade][TEST] Validation SMTP")
            self.assertEqual(message["To"], "smtp-test@example.com")


if __name__ == "__main__":
    unittest.main()
