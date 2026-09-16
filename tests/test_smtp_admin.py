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
            "releaseIntroduction": "",
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


def alerts_payload() -> dict[str, object]:
    """Canonical functional alert preferences, shaped as the admin page submits them."""
    return {
        "enabled": True,
        "minimumSeverity": "high",
        "products": {
            "fortigate-fortios": True,
            "fortimanager": False,
            "fortianalyzer": False,
            "forticlient-ems": False,
            "forticlient": {"windows": True, "macos": False, "linux": False},
        },
        "recipients": ["soc@example.com"],
    }


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
    def test_unknown_security_environment_value_fails_closed(self) -> None:
        smtp = notify._smtp_settings_from_env(
            {"FORTIOS_SMTP_SECURITY": "unexpected-value"}
        )

        self.assertEqual(smtp.security, "starttls")
        self.assertFalse(smtp.allow_insecure)

    def test_legacy_starttls_environment_value_remains_supported(self) -> None:
        smtp = notify._smtp_settings_from_env(
            {"FORTIOS_SMTP_STARTTLS": "false"}
        )

        self.assertEqual(smtp.security, "none")
        self.assertTrue(smtp.allow_insecure)

    def test_environment_transport_is_authoritative_over_legacy_saved_fields(self) -> None:
        appearance = {
            "displayName": "Saved title",
            "introduction": "Saved introduction",
            "signature": "Saved signature",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings_path = root / "smtp-settings.json"
            settings_path.write_text(
                json.dumps(
                    {
                        **smtp_payload(),
                        "host": "smtp.saved.example",
                        "password": "legacy-secret-must-not-be-read",
                        "emailAppearance": appearance,
                    }
                ),
                encoding="utf-8",
            )
            secret = root / "mounted-secret"
            secret.write_text("environment-secret\n", encoding="utf-8")
            environment = {
                "FORTIOS_SMTP_HOST": "smtp.environment.example",
                "FORTIOS_SMTP_PORT": "465",
                "FORTIOS_SMTP_USERNAME": "environment-user",
                "FORTIOS_SMTP_SECURITY": "tls",
                "FORTIOS_SMTP_ALLOW_INSECURE": "false",
                "FORTIOS_SMTP_FROM": "environment@example.com",
                "FORTIOS_SMTP_TIMEOUT": "19",
                "FORTIOS_APP_URL": "https://environment.example/app/",
                "FORTIOS_SMTP_PASSWORD_FILE": str(secret),
            }

            smtp, config = notify.load_smtp_snapshot(
                environment,
                settings=notification_settings(),
                smtp_settings_path=settings_path,
            )
            public = notify.smtp_public_settings(smtp, config)

        self.assertEqual(smtp.source, "environment")
        self.assertEqual(config.smtp_host, "smtp.environment.example")
        self.assertEqual(config.smtp_port, 465)
        self.assertEqual(config.smtp_username, "environment-user")
        self.assertEqual(config.smtp_security, "tls")
        self.assertEqual(config.smtp_from, "environment@example.com")
        self.assertEqual(config.smtp_timeout, 19)
        self.assertEqual(config.app_url, "https://environment.example/app/")
        self.assertEqual(config.smtp_password, "environment-secret")
        self.assertEqual(config.email_appearance, notify.validate_email_appearance(appearance))
        self.assertEqual(public["host"], "smtp.environment.example")
        self.assertEqual(public["source"], "environment")
        serialized = json.dumps(public)
        self.assertNotIn("environment-secret", serialized)
        self.assertNotIn("legacy-secret", serialized)
        self.assertNotIn(str(secret), serialized)

    def test_new_gui_schema_precedes_environment_and_keeps_password_out_of_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings_path = root / "smtp-settings.json"
            password_path = root / "smtp-secrets" / "password"
            password_path.parent.mkdir()
            environment = {
                "FORTIOS_SMTP_HOST": "smtp.bootstrap.example",
                "FORTIOS_SMTP_PORT": "2525",
                "FORTIOS_SMTP_SECURITY": "starttls",
                "FORTIOS_SMTP_USERNAME": "bootstrap-user",
                "FORTIOS_SMTP_FROM": "bootstrap@example.com",
                "FORTIOS_SMTP_TIMEOUT": "20",
                "FORTIOS_APP_URL": "https://bootstrap.example/app/",
                "FORTIOS_SMTP_PASSWORD_FILE": str(password_path),
            }
            notify.save_smtp_settings(settings_path, smtp_payload(), env=environment)
            persisted = json.loads(settings_path.read_text(encoding="utf-8"))
            changed_environment = {
                **environment,
                "FORTIOS_SMTP_HOST": "smtp.changed.example",
                "FORTIOS_SMTP_PORT": "465",
                "FORTIOS_SMTP_USERNAME": "changed-user",
                "FORTIOS_SMTP_FROM": "changed@example.com",
                "FORTIOS_SMTP_TIMEOUT": "30",
                "FORTIOS_APP_URL": "https://changed.example/app/",
            }
            loaded = notify.load_smtp_settings(settings_path, env=changed_environment)
            public = notify.smtp_public_settings(
                loaded,
                notify.load_email_config(
                    changed_environment,
                    settings=notification_settings(),
                    smtp_settings_path=settings_path,
                ),
            )

        self.assertEqual(persisted["schemaVersion"], notify.SMTP_SETTINGS_SCHEMA_VERSION)
        self.assertEqual(loaded.source, "saved")
        self.assertEqual(loaded.host, "smtp.saved.example")
        self.assertEqual(loaded.port, 587)
        self.assertEqual(loaded.username, "mailer@example.com")
        self.assertEqual(loaded.sender, "fortiupgrade@example.com")
        self.assertEqual(loaded.app_url, "https://fortiupgrade.example/app/")
        serialized = json.dumps(persisted) + json.dumps(public)
        self.assertNotIn("api-secret-value", serialized)
        self.assertNotIn("smtp-secret", serialized)

    def test_corrupt_new_schema_fails_closed_instead_of_bootstrapping_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smtp-settings.json"
            path.write_text(
                json.dumps({"schemaVersion": notify.SMTP_SETTINGS_SCHEMA_VERSION, "host": "smtp.saved.example"}),
                encoding="utf-8",
            )
            environment = {
                "FORTIOS_SMTP_HOST": "smtp.environment.example",
                "FORTIOS_SMTP_FROM": "environment@example.com",
                "FORTIOS_SMTP_PASSWORD_FILE": str(Path(tmp) / "password"),
            }
            loaded = notify.load_smtp_settings(path, env=environment)
            config = notify.load_email_config(
                environment,
                settings=notification_settings(),
                smtp_settings_path=path,
            )

        self.assertEqual(loaded.source, "saved-invalid")
        self.assertEqual(loaded.host, "")
        self.assertNotEqual(config.smtp_host, "smtp.environment.example")
        self.assertFalse(config.is_complete())

    def test_truncated_existing_document_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smtp-settings.json"
            path.write_text(
                '{"schemaVersion": 1, "host": "smtp.partial.example",',
                encoding="utf-8",
            )
            environment = {
                "FORTIOS_SMTP_HOST": "smtp.environment.example",
                "FORTIOS_SMTP_FROM": "environment@example.com",
            }
            loaded = notify.load_smtp_settings(path, env=environment)
            config = notify.load_email_config(
                environment,
                settings=notification_settings(),
                smtp_settings_path=path,
            )

        self.assertEqual(loaded.source, "saved-invalid")
        self.assertEqual(loaded.host, "")
        self.assertNotEqual(config.smtp_host, "smtp.environment.example")
        self.assertFalse(config.is_complete())

    def test_existing_non_object_documents_fail_closed(self) -> None:
        for document in ([], 42, "smtp-settings"):
            with self.subTest(document=document), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "smtp-settings.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                settings = notify.load_smtp_settings(
                    path,
                    env={"FORTIOS_SMTP_HOST": "smtp.environment.example"},
                )
                self.assertEqual(settings.source, "saved-invalid")
                self.assertEqual(settings.host, "")

    def test_smtp_password_is_write_only_atomic_and_empty_submission_preserves_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            password_path = Path(tmp) / "smtp-secrets" / "password"
            password_path.parent.mkdir()
            environment = {"FORTIOS_SMTP_PASSWORD_FILE": str(password_path)}
            notify.save_smtp_password("initial-secret", env=environment)
            self.assertEqual(password_path.read_bytes(), b"initial-secret")
            self.assertEqual(stat.S_IMODE(password_path.stat().st_mode), 0o600)
            self.assertEqual(
                notify.save_smtp_password("", env=environment),
                notify.SMTP_PASSWORD_STORAGE_AVAILABLE,
            )
            self.assertEqual(password_path.read_bytes(), b"initial-secret")
            config = notify.load_email_config(
                {
                    **environment,
                    "FORTIOS_SMTP_HOST": "smtp.example.com",
                    "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
                },
                settings=notification_settings(),
                smtp_settings_path=Path(tmp) / "missing-settings.json",
            )
            public = notify.smtp_public_settings(
                notify.load_smtp_settings(Path(tmp) / "missing-settings.json", env=environment),
                config,
            )

        self.assertEqual(config.smtp_password, "initial-secret")
        self.assertTrue(public["passwordConfigured"])
        serialized = json.dumps(public)
        self.assertNotIn("initial-secret", serialized)
        self.assertNotIn(str(password_path), serialized)

    def test_smtp_password_requires_prepared_private_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            password_path = Path(tmp) / "unprepared" / "password"
            environment = {"FORTIOS_SMTP_PASSWORD_FILE": str(password_path)}
            with self.assertRaises(notify.SmtpPasswordStorageError):
                notify.save_smtp_password("must-not-create", env=environment)
            self.assertFalse(password_path.parent.exists())

    def test_graph_and_appearance_saves_preserve_new_saved_smtp_fields(self) -> None:
        appearance = smtp_payload()["emailAppearance"]
        graph_payload = {
            "transport": "microsoft365",
            "microsoft365": {
                "tenantId": "tenant.example.test",
                "clientId": "11111111-2222-3333-4444-555555555555",
                "from": "graph@example.com",
                "displayName": "Graph",
                "mailboxIdentity": "graph@example.com",
            },
            "emailAppearance": {
                "displayName": "Graph appearance",
                "introduction": "Graph intro",
                "releaseIntroduction": "",
                "signature": "Graph signature",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            smtp_path = root / "smtp-settings.json"
            transport_path = root / "email-transport-settings.json"
            notify.save_smtp_settings(smtp_path, smtp_payload())
            notify.save_email_configuration(smtp_path, transport_path, graph_payload)
            after_graph = json.loads(smtp_path.read_text(encoding="utf-8"))
            notify.save_email_appearance(
                smtp_path,
                {"emailAppearance": appearance},
            )
            after_appearance = json.loads(smtp_path.read_text(encoding="utf-8"))

        for saved in (after_graph, after_appearance):
            self.assertEqual(saved["schemaVersion"], notify.SMTP_SETTINGS_SCHEMA_VERSION)
            self.assertEqual(saved["host"], "smtp.saved.example")
            self.assertEqual(saved["port"], 587)
            self.assertEqual(saved["username"], "mailer@example.com")
        self.assertEqual(after_graph["emailAppearance"]["displayName"], "Graph appearance")
        self.assertEqual(after_appearance["emailAppearance"], appearance)

    def test_graph_save_can_validate_and_persist_nested_smtp_before_writes(self) -> None:
        graph_payload = {
            "transport": "microsoft365",
            "microsoft365": {
                "tenantId": "tenant.example.test",
                "clientId": "11111111-2222-3333-4444-555555555555",
                "from": "graph@example.com",
                "displayName": "Graph",
                "mailboxIdentity": "graph@example.com",
            },
            "emailAppearance": {
                "displayName": "Shared appearance",
                "introduction": "Shared intro",
                "releaseIntroduction": "",
                "signature": "Shared signature",
            },
            "smtp": smtp_payload(),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            smtp_path = root / "smtp-settings.json"
            transport_path = root / "email-transport-settings.json"
            notify.save_email_configuration(smtp_path, transport_path, graph_payload)
            saved_smtp = json.loads(smtp_path.read_text(encoding="utf-8"))
            saved_transport = json.loads(transport_path.read_text(encoding="utf-8"))

        self.assertEqual(saved_smtp["schemaVersion"], notify.SMTP_SETTINGS_SCHEMA_VERSION)
        self.assertEqual(saved_smtp["host"], "smtp.saved.example")
        self.assertEqual(saved_smtp["emailAppearance"], graph_payload["emailAppearance"])
        self.assertEqual(saved_transport["transport"], "microsoft365")
        self.assertNotIn("password", json.dumps(saved_smtp).lower())

    def test_graph_save_preflights_malformed_smtp_before_transport_write(self) -> None:
        graph_payload = {
            "transport": "microsoft365",
            "microsoft365": {
                "tenantId": "tenant.example.test",
                "clientId": "11111111-2222-3333-4444-555555555555",
                "from": "graph@example.com",
                "displayName": "Graph",
                "mailboxIdentity": "graph@example.com",
            },
            "emailAppearance": {
                "displayName": "Shared appearance",
                "introduction": "Shared intro",
                "releaseIntroduction": "",
                "signature": "Shared signature",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            smtp_path = root / "smtp-settings.json"
            transport_path = root / "email-transport-settings.json"
            smtp_path.write_text(
                json.dumps({"schemaVersion": notify.SMTP_SETTINGS_SCHEMA_VERSION, "host": ""}),
                encoding="utf-8",
            )
            original_transport = {"transport": "smtp", "microsoft365": {
                "tenantId": "", "clientId": "", "from": "", "displayName": "", "mailboxIdentity": ""
            }}
            transport_path.write_text(json.dumps(original_transport), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Configuration SMTP"):
                notify.save_email_configuration(smtp_path, transport_path, graph_payload)
            self.assertEqual(json.loads(transport_path.read_text(encoding="utf-8")), original_transport)

    def test_nested_smtp_save_repairs_corrupt_marked_document(self) -> None:
        graph_payload = {
            "transport": "microsoft365",
            "microsoft365": {
                "tenantId": "tenant.example.test",
                "clientId": "11111111-2222-3333-4444-555555555555",
                "from": "graph@example.com",
                "displayName": "Graph",
                "mailboxIdentity": "graph@example.com",
            },
            "emailAppearance": {
                "displayName": "Repaired appearance",
                "introduction": "Repaired intro",
                "releaseIntroduction": "",
                "signature": "Repaired signature",
            },
            "smtp": smtp_payload(),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            smtp_path = root / "smtp-settings.json"
            transport_path = root / "email-transport-settings.json"
            smtp_path.write_text(
                '{"schemaVersion": 1, "host": "smtp.corrupt.example",',
                encoding="utf-8",
            )
            notify.save_email_configuration(smtp_path, transport_path, graph_payload)
            repaired = json.loads(smtp_path.read_text(encoding="utf-8"))

        self.assertEqual(repaired["schemaVersion"], notify.SMTP_SETTINGS_SCHEMA_VERSION)
        self.assertEqual(repaired["host"], "smtp.saved.example")
        self.assertEqual(repaired["emailAppearance"], graph_payload["emailAppearance"])

    def test_saving_appearance_persists_no_transport(self) -> None:
        appearance = {
            "displayName": "FortiUpgrade SOC",
            "introduction": "Introduction contrôlée",
            "signature": "Équipe sécurité",
        }
        environment = {
            "FORTIOS_SMTP_HOST": "smtp.environment.example",
            "FORTIOS_SMTP_PORT": "2525",
            "FORTIOS_SMTP_SECURITY": "starttls",
            "FORTIOS_SMTP_USERNAME": "mailer",
            "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
            "FORTIOS_APP_URL": "https://upgrade.example/app/",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smtp-settings.json"
            saved = notify.save_smtp_settings(
                path,
                {"emailAppearance": appearance},
                env=environment,
            )
            persisted = json.loads(path.read_text(encoding="utf-8"))
            loaded = notify.load_smtp_settings(path, env=environment)

        # The legacy three-key appearance is normalised on write: `releaseIntroduction` is added
        # empty (the renderer's automatic text) and the transport still comes from the environment.
        self.assertEqual(
            persisted,
            {"emailAppearance": notify.validate_email_appearance(appearance).to_payload()},
        )
        self.assertEqual(saved, loaded)
        self.assertEqual(saved.host, "smtp.environment.example")
        self.assertEqual(saved.port, 2525)
        self.assertEqual(saved.security, "starttls")
        self.assertEqual(saved.username, "mailer")
        self.assertEqual(saved.sender, "fortiupgrade@example.com")
        self.assertEqual(saved.app_url, "https://upgrade.example/app/")
        self.assertEqual(saved.email_appearance, notify.validate_email_appearance(appearance))
        self.assertFalse((path.parent / notify.SMTP_PASSWORD_FILENAME).exists())

    def test_save_rejects_infrastructure_mutations(self) -> None:
        appearance_only = {"emailAppearance": smtp_payload()["emailAppearance"]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smtp-settings.json"
            for mutation in (
                {**appearance_only, "host": "smtp.attacker.example"},
                {**appearance_only, "port": 25},
                {**appearance_only, "username": "attacker"},
                {**appearance_only, "security": "none"},
                {**appearance_only, "from": "attacker@example.com"},
                {**appearance_only, "appUrl": "https://attacker.example/"},
            ):
                with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    ValueError, "Configuration SMTP"
                ):
                    notify.save_smtp_settings(path, mutation)
            self.assertFalse(path.exists())

    def test_save_rejects_web_password_even_when_appearance_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smtp-settings.json"
            with self.assertRaisesRegex(ValueError, "FORTIOS_SMTP_PASSWORD_FILE"):
                notify.save_smtp_settings(
                    path,
                    {"emailAppearance": smtp_payload()["emailAppearance"]},
                    password="browser-secret",
                )
            self.assertFalse(path.exists())

    def test_delete_web_password_operation_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smtp-settings.json"
            path.write_text(json.dumps({"emailAppearance": smtp_payload()["emailAppearance"]}), encoding="utf-8")
            before = path.read_bytes()

            with self.assertRaisesRegex(ValueError, "FORTIOS_SMTP_PASSWORD_FILE"):
                notify.delete_smtp_password(path)

            self.assertEqual(path.read_bytes(), before)

    def test_none_security_requires_explicit_allow_insecure(self) -> None:
        allowed = notify.load_email_config(
            {
                "FORTIOS_SMTP_HOST": "smtp.example.com",
                "FORTIOS_SMTP_SECURITY": "none",
                "FORTIOS_SMTP_ALLOW_INSECURE": "true",
                "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
            },
            settings=notification_settings(),
        )
        blocked = notify.load_email_config(
            {
                "FORTIOS_SMTP_HOST": "smtp.example.com",
                "FORTIOS_SMTP_SECURITY": "none",
                "FORTIOS_SMTP_ALLOW_INSECURE": "false",
                "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
            },
            settings=notification_settings(),
        )

        self.assertTrue(allowed.is_complete())
        self.assertFalse(blocked.is_complete())

    def test_missing_smtp_environment_is_safe_for_read_and_preview(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = notify.load_smtp_settings(Path(tmp) / "missing.json", env={})
            config = notify.load_email_config(
                {},
                settings=notification_settings(),
                smtp_settings_path=Path(tmp) / "missing.json",
            )

        self.assertEqual(settings.source, "environment")
        self.assertEqual(settings.host, "")
        self.assertEqual(settings.email_appearance, notify.EmailAppearance("FortiUpgrade", "", ""))
        self.assertFalse(config.is_complete())
        self.assertEqual(notify.smtp_public_settings(settings, config)["state"], "incomplete")

    def test_malformed_legacy_appearance_falls_back_without_copying_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smtp-settings.json"
            path.write_text(
                json.dumps(
                    {
                        "host": "smtp.legacy.example",
                        "smtpPassword": "must-not-survive",
                        "emailAppearance": {"displayName": ""},
                    }
                ),
                encoding="utf-8",
            )
            settings = notify.load_smtp_settings(path, env={})
            public = notify.smtp_public_settings(
                settings,
                notify.load_email_config({}, settings=notification_settings(), smtp_settings_path=path),
            )

        self.assertEqual(settings.email_appearance, notify.EmailAppearance("FortiUpgrade", "", ""))
        self.assertNotIn("must-not-survive", json.dumps(public))

    def test_invalid_host_port_and_sender_are_rejected_by_legacy_validator(self) -> None:
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
                body = {"emailAppearance": smtp_payload()["emailAppearance"]}
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

            self.assertFalse(written["smtp"]["passwordConfigured"])
            self.assertEqual(written, loaded)
            self.assertEqual(
                notification_projection["smtp"]["host"], ""
            )
            self.assertEqual(
                written["smtp"]["emailAppearance"], smtp_payload()["emailAppearance"]
            )
            serialized = json.dumps(written)
            self.assertNotIn('"password"', serialized.lower())

    def test_editable_smtp_route_uses_auth_csrf_and_separate_write_only_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            data_dir = root / "data"
            password_path = root / "smtp-secrets" / "password"
            password_path.parent.mkdir(mode=0o700)
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(data_dir),
                "FORTIOS_SMTP_PASSWORD_FILE": str(password_path),
            }
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)
                settings_body = smtp_payload()
                without_csrf = urllib.request.Request(
                    f"{base_url}/api/cert/smtp",
                    data=json.dumps(settings_body).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with self.assertRaises(urllib.error.HTTPError) as settings_rejected:
                    opener.open(without_csrf, timeout=3)
                self.assertEqual(settings_rejected.exception.code, 403)

                def post(path: str, body: dict[str, object], token: str = csrf_token) -> dict[str, object]:
                    request = urllib.request.Request(
                        f"{base_url}{path}",
                        data=json.dumps(body).encode(),
                        method="POST",
                        headers={
                            "Content-Type": "application/json",
                            "Origin": base_url,
                            "X-CSRF-Token": token,
                        },
                    )
                    with opener.open(request, timeout=3) as response:
                        return json.load(response)

                written = post("/api/cert/smtp", settings_body)
                self.assertEqual(written["smtp"]["host"], "smtp.saved.example")
                empty_password_response = post(
                    "/api/cert/smtp/password", {"password": ""}
                )
                self.assertEqual(
                    empty_password_response["smtp"]["passwordConfigured"], False
                )
                self.assertFalse(password_path.exists())
                password_response = post(
                    "/api/cert/smtp/password",
                    {"password": "api-secret-value"},
                )
                with opener.open(f"{base_url}/api/cert/smtp", timeout=3) as response:
                    loaded = json.load(response)

            serialized = json.dumps(password_response) + json.dumps(loaded)
            settings_bytes = (data_dir / "smtp-settings.json").read_bytes()

            self.assertEqual(password_path.read_bytes(), b"api-secret-value")
            self.assertEqual(stat.S_IMODE(password_path.stat().st_mode), 0o600)
            self.assertEqual(loaded, password_response)
            self.assertNotIn("api-secret-value", serialized)
            self.assertNotIn(str(password_path), serialized)
            self.assertNotIn(b"api-secret-value", settings_bytes)
            self.assertFalse((data_dir / "fortios-notify-history.json").exists())

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
                "FORTIOS_SMTP_HOST": "127.0.0.1",
                "FORTIOS_SMTP_PORT": str(smtp.server_address[1]),
                "FORTIOS_SMTP_SECURITY": "none",
                "FORTIOS_SMTP_ALLOW_INSECURE": "true",
                "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
            }
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)
                smtp_body = {"emailAppearance": smtp_payload()["emailAppearance"]}
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

    def test_transport_verdict_is_evaluated_per_transport_and_survives_reload(self) -> None:
        """The status endpoint must expose each transport's own verdict.

        Microsoft 365 completely configured with an empty SMTP block is *complete*; an SMTP
        block that is completely configured is complete on its own too; and a selected transport
        that really misses a prerequisite is reported incomplete.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            data_dir = root / "data"
            data_dir.mkdir()
            secret_path = root / "microsoft365-secrets" / "client-secret"
            secret_path.parent.mkdir(mode=0o700)
            password_path = root / "smtp-secrets" / "password"
            password_path.parent.mkdir(mode=0o700)
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(data_dir),
                "FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE": str(secret_path),
                "FORTIOS_SMTP_PASSWORD_FILE": str(password_path),
                # No SMTP host/from on purpose: the SMTP block starts empty.
                "FORTIOS_SMTP_TIMEOUT": "12",
                "FORTIOS_APP_URL": "https://fortiupgrade.example/app/",
            }
            graph_configuration = {
                "transport": "microsoft365",
                "microsoft365": {
                    "tenantId": "11111111-2222-3333-4444-555555555555",
                    "clientId": "66666666-7777-8888-9999-000000000000",
                    "from": "fortiupgrade@example.com",
                    "displayName": "FortiUpgrade — Alertes de sécurité Fortinet",
                    "mailboxIdentity": "fortiupgrade@example.com",
                },
                "emailAppearance": smtp_payload()["emailAppearance"],
            }
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)

                def post(path: str, body: dict[str, object]) -> dict[str, Any]:
                    request = urllib.request.Request(
                        f"{base_url}{path}",
                        data=json.dumps(body).encode(),
                        method="POST",
                        headers={
                            "Content-Type": "application/json",
                            "Origin": base_url,
                            "X-CSRF-Token": csrf_token,
                        },
                    )
                    with opener.open(request, timeout=3) as response:
                        return json.load(response)

                def reload_smtp() -> dict[str, Any]:
                    with opener.open(f"{base_url}/api/cert/smtp", timeout=3) as response:
                        return json.load(response)["smtp"]

                post("/api/cert/notifications", alerts_payload())
                post("/api/cert/microsoft365/client-secret", {"clientSecret": "graph-secret"})
                written = post("/api/cert/smtp", graph_configuration)["smtp"]
                reloaded = reload_smtp()

                self.assertEqual(written["transport"], "microsoft365")
                self.assertEqual(written["state"], "operational")
                self.assertEqual(written["microsoft365"]["state"], "operational")
                self.assertEqual(written["smtpState"], "incomplete")
                self.assertEqual(reloaded["state"], "operational")
                self.assertEqual(reloaded["microsoft365"]["state"], "operational")
                self.assertEqual(reloaded["smtpState"], "incomplete")

                # SMTP selected and complete, while Microsoft 365 is emptied: SMTP's own verdict
                # is complete and the missing Graph fields only affect Microsoft 365.
                smtp_written = post(
                    "/api/cert/smtp",
                    {
                        "transport": "smtp",
                        "smtp": smtp_payload(),
                        "microsoft365": {
                            "tenantId": "",
                            "clientId": "",
                            "from": "",
                            "displayName": "FortiUpgrade",
                            "mailboxIdentity": "",
                        },
                        "emailAppearance": smtp_payload()["emailAppearance"],
                    },
                )["smtp"]
                post("/api/cert/smtp/password", {"password": "api-secret-value"})
                smtp_reloaded = reload_smtp()

                # A username without a password is not operational yet; the password write
                # completes the SMTP prerequisites.
                self.assertEqual(smtp_written["smtpState"], "incomplete")
                self.assertEqual(smtp_written["microsoft365"]["state"], "incomplete")
                self.assertEqual(smtp_reloaded["state"], "operational")
                self.assertEqual(smtp_reloaded["smtpState"], "operational")
                self.assertEqual(smtp_reloaded["microsoft365"]["state"], "incomplete")
                self.assertTrue(smtp_reloaded["microsoft365"]["clientSecretConfigured"])

                # A selected transport that really misses a prerequisite stays incomplete.
                incomplete = post(
                    "/api/cert/smtp",
                    {
                        **graph_configuration,
                        "microsoft365": {
                            **graph_configuration["microsoft365"],
                            "tenantId": "",
                            "clientId": "",
                        },
                    },
                )["smtp"]

            self.assertEqual(incomplete["microsoft365"]["state"], "incomplete")
            self.assertEqual(incomplete["smtpState"], "operational")
            self.assertNotIn("graph-secret", json.dumps(incomplete))
            self.assertNotIn("api-secret-value", json.dumps(incomplete))
            self.assertNotIn(str(secret_path), json.dumps(incomplete))

    def test_cve_alert_master_switch_persists_on_and_off_across_reloads(self) -> None:
        """The Alerts CVE checkbox value must survive a save + full reload, both ways."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            data_dir = root / "data"
            data_dir.mkdir()
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(data_dir),
            }
            alerts = alerts_payload()
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)

                def save(enabled: bool) -> dict[str, Any]:
                    request = urllib.request.Request(
                        f"{base_url}/api/cert/notifications",
                        data=json.dumps({**alerts, "enabled": enabled}).encode(),
                        method="POST",
                        headers={
                            "Content-Type": "application/json",
                            "Origin": base_url,
                            "X-CSRF-Token": csrf_token,
                        },
                    )
                    with opener.open(request, timeout=3) as response:
                        return json.load(response)["settings"]

                def reload_settings() -> dict[str, Any]:
                    with opener.open(f"{base_url}/api/cert/notifications", timeout=3) as response:
                        return json.load(response)["settings"]

                for target in (False, True, False):
                    saved = save(target)
                    reloaded = reload_settings()
                    on_disk = json.loads(
                        (data_dir / "notification-settings.json").read_text(encoding="utf-8")
                    )
                    with self.subTest(enabled=target):
                        self.assertEqual(saved["enabled"], target)
                        self.assertEqual(reloaded["enabled"], target)
                        self.assertEqual(on_disk["enabled"], target)
                        self.assertEqual(reloaded["recipients"], ["soc@example.com"])
                        self.assertEqual(reloaded["minimumSeverity"], "high")

            self.assertEqual(on_disk["enabled"], False)


if __name__ == "__main__":
    unittest.main()
