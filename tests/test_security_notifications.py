"""High/Critical CVE notification settings, rendering, and admin API coverage."""

from __future__ import annotations

import concurrent.futures
import http.cookiejar
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cert_admin
import fortios_notify as notify
import fortios_watch as fw

from tests.test_cert_web import running_server

PRODUCT_SELECTIONS = {
    "fortigate-fortios": {"product": "fortigate-fortios", "models": []},
    "fortimanager": {"product": "fortimanager", "models": []},
    "fortianalyzer": {"product": "fortianalyzer", "models": []},
    "forticlient-ems": {"product": "forticlient-ems", "models": ["ems"]},
    "forticlient-windows": {"product": "forticlient", "models": ["windows"]},
    "forticlient-macos": {"product": "forticlient", "models": ["macos"]},
    "forticlient-linux": {"product": "forticlient", "models": ["linux"]},
}


def settings_payload(*, enabled: bool = True, selected: set[str] | None = None) -> dict[str, Any]:
    selected = set(PRODUCT_SELECTIONS) if selected is None else selected
    return {
        "enabled": enabled,
        "minimumSeverity": "high",
        "products": {
            "fortigate-fortios": "fortigate-fortios" in selected,
            "fortimanager": "fortimanager" in selected,
            "fortianalyzer": "fortianalyzer" in selected,
            "forticlient-ems": "forticlient-ems" in selected,
            "forticlient": {
                "windows": "forticlient-windows" in selected,
                "macos": "forticlient-macos" in selected,
                "linux": "forticlient-linux" in selected,
            },
        },
        "recipients": ["security@example.com"],
    }


def cve(
    cve_id: str,
    severity: str,
    affected: list[dict[str, Any]],
    *,
    score: float | None = None,
) -> dict[str, Any]:
    return {
        "id": cve_id,
        "advisoryId": "FG-IR-26-001",
        "title": f"Résumé {cve_id}",
        "severity": severity,
        "cvssScore": score,
        "url": "https://fortiguard.fortinet.com/psirt/FG-IR-26-001",
        "affected": affected,
    }


class NotificationSettingsTests(unittest.TestCase):
    def test_missing_settings_are_disabled_and_select_all_supported_products(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = notify.load_notification_settings(Path(tmp) / "missing.json", env={})

        self.assertFalse(settings.enabled)
        self.assertEqual(settings.minimum_severity, "high")
        self.assertTrue(all(settings.selected_product_keys().values()))
        self.assertEqual(settings.recipients, ())

    def test_valid_settings_round_trip_through_an_atomic_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            expected = notify.save_notification_settings(path, settings_payload())
            loaded = notify.load_notification_settings(path, env={})

            self.assertEqual(loaded, expected)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), settings_payload())
            self.assertEqual(list(path.parent.glob("notification-settings.json.tmp-*")), [])

    def test_invalid_persisted_settings_are_archived_and_fall_back_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            path.write_text('{"enabled": "yes", "recipients": ["bad"]}', encoding="utf-8")
            settings = notify.load_notification_settings(path, env={})

            self.assertFalse(settings.enabled)
            self.assertEqual(len(list(path.parent.glob("notification-settings.json.corrupt-*"))), 1)

    def test_corrupt_settings_cannot_reenable_legacy_environment_on_the_next_run(self) -> None:
        legacy_environment = {
            "FORTIOS_EMAIL_ENABLED": "true",
            "FORTIOS_SMTP_TO": "legacy@example.com",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            path.write_text('{"enabled": "invalid"}', encoding="utf-8")
            first = notify.load_notification_settings(path, env=legacy_environment)
            second = notify.load_notification_settings(path, env=legacy_environment)

        self.assertFalse(first.enabled)
        self.assertFalse(second.enabled)

    def test_corrupt_settings_remain_fail_closed_when_default_write_fails(self) -> None:
        legacy_environment = {
            "FORTIOS_EMAIL_ENABLED": "true",
            "FORTIOS_SMTP_TO": "legacy@example.com",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            path.write_text('{"enabled": "invalid"}', encoding="utf-8")
            with patch.object(notify, "write_json", side_effect=OSError("disk full")):
                first = notify.load_notification_settings(path, env=legacy_environment)
                second = notify.load_notification_settings(path, env=legacy_environment)

            self.assertTrue(path.exists())

        self.assertFalse(first.enabled)
        self.assertFalse(second.enabled)

    def test_concurrent_valid_save_is_not_archived_by_corrupt_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            path.write_text('{"enabled": "invalid"}', encoding="utf-8")
            archive_started = threading.Event()
            allow_archive = threading.Event()
            original_archive = notify._archive_corrupt_settings_marker

            def blocking_archive(target: Path, raw_text: str) -> None:
                archive_started.set()
                self.assertTrue(allow_archive.wait(timeout=3))
                original_archive(target, raw_text)

            with patch.object(
                notify,
                "_archive_corrupt_settings_marker",
                side_effect=blocking_archive,
            ), concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                loader = executor.submit(notify.load_notification_settings, path)
                self.assertTrue(archive_started.wait(timeout=3))
                saver = executor.submit(
                    notify.save_notification_settings,
                    path,
                    settings_payload(),
                )
                allow_archive.set()
                loader.result(timeout=3)
                saver.result(timeout=3)

            loaded = notify.load_notification_settings(path, env={})

        self.assertEqual(loaded.to_payload(), settings_payload())

    def test_invalid_recipient_is_rejected(self) -> None:
        payload = settings_payload()
        payload["recipients"] = ["not-an-email"]
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(
            ValueError, "destinataire"
        ):
            notify.save_notification_settings(Path(tmp) / "settings.json", payload)

    def test_smtp_secret_is_rejected_from_application_settings(self) -> None:
        payload = settings_payload()
        payload["smtpPassword"] = "must-not-be-stored"
        with self.assertRaisesRegex(ValueError, "Configuration"):
            notify.validate_notification_settings(payload)

    def test_corrupt_archive_marker_never_copies_unknown_secret_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            path.write_text(
                '{"smtpPassword": "must-not-survive"}',
                encoding="utf-8",
            )
            notify.load_notification_settings(path, env={})
            archived = list(path.parent.glob("notification-settings.json.corrupt-*"))

            self.assertEqual(len(archived), 1)
            marker = archived[0].read_text(encoding="utf-8")

        self.assertNotIn("must-not-survive", marker)
        self.assertNotIn("smtpPassword", marker)

    def test_plaintext_smtp_password_environment_value_is_ignored(self) -> None:
        settings = notify.validate_notification_settings(settings_payload())
        config = notify.load_email_config(
            {
                "FORTIOS_SMTP_HOST": "smtp.example.com",
                "FORTIOS_SMTP_USERNAME": "mailer",
                "FORTIOS_SMTP_PASSWORD": "must-not-be-used",
                "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
            },
            settings=settings,
        )
        self.assertEqual(config.smtp_password, "")
        self.assertFalse(config.is_complete())

    def test_unreadable_password_secret_makes_smtp_configuration_incomplete(self) -> None:
        settings = notify.validate_notification_settings(settings_payload())
        config = notify.load_email_config(
            {
                "FORTIOS_SMTP_HOST": "smtp.example.com",
                "FORTIOS_SMTP_PORT": "587",
                "FORTIOS_SMTP_USERNAME": "mailer",
                "FORTIOS_SMTP_PASSWORD_FILE": "/missing/smtp-password",
                "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
            },
            settings=settings,
        )

        self.assertFalse(config.is_complete())
        self.assertEqual(config.smtp_password, "")
        self.assertTrue(config.smtp_password_error)
        self.assertEqual(notify.smtp_public_status(config)["state"], "incomplete")

    def test_saved_transport_and_legacy_secret_never_override_environment(self) -> None:
        settings = notify.validate_notification_settings(settings_payload())
        saved_payload = {
            "host": "smtp.saved.example",
            "port": 2525,
            "security": "none",
            "allowInsecure": True,
            "username": "saved-user",
            "from": "saved@example.com",
            "appUrl": "https://saved.example/app/",
            "timeout": 7,
            "emailAppearance": {
                "displayName": "Saved title",
                "introduction": "Saved introduction",
                "signature": "Saved signature",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings_path = root / "smtp-settings.json"
            settings_path.write_text(json.dumps(saved_payload), encoding="utf-8")
            legacy_secret = root / "smtp-password"
            legacy_secret.write_text("legacy-secret", encoding="utf-8")
            environment_secret = root / "mounted-smtp-secret"
            environment_secret.write_text("environment-secret", encoding="utf-8")
            environment = {
                "FORTIOS_SMTP_HOST": "smtp.environment.example",
                "FORTIOS_SMTP_PORT": "465",
                "FORTIOS_SMTP_USERNAME": "environment-user",
                "FORTIOS_SMTP_STARTTLS": "false",
                "FORTIOS_SMTP_FROM": "environment@example.com",
                "FORTIOS_SMTP_TIMEOUT": "19",
                "FORTIOS_APP_URL": "https://environment.example/app/",
                "FORTIOS_SMTP_PASSWORD_FILE": str(environment_secret),
            }

            smtp, config = notify.load_smtp_snapshot(
                environment,
                settings=settings,
                smtp_settings_path=settings_path,
            )
            public = notify.smtp_public_settings(smtp, config)

        self.assertEqual(smtp.source, "environment")
        self.assertEqual(config.smtp_host, "smtp.environment.example")
        self.assertEqual(config.smtp_port, 465)
        self.assertEqual(config.smtp_username, "environment-user")
        self.assertEqual(config.smtp_from, "environment@example.com")
        self.assertFalse(config.smtp_starttls)
        self.assertEqual(config.smtp_timeout, 19)
        self.assertEqual(config.app_url, "https://environment.example/app/")
        self.assertEqual(config.smtp_password, "environment-secret")
        self.assertEqual(config.smtp_password_file, str(environment_secret))
        self.assertEqual(
            config.email_appearance,
            notify.EmailAppearance(
                display_name="Saved title",
                introduction="Saved introduction",
                signature="Saved signature",
            ),
        )
        self.assertTrue(public["passwordConfigured"])
        self.assertNotIn("environment-secret", json.dumps(public))
        self.assertNotIn("legacy-secret", json.dumps(public))
        self.assertNotIn(str(environment_secret), json.dumps(public))
        self.assertNotIn(str(legacy_secret), json.dumps(public))

    def test_web_password_is_rejected_and_never_written(self) -> None:
        saved_payload = {
            "emailAppearance": {
                "displayName": "FortiUpgrade",
                "introduction": "",
                "signature": "",
            },
        }
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(
            ValueError, "FORTIOS_SMTP_PASSWORD_FILE"
        ):
            notify.save_smtp_settings(
                Path(tmp) / "smtp-settings.json",
                saved_payload,
                password="browser-secret",
            )

        self.assertFalse((Path(tmp) / "smtp-password").exists())

    def test_saving_appearance_persists_no_transport_or_secret_fields(self) -> None:
        appearance = {
            "displayName": "FortiUpgrade SOC",
            "introduction": "Introduction contrôlée",
            "signature": "Équipe sécurité",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings_path = root / "smtp-settings.json"
            saved = notify.save_smtp_settings(
                settings_path, {"emailAppearance": appearance}
            )
            persisted = json.loads(settings_path.read_text(encoding="utf-8"))

        self.assertEqual(saved.email_appearance, notify.validate_email_appearance(appearance))
        self.assertEqual(persisted, {"emailAppearance": appearance})
        serialized = json.dumps(persisted)
        self.assertNotIn("smtp.saved", serialized)
        self.assertNotIn("password", serialized.lower())
        self.assertFalse((root / "smtp-password").exists())


class HighCriticalDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.all_settings = notify.validate_notification_settings(settings_payload())
        self.fortios = PRODUCT_SELECTIONS["fortigate-fortios"]

    def test_new_critical_fortios_generates_one_event(self) -> None:
        events = notify.derive_new_cve_events(
            [cve("CVE-2026-00001", "critical", [self.fortios], score=9.8)],
            self.all_settings,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "critical")

    def test_new_high_fortios_generates_one_event(self) -> None:
        events = notify.derive_new_cve_events(
            [cve("CVE-2026-00002", "high", [self.fortios], score=8.1)],
            self.all_settings,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "high")

    def test_new_medium_generates_no_event(self) -> None:
        self.assertEqual(
            notify.derive_new_cve_events(
                [cve("CVE-2026-00003", "medium", [self.fortios])],
                self.all_settings,
            ),
            [],
        )

    def test_medium_to_high_generates_one_event(self) -> None:
        before = cve("CVE-2026-00004", "medium", [self.fortios])
        after = cve("CVE-2026-00004", "high", [self.fortios], score=7.5)
        events = notify.derive_cve_modification_events(
            {before["id"]: before}, {after["id"]: after}, self.all_settings
        )
        self.assertEqual(len(events), 1)
        self.assertIn("medium-to-high", events[0].dedup_key)

    def test_high_to_critical_generates_one_event(self) -> None:
        before = cve("CVE-2026-00005", "high", [self.fortios], score=8.0)
        after = cve("CVE-2026-00005", "critical", [self.fortios], score=9.5)
        events = notify.derive_cve_modification_events(
            {before["id"]: before}, {after["id"]: after}, self.all_settings
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "critical")

    def test_unchanged_high_generates_no_event(self) -> None:
        before = cve("CVE-2026-00006", "high", [self.fortios], score=8.0)
        after = {**before, "updatedAt": "2026-08-31"}
        self.assertEqual(
            notify.derive_cve_modification_events(
                {before["id"]: before}, {after["id"]: after}, self.all_settings
            ),
            [],
        )

    def test_each_supported_product_can_be_selected_individually(self) -> None:
        for product_key, affected in PRODUCT_SELECTIONS.items():
            with self.subTest(product=product_key):
                settings = notify.validate_notification_settings(
                    settings_payload(selected={product_key})
                )
                events = notify.derive_new_cve_events(
                    [cve("CVE-2026-01000", "high", [affected])], settings
                )
                self.assertEqual(len(events), 1)

    def test_unselected_product_generates_no_event(self) -> None:
        settings = notify.validate_notification_settings(
            settings_payload(selected={"fortimanager"})
        )
        self.assertEqual(
            notify.derive_new_cve_events(
                [cve("CVE-2026-00007", "critical", [self.fortios])], settings
            ),
            [],
        )

    def test_one_cve_affecting_multiple_selected_products_stays_one_event(self) -> None:
        affected = [
            PRODUCT_SELECTIONS["fortigate-fortios"],
            PRODUCT_SELECTIONS["fortimanager"],
            PRODUCT_SELECTIONS["forticlient-windows"],
        ]
        events = notify.derive_new_cve_events(
            [cve("CVE-2026-00008", "critical", affected, score=9.8)],
            self.all_settings,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0].details["productLabels"],
            ["FortiGate / FortiOS", "FortiManager", "FortiClient Windows"],
        )


class SecurityEmailRenderingTests(unittest.TestCase):
    def test_multiple_cves_are_grouped_in_one_multipart_email(self) -> None:
        settings = notify.validate_notification_settings(settings_payload())
        events = notify.derive_new_cve_events(
            [
                cve(
                    "CVE-2026-10001",
                    "critical",
                    [PRODUCT_SELECTIONS["fortigate-fortios"]],
                    score=9.8,
                ),
                cve(
                    "CVE-2026-10002",
                    "high",
                    [PRODUCT_SELECTIONS["fortimanager"]],
                    score=8.1,
                ),
            ],
            settings,
        )
        composed = notify.compose_email(
            events,
            app_url="https://upgrade.example/app/",
            run_timestamp="2026-08-31T13:00:00Z",
        )
        self.assertIsNotNone(composed)
        subject, text_body, html_body = composed
        self.assertEqual(
            subject,
            "[FortiUpgrade][CRITICAL] 2 nouvelles vulnérabilités Fortinet",
        )
        self.assertIn("Critical : 1", text_body)
        self.assertIn("High     : 1", text_body)
        self.assertIn("CVE-2026-10001", text_body)
        self.assertIn("FortiManager", text_body)
        self.assertIn("CVE-2026-10002", html_body)
        self.assertIn("Fortinet PSIRT", html_body)

    def test_multiple_cves_are_sent_as_one_smtp_message(self) -> None:
        settings = notify.validate_notification_settings(settings_payload())
        events = notify.derive_new_cve_events(
            [
                cve("CVE-2026-20001", "critical", [PRODUCT_SELECTIONS["fortigate-fortios"]]),
                cve("CVE-2026-20002", "high", [PRODUCT_SELECTIONS["fortimanager"]]),
            ],
            settings,
        )
        subject, text_body, html_body = notify.compose_email(
            events, app_url="https://upgrade.example/app/", run_timestamp="2026-08-31T13:00:00Z"
        )
        with smtp_server() as smtp_port:
            config = notify.EmailConfig(
                enabled=True,
                smtp_host="127.0.0.1",
                smtp_port=smtp_port,
                smtp_username="",
                smtp_password="",
                smtp_from="fortiupgrade@example.com",
                smtp_to=("security@example.com",),
                smtp_starttls=False,
                smtp_timeout=3,
                app_url="https://upgrade.example/app/",
                smtp_allow_insecure=True,
            )
            self.assertTrue(notify.send_email(config, subject, text_body, html_body))
        self.assertEqual(len(_SmtpHandler.messages), 1)


class WatchSettingsIntegrationTests(unittest.TestCase):
    def test_persisted_settings_drive_the_real_collection_notification_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path = root / "state.json"
            health_path = root / "health.json"
            history_path = root / "notify-history.json"
            settings_path = root / "notification-settings.json"
            fw.write_json(base_path, fw.normalize_state({}))
            notify.save_notification_settings(
                settings_path,
                settings_payload(selected={"fortimanager"}),
            )
            fake_cve = cve(
                "CVE-2026-30001",
                "high",
                [PRODUCT_SELECTIONS["fortimanager"]],
                score=8.1,
            )
            client = MagicMock()
            client.__enter__ = MagicMock(return_value=client)
            client.__exit__ = MagicMock(return_value=False)
            environment = {
                "FORTIOS_SMTP_HOST": "smtp.example.com",
                "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
            }
            with (
                patch.dict(os.environ, environment, clear=True),
                patch.object(
                    fw,
                    "collect_cve_catalog",
                    return_value=({"FG-IR-26-300": [fake_cve]}, []),
                ),
                patch.object(fw, "fetch_psirt_versions", return_value=set()),
                patch("smtplib.SMTP", return_value=client),
            ):
                exit_code = fw.main(
                    [
                        "--cve-catalog",
                        "--base",
                        str(base_path),
                        "--output",
                        str(base_path),
                        "--report",
                        str(root / "report.md"),
                        "--health-output",
                        str(health_path),
                        "--notify-history-output",
                        str(history_path),
                        "--notification-settings-output",
                        str(settings_path),
                        "--official-paths-csv",
                        str(root / "no-official-paths.csv"),
                        "--advisories-csv",
                        str(root / "no-advisories.csv"),
                        "--upgrade-exports",
                        str(root / "no-upgrade-exports"),
                    ]
                )

            self.assertEqual(exit_code, 0)
            client.send_message.assert_called_once()
            message = client.send_message.call_args.args[0]
            self.assertIn("[FortiUpgrade][HIGH]", message["Subject"])
            self.assertIn(
                "CVE-2026-30001",
                message.get_body(preferencelist=("plain",)).get_content(),
            )

    def test_reenabling_does_not_send_cves_collected_while_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path = root / "state.json"
            health_path = root / "health.json"
            history_path = root / "notify-history.json"
            settings_path = root / "notification-settings.json"
            historical_cve = cve(
                "CVE-2026-30002",
                "critical",
                [PRODUCT_SELECTIONS["fortimanager"]],
                score=9.8,
            )
            fw.write_json(
                base_path,
                fw.normalize_state({"cves": [historical_cve]}),
            )
            notify.ensure_checkpoint(
                history_path,
                {"versionsByProduct": {}, "cvesById": {}, "health": {}},
            )
            disabled_payload = settings_payload(
                enabled=False, selected={"fortimanager"}
            )
            notify.save_notification_settings(settings_path, disabled_payload)
            arguments = [
                "--skip-network",
                "--base",
                str(base_path),
                "--output",
                str(base_path),
                "--report",
                str(root / "report.md"),
                "--health-output",
                str(health_path),
                "--notify-history-output",
                str(history_path),
                "--notification-settings-output",
                str(settings_path),
                "--official-paths-csv",
                str(root / "no-official-paths.csv"),
                "--advisories-csv",
                str(root / "no-advisories.csv"),
                "--upgrade-exports",
                str(root / "no-upgrade-exports"),
            ]

            self.assertEqual(fw.main(arguments), 0)
            state_after_disabled_run = notify.load_notify_state(history_path)
            self.assertIn(
                historical_cve["id"],
                state_after_disabled_run["checkpoint"]["cvesById"],
            )

            enabled_payload = {**disabled_payload, "enabled": True}
            notify.save_notification_settings(settings_path, enabled_payload)
            client = MagicMock()
            client.__enter__ = MagicMock(return_value=client)
            client.__exit__ = MagicMock(return_value=False)
            with (
                patch.dict(
                    os.environ,
                    {
                        "FORTIOS_SMTP_HOST": "smtp.example.com",
                        "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
                    },
                    clear=True,
                ),
                patch("smtplib.SMTP", return_value=client),
            ):
                self.assertEqual(fw.main(arguments), 0)

            client.send_message.assert_not_called()


class DisabledNotificationStateAtomicityTests(unittest.TestCase):
    def test_eol_state_and_checkpoint_are_persisted_in_one_atomic_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify-history.json"
            notify.write_json(path, notify._empty_notify_state())
            checkpoint = {
                "versionsByProduct": {"fortigate-fortios": ["7.6.1"]},
                "cvesById": {"CVE-2026-40001": {"id": "CVE-2026-40001"}},
                "health": {},
            }
            original_write = notify.write_json
            with patch.object(notify, "write_json", wraps=original_write) as writer:
                notify.commit_disabled_notification_state(
                    path,
                    {"7.6": True},
                    checkpoint,
                )

            writer.assert_called_once()
            persisted = notify.load_notify_state(path)

        self.assertEqual(persisted["eolState"], {"7.6": True})
        self.assertEqual(persisted["checkpoint"], checkpoint)

    def test_failed_atomic_write_leaves_both_old_values_intact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify-history.json"
            initial = notify._empty_notify_state()
            initial["eolState"] = {"7.6": False}
            initial["checkpoint"] = {
                "versionsByProduct": {},
                "cvesById": {},
                "health": {},
            }
            notify.write_json(path, initial)
            before = path.read_bytes()
            with (
                patch.object(notify, "write_json", side_effect=OSError("disk full")),
                self.assertRaises(OSError),
            ):
                notify.commit_disabled_notification_state(
                    path,
                    {"7.6": True},
                    {
                        "versionsByProduct": {"fortigate-fortios": ["7.6.1"]},
                        "cvesById": {},
                        "health": {},
                    },
                )

            after = path.read_bytes()

        self.assertEqual(after, before)


class _SmtpHandler(socketserver.StreamRequestHandler):
    messages: ClassVar[list[bytes]] = []

    def handle(self) -> None:
        self.wfile.write(b"220 localhost test SMTP\r\n")
        data_mode = False
        message = bytearray()
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if data_mode:
                if line == b".\r\n":
                    type(self).messages.append(bytes(message))
                    self.wfile.write(b"250 queued\r\n")
                    data_mode = False
                else:
                    message.extend(line)
                continue
            command = line.decode("ascii", errors="ignore").upper()
            if command.startswith(("EHLO", "HELO")):
                self.wfile.write(b"250-localhost\r\n250 SIZE 10485760\r\n")
            elif command.startswith(("MAIL FROM", "RCPT TO")):
                self.wfile.write(b"250 ok\r\n")
            elif command.startswith("DATA"):
                data_mode = True
                message.clear()
                self.wfile.write(b"354 end with dot\r\n")
            elif command.startswith("QUIT"):
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


@contextmanager
def smtp_server() -> Iterator[int]:
    _SmtpHandler.messages = []
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _SmtpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def login(opener: urllib.request.OpenerDirector, base_url: str) -> str:
    request = urllib.request.Request(
        f"{base_url}/api/cert/login",
        data=json.dumps(
            {"username": "valentin", "password": "mot-de-passe-solide"}
        ).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Origin": base_url},
    )
    with opener.open(request, timeout=3) as response:
        return str(json.load(response)["csrfToken"])


class NotificationAdminWebTests(unittest.TestCase):
    def test_admin_page_exposes_certificate_and_notification_sections(self) -> None:
        with running_server({"FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1"}) as base_url, urllib.request.urlopen(
            f"{base_url}/cert/", timeout=3
        ) as response:
            body = response.read().decode("utf-8")
        self.assertIn("Administration", body)
        self.assertIn("Certificats", body)
        self.assertIn("Notifications de sécurité", body)
        self.assertIn("Envoyer un email de test", body)

    def test_settings_api_requires_the_existing_admin_session(self) -> None:
        with running_server({"FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1"}) as base_url, self.assertRaises(
            urllib.error.HTTPError
        ) as raised:
            urllib.request.urlopen(f"{base_url}/api/cert/notifications", timeout=3)
        self.assertEqual(raised.exception.code, 401)

    def test_admin_can_read_update_and_test_without_any_secret_in_responses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, smtp_server() as smtp_port:
            root = Path(tmp)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(root / "data"),
                "FORTIOS_SMTP_HOST": "127.0.0.1",
                "FORTIOS_SMTP_PORT": str(smtp_port),
                "FORTIOS_SMTP_STARTTLS": "false",
                "FORTIOS_SMTP_FROM": "fortiupgrade@example.com",
            }
            with running_server(environment) as base_url:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
                )
                csrf_token = login(opener, base_url)

                save_without_csrf = urllib.request.Request(
                    f"{base_url}/api/cert/notifications",
                    data=json.dumps(settings_payload()).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with self.assertRaises(urllib.error.HTTPError) as csrf_error:
                    opener.open(save_without_csrf, timeout=3)
                self.assertEqual(csrf_error.exception.code, 403)

                save = urllib.request.Request(
                    f"{base_url}/api/cert/notifications",
                    data=json.dumps(settings_payload()).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    },
                )
                with opener.open(save, timeout=3) as response:
                    saved = json.load(response)

                with opener.open(
                    f"{base_url}/api/cert/notifications", timeout=3
                ) as response:
                    current = json.load(response)

                test_request = urllib.request.Request(
                    f"{base_url}/api/cert/notifications/test",
                    data=json.dumps(
                        {"recipient": "security@example.com"}
                    ).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    },
                )
                with opener.open(test_request, timeout=5) as response:
                    test_result = json.load(response)

            response_text = json.dumps([saved, current, test_result]).lower()
            self.assertNotIn("password", response_text)
            self.assertNotIn("username", response_text)
            self.assertNotIn("secret", response_text)
            self.assertEqual(current["settings"], settings_payload())
            self.assertEqual(current["smtp"]["state"], "operational")
            self.assertTrue(test_result["sent"])
            self.assertEqual(test_result["message"], "Email de test envoyé.")
            self.assertIn("Message accepté par le serveur SMTP", test_result["checks"])
            self.assertEqual(
                test_result["summary"]["recipient"], "security@example.com"
            )
            self.assertEqual(len(_SmtpHandler.messages), 1)


if __name__ == "__main__":
    unittest.main()
