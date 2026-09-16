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


def settings_payload(
    *,
    enabled: bool = True,
    selected: set[str] | None = None,
    release_notifications: bool | None = None,
    release_recipients_shared: bool = True,
    release_recipients: list[str] | None = None,
    minimum_severity: str = "high",
) -> dict[str, Any]:
    """The canonical saved payload, including the explicit release switches.

    ``release_notifications`` defaults to mirroring ``enabled``, which is what a legacy file
    without the key resolves to; pass it explicitly to exercise the asymmetric combinations.
    ``release_recipients`` only matters when ``release_recipients_shared`` is false.
    ``minimum_severity`` defaults to the historical, still-default `high` threshold.
    """
    selected = set(PRODUCT_SELECTIONS) if selected is None else selected
    if release_notifications is None:
        release_notifications = enabled
    return {
        "enabled": enabled,
        "releaseNotificationsEnabled": release_notifications,
        "minimumSeverity": minimum_severity,
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
        "releaseRecipientsShared": release_recipients_shared,
        "releaseRecipients": list(release_recipients or []),
    }


def legacy_settings_payload(*, enabled: bool = True) -> dict[str, Any]:
    """The four-key shape persisted before any release-notification key existed."""
    payload = settings_payload(enabled=enabled)
    for key in ("releaseNotificationsEnabled", "releaseRecipientsShared", "releaseRecipients"):
        payload.pop(key)
    return payload


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

    def test_legacy_four_key_settings_inherit_release_notifications_and_keep_recipients(
        self,
    ) -> None:
        """A file saved before release notifications existed must load unchanged.

        The release switch inherits `enabled`, no corrupt-configuration fallback is triggered,
        the existing recipients survive, and loading never rewrites the file.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            raw = json.dumps(legacy_settings_payload())
            path.write_text(raw, encoding="utf-8")

            settings = notify.load_notification_settings(path, env={})

            self.assertTrue(settings.enabled)
            self.assertTrue(settings.release_notifications_enabled)
            self.assertEqual(settings.recipients, ("security@example.com",))
            self.assertEqual(path.read_text(encoding="utf-8"), raw)
            self.assertEqual(list(path.parent.glob("notification-settings.json.corrupt-*")), [])
            # The next save makes the switch explicit without changing any decision.
            self.assertTrue(settings.to_payload()["releaseNotificationsEnabled"])

    def test_legacy_disabled_four_key_settings_inherit_a_disabled_release_switch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            path.write_text(json.dumps(legacy_settings_payload(enabled=False)), encoding="utf-8")

            settings = notify.load_notification_settings(path, env={})

            self.assertFalse(settings.enabled)
            self.assertFalse(settings.release_notifications_enabled)

    def test_explicit_release_only_configuration_round_trips(self) -> None:
        """The asymmetric combination the UI allows: CVE off, releases on."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            payload = settings_payload(enabled=False, release_notifications=True)

            notify.save_notification_settings(path, payload)
            settings = notify.load_notification_settings(path, env={})

            self.assertFalse(settings.enabled)
            self.assertTrue(settings.release_notifications_enabled)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), payload)

    def test_unknown_notification_setting_keys_are_still_rejected(self) -> None:
        for key in ("releaseNotifications", "releaseNotificationEnabled", "releaseEnabled"):
            payload = settings_payload()
            payload[key] = True
            with self.assertRaises(ValueError):
                notify.validate_notification_settings(payload)

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
        # A legacy three-key save is normalised on write: the release introduction is added empty,
        # which means "use the renderer's automatic text", and nothing else is invented.
        self.assertEqual(
            persisted,
            {"emailAppearance": notify.validate_email_appearance(appearance).to_payload()},
        )
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
            "[FortiUpgrade] 2 nouvelles vulnérabilités — 1 Critical / 1 High",
        )
        self.assertIn("Critical : 1", text_body)
        self.assertIn("High     : 1", text_body)
        self.assertIn("CVE-2026-10001", text_body)
        self.assertIn("FortiManager", text_body)
        self.assertIn("CVE-2026-10002", html_body)
        self.assertIn("Voir l’advisory Fortinet →", html_body)

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
            self.assertIn("[FortiUpgrade] 1 nouvelle vulnérabilité — 1 High", message["Subject"])
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
            f"{base_url}/admin/", timeout=3
        ) as response:
            body = response.read().decode("utf-8")
        self.assertIn("Administration", body)
        self.assertIn("Certificats", body)
        self.assertIn("Notifications de sécurité", body)
        self.assertIn("Envoyer un email de test", body)
        # The two independent category switches and the release preview scenario are exposed.
        self.assertIn("Alertes CVE", body)
        self.assertIn("Alertes nouvelles versions", body)
        self.assertIn("Produits surveillés pour les CVE", body)
        self.assertIn('id="release-notifications-enabled"', body)
        self.assertIn('data-preview-scenario="release"', body)
        self.assertIn("Recevoir une notification lorsqu’une nouvelle version Fortinet est détectée.", body)

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
            self.assertNotIn('"clientsecret":', response_text)
            self.assertEqual(current["settings"], settings_payload())
            self.assertEqual(current["smtp"]["state"], "operational")
            self.assertTrue(test_result["sent"])
            self.assertEqual(test_result["message"], "Email de test envoyé.")
            self.assertIn("Message accepté par le serveur SMTP", test_result["checks"])
            self.assertEqual(
                test_result["summary"]["recipient"], "security@example.com"
            )
            self.assertEqual(len(_SmtpHandler.messages), 1)


class SeverityThresholdTests(unittest.TestCase):
    """`minimumSeverity` is a real, persisted notification threshold.

    The selectable levels are the ones Fortinet genuinely publishes, derived from the CVRF CVSS
    base score by fortios_watch.cvss_severity(); `unknown` is this application's own fallback for
    an unscored CVE and is deliberately not selectable.
    """

    # Most severe first, the order the administration select offers.
    PUBLISHED = ("critical", "high", "medium", "low")
    # One CVE per published level, in decreasing severity, so the retained set is always a prefix.
    LEVELS = (("critical", 9.6), ("high", 8.0), ("medium", 5.0), ("low", 3.0))
    REACHED: ClassVar[dict[str, tuple[str, ...]]] = {
        "critical": ("critical",),
        "high": ("critical", "high"),
        "medium": ("critical", "high", "medium"),
        "low": ("critical", "high", "medium", "low"),
    }

    def setUp(self) -> None:
        self.fortios = PRODUCT_SELECTIONS["fortigate-fortios"]

    def settings(self, threshold: str) -> Any:
        return notify.validate_notification_settings(
            settings_payload(minimum_severity=threshold)
        )

    def catalog(self) -> list[dict[str, Any]]:
        return [
            cve(f"CVE-2026-1100{index}", severity, [self.fortios], score=score)
            for index, (severity, score) in enumerate(self.LEVELS)
        ]

    def test_the_selectable_levels_are_the_published_ones_most_severe_first(self) -> None:
        self.assertEqual(notify.NOTIFICATION_MINIMUM_SEVERITIES, self.PUBLISHED)
        self.assertEqual(notify.DEFAULT_MINIMUM_SEVERITY, "high")
        # Ordering is a real hierarchy, not string comparison: each level reaches its own
        # threshold and nothing more severe than it.
        for index, level in enumerate(self.PUBLISHED):
            with self.subTest(level=level):
                self.assertTrue(notify.severity_reaches(level, level))
                for stricter in self.PUBLISHED[:index]:
                    self.assertFalse(notify.severity_reaches(level, stricter))

    def test_the_threshold_is_a_strict_minimum_for_new_cves(self) -> None:
        for threshold, reached in self.REACHED.items():
            with self.subTest(threshold=threshold):
                events = notify.derive_new_cve_events(
                    self.catalog(), self.settings(threshold)
                )
                self.assertEqual(tuple(event.severity for event in events), reached)

    def test_an_unscored_cve_never_reaches_even_the_lowest_threshold(self) -> None:
        events = notify.derive_new_cve_events(
            [cve("CVE-2026-12000", "unknown", [self.fortios])], self.settings("low")
        )
        self.assertEqual(events, [])

    def test_an_unknown_threshold_is_refused_rather_than_falling_back_to_high(self) -> None:
        # `Any` on purpose: a payload arriving from a client is not typed either.
        invalid_values: list[Any] = [
            "High",
            "HIGH",
            "Medium",
            "informational",
            "unknown",
            "",
            " high",
            4,
            True,
            None,
        ]
        for invalid in invalid_values:
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                notify.validate_notification_settings(
                    settings_payload(minimum_severity=invalid)
                )

    def test_every_threshold_round_trips_through_the_persisted_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            for threshold in self.PUBLISHED:
                with self.subTest(threshold=threshold):
                    notify.save_notification_settings(
                        path, settings_payload(minimum_severity=threshold)
                    )
                    self.assertEqual(
                        notify.load_notification_settings(path, env={}).minimum_severity,
                        threshold,
                    )

    def test_an_existing_high_configuration_keeps_its_behaviour_and_is_not_rewritten(
        self,
    ) -> None:
        """Legacy migration: an existing `minimumSeverity: high` file stays a High/Critical one."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notification-settings.json"
            legacy = legacy_settings_payload()
            path.write_text(json.dumps(legacy), encoding="utf-8")
            settings = notify.load_notification_settings(path, env={})
            stored = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(settings.minimum_severity, "high")
        self.assertTrue(settings.enabled)
        self.assertEqual(settings.recipients, ("security@example.com",))
        self.assertEqual(stored, legacy)  # a read never rewrites the document
        events = notify.derive_new_cve_events(self.catalog(), settings)
        self.assertEqual(tuple(event.severity for event in events), ("critical", "high"))


def _newly_added_cves(
    checkpoint_cves_by_id: dict[str, Any], catalog: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The collector's own definition of "new" (fortios_watch's notification block).

    A CVE is newly added when its id is absent from the persisted checkpoint. The notification
    threshold plays no part in this diff, which is exactly why changing it can never turn the
    already-collected backlog into new events.
    """
    return [item for item in catalog if item["id"] not in checkpoint_cves_by_id]


class SeverityThresholdCheckpointTests(unittest.TestCase):
    """Lowering the threshold filters FUTURE events; it never mails the collected backlog."""

    def setUp(self) -> None:
        self.fortios = PRODUCT_SELECTIONS["fortigate-fortios"]
        self.catalog = [
            cve("CVE-2026-20001", "critical", [self.fortios], score=9.6),
            cve("CVE-2026-20002", "high", [self.fortios], score=8.2),
            cve("CVE-2026-20003", "medium", [self.fortios], score=5.1),
            cve("CVE-2026-20004", "low", [self.fortios], score=3.4),
        ]

    def settings(self, threshold: str) -> Any:
        return notify.validate_notification_settings(
            settings_payload(minimum_severity=threshold)
        )

    def test_lowering_the_threshold_does_not_replay_the_collected_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fortios-notify-history.json"
            # First collection under the historical `high` threshold: only Critical/High notify...
            events = notify.derive_new_cve_events(
                _newly_added_cves({}, self.catalog), self.settings("high")
            )
            self.assertEqual(tuple(event.severity for event in events), ("critical", "high"))
            # ...but the checkpoint records EVERY collected CVE, including the ones the threshold
            # filtered out. That is the invariant which makes the change below silent.
            notify.commit_events_with_checkpoint(
                path,
                {
                    "versionsByProduct": {},
                    "cvesById": {item["id"]: item for item in self.catalog},
                    "health": {},
                },
                events,
                claimant="run-1",
            )
            checkpoint = notify.load_notify_state(path)["checkpoint"]["cvesById"]

        self.assertEqual(set(checkpoint), {item["id"] for item in self.catalog})
        catalog_by_id = {item["id"]: item for item in self.catalog}
        # Second collection, High -> Low on the very same catalog: nothing is new, no severity
        # change was observed, so the operator receives no backlog email.
        self.assertEqual(_newly_added_cves(checkpoint, self.catalog), [])
        self.assertEqual(
            notify.derive_new_cve_events(
                _newly_added_cves(checkpoint, self.catalog), self.settings("low")
            ),
            [],
        )
        self.assertEqual(
            notify.derive_cve_modification_events(
                checkpoint, catalog_by_id, self.settings("low")
            ),
            [],
        )

    def test_a_cve_discovered_after_the_change_follows_the_new_threshold(self) -> None:
        fresh = cve("CVE-2026-20009", "low", [self.fortios], score=3.9)
        self.assertEqual(
            [event.severity for event in notify.derive_new_cve_events([fresh], self.settings("low"))],
            ["low"],
        )
        self.assertEqual(notify.derive_new_cve_events([fresh], self.settings("high")), [])

    def test_a_severity_escalation_notifies_only_when_it_reaches_the_threshold(self) -> None:
        cases = (
            ("high", "low", "medium", 0),
            ("medium", "low", "medium", 1),
            ("high", "medium", "high", 1),
            ("high", "high", "critical", 1),
            ("critical", "high", "critical", 1),
            ("critical", "medium", "high", 0),
            ("low", "unknown", "low", 1),
        )
        for threshold, before_severity, after_severity, expected in cases:
            with self.subTest(threshold=threshold, change=f"{before_severity}->{after_severity}"):
                before = cve("CVE-2026-30001", before_severity, [self.fortios], score=1.0)
                after = cve("CVE-2026-30001", after_severity, [self.fortios], score=9.0)
                events = notify.derive_cve_modification_events(
                    {before["id"]: before}, {after["id"]: after}, self.settings(threshold)
                )
                self.assertEqual(len(events), expected)

    def test_a_severity_downgrade_is_neither_an_escalation_nor_a_new_cve(self) -> None:
        before = cve("CVE-2026-30002", "critical", [self.fortios], score=9.5)
        after = cve("CVE-2026-30002", "high", [self.fortios], score=8.0)
        for threshold in notify.NOTIFICATION_MINIMUM_SEVERITIES:
            with self.subTest(threshold=threshold):
                self.assertEqual(
                    notify.derive_cve_modification_events(
                        {before["id"]: before}, {after["id"]: after}, self.settings(threshold)
                    ),
                    [],
                )
        # And the collector's diff cannot report it as new either: the id is already checkpointed.
        self.assertEqual(_newly_added_cves({before["id"]: before}, [after]), [])

    def test_a_queued_cve_below_high_is_a_valid_outbox_entry(self) -> None:
        """A low threshold queues Medium/Low events: those entries must survive a state reload."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fortios-notify-history.json"
            events = notify.derive_new_cve_events(
                [
                    cve("CVE-2026-30003", "medium", [self.fortios], score=5.2),
                    cve("CVE-2026-30004", "low", [self.fortios], score=3.3),
                ],
                self.settings("low"),
            )
            notify.commit_events_with_checkpoint(
                path,
                {"versionsByProduct": {}, "cvesById": {}, "health": {}},
                events,
                claimant="run-1",
            )
            outbox = notify.load_notify_state(path)["outbox"]

        self.assertEqual(
            [(entry["severity"], entry["dedupKey"]) for entry in outbox],
            [
                ("medium", "new-cve|psirt|CVE-2026-30003|medium"),
                ("low", "new-cve|psirt|CVE-2026-30004|low"),
            ],
        )


class SeverityFilteredEmailTests(unittest.TestCase):
    """The threshold filters derivation, so the email describes only the retained batch."""

    def setUp(self) -> None:
        self.fortios = PRODUCT_SELECTIONS["fortigate-fortios"]
        self.fortimanager = PRODUCT_SELECTIONS["fortimanager"]
        self.fortianalyzer = PRODUCT_SELECTIONS["fortianalyzer"]

    def catalog(self) -> list[dict[str, Any]]:
        return [
            cve("CVE-2026-40001", "critical", [self.fortios], score=9.7),
            cve("CVE-2026-40002", "high", [self.fortimanager], score=7.8),
            cve("CVE-2026-40003", "medium", [self.fortios], score=5.4),
            cve("CVE-2026-40004", "low", [self.fortianalyzer], score=3.2),
        ]

    def compose(self, threshold: str) -> tuple[Any, str, str, str]:
        settings = notify.validate_notification_settings(
            settings_payload(minimum_severity=threshold)
        )
        events = notify.derive_new_cve_events(self.catalog(), settings)
        composed = notify.compose_email(
            events,
            app_url="https://example.test/",
            run_timestamp="2026-09-16T05:00:00Z",
        )
        self.assertIsNotNone(composed)
        subject, text, html = composed
        return events, subject, text, html

    def test_the_default_high_threshold_still_produces_the_historical_email(self) -> None:
        events, subject, text, _html = self.compose("high")
        self.assertEqual(tuple(event.severity for event in events), ("critical", "high"))
        self.assertEqual(
            [line for line in text.splitlines() if line.startswith("Critical :")],
            ["Critical : 1"],
        )
        # No Medium/Low counter line exists for a batch that contains neither level.
        self.assertNotIn("Medium", text)
        self.assertNotIn("Low  ", text)
        self.assertEqual(
            subject, "[FortiUpgrade] 2 nouvelles vulnérabilités — 1 Critical / 1 High"
        )

    def test_counters_products_and_labels_describe_only_the_retained_cves(self) -> None:
        events, subject, text, html = self.compose("medium")
        self.assertEqual(
            tuple(event.severity for event in events), ("critical", "high", "medium")
        )
        # The CVE below the threshold contributes nothing at all: no body section, no counter,
        # no product row.
        self.assertNotIn("CVE-2026-40004", text)
        self.assertNotIn("CVE-2026-40004", html)
        self.assertNotIn("FortiAnalyzer", text)
        self.assertNotIn("FortiAnalyzer", html)
        self.assertEqual(
            [
                line
                for line in text.splitlines()
                if line.startswith(("Critical ", "High ", "Medium ", "Low ", "Total "))
            ],
            ["Critical : 1", "High     : 1", "Medium   : 1", "Total    : 3"],
        )
        self.assertIn("FortiGate / FortiOS : 2 CVE", text)
        self.assertIn("FortiManager : 1 CVE", text)
        # Each retained level is reported under its own name, in the text and in the HTML badge.
        self.assertIn("MEDIUM — CVE-2026-40003", text)
        for badge in ("CRITICAL", "HIGH", "MEDIUM"):
            self.assertIn(f">{badge}</td>", html)
        self.assertNotIn(">LOW</td>", html)
        self.assertEqual(
            subject, "[FortiUpgrade] 3 nouvelles vulnérabilités — 1 Critical / 1 High / 1 Medium"
        )


class SeverityThresholdAdminApiTests(unittest.TestCase):
    """The threshold is validated, persisted, and never silently replaced by the API."""

    def test_the_threshold_is_validated_persisted_and_never_silently_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            data_dir = root / "data"
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(data_dir),
            }
            with running_server(environment) as base_url:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
                )
                csrf_token = login(opener, base_url)

                def save(payload: dict[str, Any]):
                    request = urllib.request.Request(
                        f"{base_url}/api/cert/notifications",
                        data=json.dumps(payload).encode(),
                        method="POST",
                        headers={
                            "Content-Type": "application/json",
                            "Origin": base_url,
                            "X-CSRF-Token": csrf_token,
                        },
                    )
                    return opener.open(request, timeout=3)

                with save(settings_payload(minimum_severity="medium")) as response:
                    saved = json.load(response)
                self.assertEqual(saved["settings"]["minimumSeverity"], "medium")

                with self.assertRaises(urllib.error.HTTPError) as raised:
                    save(settings_payload(minimum_severity="urgent"))
                self.assertEqual(raised.exception.code, 400)
                self.assertIn(
                    "critical, high, medium, low",
                    raised.exception.read().decode("utf-8"),
                )

                with opener.open(
                    f"{base_url}/api/cert/notifications", timeout=3
                ) as response:
                    current = json.load(response)

            self.assertEqual(current["settings"]["minimumSeverity"], "medium")
            self.assertEqual(current["settings"]["recipients"], ["security@example.com"])
            persisted = json.loads(
                (data_dir / "notification-settings.json").read_text(encoding="utf-8")
            )
            self.assertEqual(persisted["minimumSeverity"], "medium")
            self.assertEqual(persisted["recipients"], ["security@example.com"])


if __name__ == "__main__":
    unittest.main()
