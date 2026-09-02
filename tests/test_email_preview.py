"""Realistic email preview scenarios and protected admin delivery."""

from __future__ import annotations

import json
import tempfile
import unittest
import urllib.error
import urllib.request
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from unittest import mock

from scripts import cert_admin
from scripts import fortios_notify as notify
from tests.test_cert_web import running_server
from tests.test_smtp_admin import (
    authenticated_opener,
    running_smtp_server,
    smtp_payload,
)

APPEARANCE = {
    "displayName": "FortiUpgrade SOC",
    "introduction": "Introduction de prévisualisation.",
    "signature": "Équipe sécurité.",
}


class EmailPreviewCompositionTests(unittest.TestCase):
    def compose(self, scenario: str) -> dict[str, str]:
        return notify.compose_email_preview(
            scenario,
            app_url="https://fortiupgrade.example/app/",
            run_timestamp="2026-09-02T16:00:00Z",
            appearance=notify.validate_email_appearance(APPEARANCE),
        )

    def test_single_preview_uses_the_real_renderer(self) -> None:
        original = notify.compose_email
        calls: list[list[notify.NotificationEvent]] = []

        def recording_compose(
            events: list[notify.NotificationEvent], **kwargs: Any
        ) -> tuple[str, str, str] | None:
            calls.append(events)
            return original(events, **kwargs)

        with mock.patch.object(
            notify, "compose_email", side_effect=recording_compose
        ):
            preview = self.compose("single")

        self.assertEqual(len(calls), 1)
        self.assertEqual(len(calls[0]), 1)
        self.assertEqual(
            preview["subject"],
            "[FortiUpgrade][CRITICAL] 1 nouvelles vulnérabilités Fortinet",
        )
        self.assertIn("Critical : 1", preview["text"])
        self.assertIn("High     : 0", preview["text"])
        self.assertIn("CVE-2026-00001", preview["html"])

    def test_multiple_preview_contains_three_distinct_cve_blocks(self) -> None:
        preview = self.compose("multiple")

        self.assertIn("Critical : 1", preview["text"])
        self.assertIn("High     : 2", preview["text"])
        self.assertEqual(preview["text"].count(" — CVE-2026-0000"), 3)
        for cve_id in ("CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00003"):
            self.assertIn(cve_id, preview["html"])

    def test_multi_product_preview_counts_products_and_keeps_one_block_per_cve(self) -> None:
        preview = self.compose("multi-product")

        self.assertEqual(
            preview["subject"],
            "[FortiUpgrade][CRITICAL] 3 nouvelles vulnérabilités Fortinet",
        )
        for expected in (
            "Critical : 1",
            "High     : 2",
            "FortiGate / FortiOS : 2",
            "FortiManager : 1",
            "FortiAnalyzer : 1",
            "FortiClient Windows : 1",
        ):
            self.assertIn(expected, preview["text"])
        self.assertEqual(preview["text"].count("CRITICAL — CVE-2026-00001"), 1)
        first_block = preview["text"].split("CRITICAL — CVE-2026-00001", 1)[1].split(
            "HIGH — CVE-2026-00002", 1
        )[0]
        self.assertIn("FortiGate / FortiOS", first_block)
        self.assertIn("FortiManager", first_block)
        self.assertEqual(preview["text"].count(" — CVE-2026-0000"), 3)

    def test_preview_applies_live_appearance_to_html_and_plain_text(self) -> None:
        preview = self.compose("single")

        for value in APPEARANCE.values():
            self.assertIn(value, preview["text"])
            self.assertIn(value, preview["html"])
        self.assertTrue(preview["html"].startswith("<!doctype html>"))
        self.assertTrue(preview["text"].strip())

    def test_preview_send_readiness_does_not_require_notification_recipients(self) -> None:
        settings = notify.validate_smtp_settings(
            smtp_payload(
                host="127.0.0.1",
                port=2525,
                security="none",
                allowInsecure=True,
                username="",
            )
        )
        config = notify.EmailConfig(
            enabled=False,
            smtp_host=settings.host,
            smtp_port=settings.port,
            smtp_username="",
            smtp_password="",
            smtp_from=settings.sender,
            smtp_to=(),
            smtp_starttls=False,
            smtp_timeout=settings.timeout,
            app_url=settings.app_url,
            smtp_security=settings.security,
        )

        public = notify.smtp_public_settings(settings, config)

        self.assertEqual(public["state"], "incomplete")
        self.assertTrue(public["previewSendReady"])


class EmailPreviewApiTests(unittest.TestCase):
    def post(
        self,
        opener: urllib.request.OpenerDirector,
        base_url: str,
        path: str,
        payload: dict[str, Any],
        *,
        csrf_token: str | None = None,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "Origin": base_url}
        if csrf_token is not None:
            headers["X-CSRF-Token"] = csrf_token
        request = urllib.request.Request(
            f"{base_url}{path}",
            data=json.dumps(payload).encode(),
            method="POST",
            headers=headers,
        )
        with opener.open(request, timeout=5) as response:
            return json.load(response)

    def test_preview_requires_admin_session_but_not_notification_activation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            notify.save_notification_settings(
                data_dir / "notification-settings.json",
                {
                    "enabled": False,
                    "minimumSeverity": "high",
                    "products": {
                        "fortigate-fortios": True,
                        "fortimanager": True,
                        "fortianalyzer": True,
                        "forticlient-ems": True,
                        "forticlient": {
                            "windows": True,
                            "macos": True,
                            "linux": True,
                        },
                    },
                    "recipients": [],
                },
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(data_dir),
            }
            payload = {"scenario": "multi-product", "appearance": APPEARANCE}
            with running_server(environment) as base_url:
                anonymous = urllib.request.build_opener()
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    self.post(
                        anonymous,
                        base_url,
                        "/api/cert/notifications/preview",
                        payload,
                    )
                self.assertEqual(rejected.exception.code, 401)

                opener, _csrf_token = authenticated_opener(base_url)
                preview = self.post(
                    opener,
                    base_url,
                    "/api/cert/notifications/preview",
                    payload,
                )

            self.assertEqual(preview["scenario"], "multi-product")
            self.assertIn("subject", preview)
            self.assertIn("html", preview)
            self.assertIn("text", preview)
            self.assertNotIn("secret", json.dumps(preview).lower())
            self.assertNotIn("password", json.dumps(preview).lower())

    def test_send_preview_requires_csrf_and_preserves_all_notification_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, running_smtp_server() as smtp:
            root = Path(tmp)
            data_dir = root / "data"
            data_dir.mkdir()
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            catalog = data_dir / "fortios-data.generated.json"
            catalog.write_text('{"catalog":"unchanged"}\n', encoding="utf-8")
            history = data_dir / "fortios-notify-history.json"
            history.write_text(
                '{"checkpoint":{"versionsByProduct":{},"cvesById":{},"health":{}},'
                '"sentKeys":{"existing":"2026-09-01T00:00:00Z"},'
                '"outbox":[],"eolState":{"7.0":false}}\n',
                encoding="utf-8",
            )
            notification_path = data_dir / "notification-settings.json"
            notify.save_notification_settings(
                notification_path,
                {
                    "enabled": False,
                    "minimumSeverity": "high",
                    "products": {
                        "fortigate-fortios": True,
                        "fortimanager": True,
                        "fortianalyzer": True,
                        "forticlient-ems": True,
                        "forticlient": {
                            "windows": True,
                            "macos": True,
                            "linux": True,
                        },
                    },
                    "recipients": [],
                },
            )
            notify.save_smtp_settings(
                data_dir / "smtp-settings.json",
                smtp_payload(
                    host="127.0.0.1",
                    port=smtp.server_address[1],
                    security="none",
                    allowInsecure=True,
                    username="",
                ),
            )
            notification_path.write_text(
                '{"malformed":"must remain byte-identical"}\n', encoding="utf-8"
            )
            before = {
                path.name: path.read_bytes()
                for path in (catalog, history, notification_path)
            }
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TEST_DATA_DIR": str(data_dir),
            }
            preview_request = {"scenario": "multi-product", "appearance": APPEARANCE}
            with running_server(environment) as base_url:
                opener, csrf_token = authenticated_opener(base_url)
                preview = self.post(
                    opener,
                    base_url,
                    "/api/cert/notifications/preview",
                    preview_request,
                )
                send_request = {
                    **preview_request,
                    "runTimestamp": preview["runTimestamp"],
                    "recipient": "preview-recipient@example.com",
                }
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    self.post(
                        opener,
                        base_url,
                        "/api/cert/notifications/send-preview",
                        send_request,
                    )
                self.assertEqual(rejected.exception.code, 403)

                sent = self.post(
                    opener,
                    base_url,
                    "/api/cert/notifications/send-preview",
                    send_request,
                    csrf_token=csrf_token,
                )

            self.assertTrue(sent["sent"])
            self.assertIn("Message accepté par le serveur SMTP", sent["checks"])
            self.assertEqual(len(smtp.messages), 1)
            message = BytesParser(policy=policy.default).parsebytes(smtp.messages[0])
            self.assertEqual(message["Subject"], preview["subject"])
            self.assertEqual(message["To"], "preview-recipient@example.com")
            self.assertEqual(
                message.get_body(preferencelist=("plain",))
                .get_content()
                .replace("\r\n", "\n")
                .strip(),
                preview["text"].strip(),
            )
            self.assertEqual(
                message.get_body(preferencelist=("html",))
                .get_content()
                .replace("\r\n", "\n")
                .strip(),
                preview["html"].strip(),
            )
            for path in (catalog, history, notification_path):
                self.assertEqual(path.read_bytes(), before[path.name])
            self.assertNotIn("secret", json.dumps(sent).lower())
            self.assertNotIn("password", json.dumps(sent).lower())


if __name__ == "__main__":
    unittest.main()
