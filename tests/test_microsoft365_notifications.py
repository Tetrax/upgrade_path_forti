"""Microsoft 365 Graph transport tests with no live tenant or network access."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from contextlib import redirect_stderr
from dataclasses import replace
from email.utils import format_datetime
from pathlib import Path
from typing import Any, Self
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fortios_notify as notify
import fortios_server as server  # type: ignore[import-not-found]
import fortios_watch as watch  # type: ignore[import-not-found]
import scheduled_refresh as refresh  # type: ignore[import-not-found]


def notification_settings(*, enabled: bool = True) -> notify.NotificationSettings:
    return notify.validate_notification_settings(
        {
            "enabled": enabled,
            "minimumSeverity": "high",
            "products": {
                "fortigate-fortios": True,
                "fortimanager": True,
                "fortianalyzer": True,
                "forticlient-ems": True,
                "forticlient": {"windows": True, "macos": True, "linux": True},
            },
            "recipients": ["alerts@example.test"],
        }
    )


def graph_env(secret_file: Path, **overrides: str) -> dict[str, str]:
    values = {
        "FORTIOS_EMAIL_TRANSPORT": "microsoft365",
        "FORTIOS_MICROSOFT365_TENANT_ID": "tenant.example.test",
        "FORTIOS_MICROSOFT365_CLIENT_ID": "11111111-2222-3333-4444-555555555555",
        "FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE": str(secret_file),
        "FORTIOS_MICROSOFT365_FROM": "fortiupgrade@example.test",
        "FORTIOS_MICROSOFT365_DISPLAY_NAME": "FortiUpgrade Notifications",
        "FORTIOS_SMTP_TIMEOUT": "17",
        "FORTIOS_APP_URL": "https://upgrade.example.test/app/",
    }
    values.update(overrides)
    return values


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int = -1) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self.status


def http_error(status: int, *, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return urllib.error.HTTPError(
        "https://graph.example.test/endpoint",
        status,
        "provider detail containing secret-value",
        headers,
        io.BytesIO(b'{"error":"provider detail containing secret-value"}'),
    )


def graph_failure_cases() -> list[tuple[str, object | None, str, bool, bool]]:
    return [
        ("429", http_error(429, retry_after="172800"), "microsoft365_throttled", True, False),
        ("500", http_error(500), "microsoft365_server_error", True, False),
        ("502", http_error(502), "microsoft365_server_error", True, False),
        ("503", http_error(503), "microsoft365_server_error", True, False),
        ("504", http_error(504), "microsoft365_server_error", True, False),
        ("timeout", TimeoutError("secret-value timeout detail"), "microsoft365_timeout", True, False),
        ("401", http_error(401), "microsoft365_unauthorized", False, False),
        ("403", http_error(403), "microsoft365_forbidden", False, False),
        ("config", None, "microsoft365_incomplete", False, True),
    ]


class Microsoft365ConfigurationTests(unittest.TestCase):
    def test_loads_graph_config_from_a_mounted_secret_without_exposing_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "microsoft365-client-secret"
            secret.write_text("secret-value\n", encoding="utf-8")
            settings = notify.load_email_config(
                graph_env(secret),
                settings=notification_settings(),
                smtp_settings_path=root / "smtp-settings.json",
            )
            smtp_settings, public_config = notify.load_smtp_snapshot(
                graph_env(secret),
                settings=notification_settings(),
                smtp_settings_path=root / "smtp-settings.json",
            )
            public = notify.smtp_public_settings(smtp_settings, public_config)

        self.assertEqual(settings.transport, "microsoft365")
        self.assertEqual(settings.graph_tenant_id, "tenant.example.test")
        self.assertEqual(settings.graph_client_id, "11111111-2222-3333-4444-555555555555")
        self.assertEqual(settings.graph_sender, "fortiupgrade@example.test")
        self.assertEqual(settings.graph_display_name, "FortiUpgrade Notifications")
        self.assertEqual(settings.graph_client_secret, "secret-value")
        self.assertTrue(settings.is_complete())
        serialized = json.dumps(public)
        self.assertNotIn("secret-value", serialized)
        self.assertNotIn(str(secret), serialized)
        self.assertTrue(public["microsoft365"]["clientSecretConfigured"])
        self.assertEqual(public["microsoft365"]["tenantId"], "tenant.example.test")

    def test_plaintext_graph_secret_environment_variable_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = graph_env(
                root / "missing-secret",
                FORTIOS_MICROSOFT365_CLIENT_SECRET="must-not-be-read",
            )
            config = notify.load_email_config(
                environment,
                settings=notification_settings(),
                smtp_settings_path=root / "smtp-settings.json",
            )

        self.assertFalse(config.is_complete())
        self.assertEqual(config.graph_client_secret, "")
        self.assertNotIn("must-not-be-read", repr(config))

    def test_invalid_graph_tenant_and_sender_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "secret"
            secret.write_text("secret-value", encoding="utf-8")
            for overrides in (
                {"FORTIOS_MICROSOFT365_TENANT_ID": "tenant/escape"},
                {"FORTIOS_MICROSOFT365_FROM": "sender\nBcc: attacker@example.test"},
            ):
                config = notify.load_email_config(
                    graph_env(secret, **overrides),
                    settings=notification_settings(),
                    smtp_settings_path=root / "smtp-settings.json",
                )
                with self.subTest(overrides=overrides):
                    self.assertFalse(config.is_complete())

class _FakeApiHandler:
    def __init__(self, payload: object, response: dict[str, object] | None = None) -> None:
        self.payload = payload
        self.response = response or {"ok": True}
        self.csrf_required: bool | None = None
        self.status: int | None = None
        self.written: dict[str, object] | None = None
        self.cert_test_email_limiter = MagicMock()
        self.cert_test_email_limiter.try_record.return_value = True
        self.cert_session_id = MagicMock(return_value="session")

    def require_admin_session(self, *, csrf: bool) -> object:
        self.csrf_required = csrf
        return object()

    def read_json_body(self, *, max_bytes: int) -> object:
        del max_bytes
        return self.payload

    def smtp_settings_response(self) -> dict[str, object]:
        return self.response

    def compose_notification_email_preview(
        self,
        payload: dict[str, object],
        *,
        app_url: str,
        run_timestamp: str,
    ) -> dict[str, str]:
        return server.FortiosHandler.compose_notification_email_preview(
            payload,
            app_url=app_url,
            run_timestamp=run_timestamp,
        )

    def write_json_response(
        self,
        payload: dict[str, object],
        status: int = 200,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        del extra_headers
        self.written = payload
        self.status = status


def graph_settings_payload() -> dict[str, object]:
    return {
        "transport": "microsoft365",
        "microsoft365": {
            "tenantId": "tenant.example.test",
            "clientId": "11111111-2222-3333-4444-555555555555",
            "from": "fortiupgrade@example.test",
            "displayName": "FortiUpgrade Notifications",
            "mailboxIdentity": "fortiupgrade@example.test",
        },
        "emailAppearance": {
            "displayName": "FortiUpgrade",
            "introduction": "Alerte de sécurité.",
            "signature": "Équipe sécurité",
        },
    }


class Microsoft365ApiTests(unittest.TestCase):
    def test_ui_uses_plain_transport_copy_and_dynamic_graph_labels(self) -> None:
        html = (Path(__file__).resolve().parents[1] / "app" / "cert" / "index.html").read_text(encoding="utf-8")
        script = (Path(__file__).resolve().parents[1] / "app" / "cert" / "cert.js").read_text(encoding="utf-8")

        self.assertIn("Comment voulez-vous envoyer les notifications ?", html)
        self.assertIn('option value="smtp">SMTP</option>', html)
        self.assertIn('option value="microsoft365">Microsoft 365 / Azure</option>', html)
        self.assertIn('id="microsoft365-settings-heading">Microsoft 365</h4>', html)
        self.assertIn("Envoi sans serveur SMTP, depuis une boîte Microsoft 365 autorisée.", html)
        self.assertIn("Comment configurer Microsoft 365 ?", html)
        self.assertIn("microsoft365-guide.md", html)
        self.assertIn('"Configuration Microsoft 365"', script)
        self.assertIn('"Tester la connexion"', script)
        self.assertIn('for (const id of ["m365-tenant-id", "m365-client-id", "m365-from-address", "m365-display-name"])', script)
        self.assertIn('if (transport === "smtp") {', script)
        self.assertIn("payload.smtp = {", script)
        self.assertIn("emailAppearance: appearance", script)

    def test_graph_configuration_api_persists_only_non_secret_fields_and_requires_csrf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            appearance_path = root / "smtp-settings.json"
            transport_path = root / "email-transport-settings.json"
            handler = _FakeApiHandler(graph_settings_payload(), {"smtp": {"transport": "microsoft365"}})
            with (
                patch.object(server, "SMTP_SETTINGS_PATH", appearance_path),
                patch.object(server, "EMAIL_TRANSPORT_SETTINGS_PATH", transport_path),
            ):
                server.FortiosHandler.handle_smtp_settings_write(handler)  # type: ignore[arg-type]
            persisted = json.loads(transport_path.read_text(encoding="utf-8"))

        self.assertTrue(handler.csrf_required)
        self.assertEqual(handler.status, 200)
        self.assertEqual(persisted["transport"], "microsoft365")
        self.assertNotIn("clientSecret", json.dumps(persisted))

    def test_graph_configuration_api_rejects_secret_upload_without_writing_it(self) -> None:
        payload = graph_settings_payload()
        payload["microsoft365"]["clientSecret"] = "must-not-persist"  # type: ignore[index]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            appearance_path = root / "smtp-settings.json"
            transport_path = root / "email-transport-settings.json"
            handler = _FakeApiHandler(payload)
            with (
                patch.object(server, "SMTP_SETTINGS_PATH", appearance_path),
                patch.object(server, "EMAIL_TRANSPORT_SETTINGS_PATH", transport_path),
            ):
                server.FortiosHandler.handle_smtp_settings_write(handler)  # type: ignore[arg-type]

        self.assertTrue(handler.csrf_required)
        self.assertEqual(handler.status, 400)
        self.assertFalse(appearance_path.exists())
        self.assertFalse(transport_path.exists())
        self.assertNotIn("must-not-persist", json.dumps(handler.written or {}))

    def test_api_test_email_invokes_real_test_transport_contract_and_reports_202(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Microsoft365GraphDeliveryTests()._config(Path(tmp))
            smtp_settings = notify.SmtpSettings(
                host="",
                port=587,
                security="starttls",
                allow_insecure=False,
                username="",
                sender=config.graph_sender,
                app_url=config.app_url,
                timeout=10,
                email_appearance=config.email_appearance or notify._default_email_appearance(),
            )
            result = notify.SmtpResult(
                True,
                "Email accepté par Microsoft Graph (HTTP 202 ; livraison finale non confirmée).",
                transport="microsoft365",
                provider_status=202,
                delivery_confirmed=False,
            )
            handler = _FakeApiHandler({"recipient": "operator@example.test"})
            with (
                patch.object(server.fortios_notify, "load_notification_settings", return_value=notification_settings()),
                patch.object(server.fortios_notify, "load_smtp_snapshot", return_value=(smtp_settings, config)),
                patch.object(server.fortios_notify, "send_test_email_result", return_value=result) as send_test,
            ):
                server.FortiosHandler.handle_notification_test_email(handler)  # type: ignore[arg-type]

        self.assertTrue(handler.csrf_required)
        self.assertEqual(handler.status, 200)
        send_test.assert_called_once_with(
            config,
            recipient="operator@example.test",
            appearance=smtp_settings.email_appearance,
        )
        self.assertEqual(handler.written["providerStatus"], 202)  # type: ignore[index]
        self.assertFalse(handler.written["deliveryConfirmed"])  # type: ignore[index]
    def test_api_preview_send_uses_graph_and_returns_safe_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Microsoft365GraphDeliveryTests()._config(Path(tmp))
            smtp_settings = notify.SmtpSettings(
                host="",
                port=587,
                security="starttls",
                allow_insecure=False,
                username="",
                sender=config.graph_sender,
                app_url=config.app_url,
                timeout=10,
                email_appearance=config.email_appearance or notify._default_email_appearance(),
            )
            handler = _FakeApiHandler(
                {
                    "scenario": "single",
                    "appearance": {
                        "displayName": "FortiUpgrade",
                        "introduction": "Preview",
                        "signature": "Security",
                    },
                    "runTimestamp": "2026-09-02T16:00:00Z",
                    "recipient": "operator@example.test",
                }
            )
            logs = io.StringIO()
            with (
                patch.object(
                    server.fortios_notify,
                    "load_smtp_preview_snapshot",
                    return_value=(smtp_settings, config),
                ),
                patch.object(
                    server.fortios_notify,
                    "_graph_urlopen",
                    side_effect=[
                        FakeResponse(200, b'{"access_token":"access-token"}'),
                        FakeResponse(202),
                    ],
                ) as urlopen,
                redirect_stderr(logs),
            ):
                server.FortiosHandler.handle_notification_email_preview_send(handler)  # type: ignore[arg-type]

        self.assertTrue(handler.csrf_required)
        self.assertEqual(handler.status, 200)
        self.assertEqual(urlopen.call_count, 2)
        response = handler.written or {}
        self.assertTrue(response["sent"])
        self.assertEqual(response["transport"], "microsoft365")
        self.assertEqual(response["providerStatus"], 202)
        self.assertFalse(response["deliveryConfirmed"])
        self.assertEqual(response["summary"]["recipient"], "operator@example.test")
        self.assertNotIn("html", response)
        serialized = json.dumps(response)
        for leaked_value in (
            "secret-value",
            "access-token",
            "Authorization",
            "Content-type",
            "Plain text body",
        ):
            self.assertNotIn(leaked_value, serialized)
        self.assertEqual(logs.getvalue().count("transport=microsoft365"), 2)
        self.assertEqual(logs.getvalue().count("provider=microsoft_graph"), 2)
        self.assertEqual(logs.getvalue().count("success=true"), 2)
    def test_api_preview_failure_returns_normalized_safe_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Microsoft365GraphDeliveryTests()._config(Path(tmp))
            smtp_settings = notify.SmtpSettings(
                host="",
                port=587,
                security="starttls",
                allow_insecure=False,
                username="",
                sender=config.graph_sender,
                app_url=config.app_url,
                timeout=10,
                email_appearance=config.email_appearance or notify._default_email_appearance(),
            )
            handler = _FakeApiHandler(
                {
                    "scenario": "single",
                    "appearance": {
                        "displayName": "FortiUpgrade",
                        "introduction": "Preview",
                        "signature": "Security",
                    },
                    "runTimestamp": "2026-09-02T16:00:00Z",
                    "recipient": "operator@example.test",
                }
            )
            logs = io.StringIO()
            with (
                patch.object(
                    server.fortios_notify,
                    "load_smtp_preview_snapshot",
                    return_value=(smtp_settings, config),
                ),
                patch.object(
                    server.fortios_notify,
                    "_graph_urlopen",
                    side_effect=[
                        FakeResponse(200, b'{"access_token":"access-token"}'),
                        http_error(403),
                    ],
                ) as urlopen,
                redirect_stderr(logs),
            ):
                server.FortiosHandler.handle_notification_email_preview_send(handler)  # type: ignore[arg-type]

        self.assertTrue(handler.csrf_required)
        self.assertEqual(handler.status, 503)
        self.assertEqual(urlopen.call_count, 2)
        response = handler.written or {}
        self.assertFalse(response.get("sent"))
        self.assertEqual(response.get("errorCode"), "microsoft365_forbidden")
        self.assertEqual(response.get("providerStatus"), 403)
        self.assertFalse(response.get("retryable"))
        serialized = json.dumps(response)
        for leaked_value in (
            "secret-value",
            "access-token",
            "Authorization",
            "Content-type",
            "provider detail",
        ):
            self.assertNotIn(leaked_value, serialized)
        self.assertEqual(logs.getvalue().count("transport=microsoft365"), 2)
        self.assertEqual(logs.getvalue().count("provider=microsoft_graph"), 2)
        self.assertEqual(logs.getvalue().count("success=true"), 1)
        self.assertEqual(logs.getvalue().count("success=false"), 1)


class Microsoft365GraphDeliveryTests(unittest.TestCase):
    def test_invalid_transport_never_falls_back_to_smtp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = replace(self._config(Path(tmp)), transport="invalid")
            with patch.object(notify, "send_email", return_value=True) as smtp_send:
                result = notify.deliver_email_result(config, "subject", "body")

        self.assertFalse(result.sent)
        self.assertEqual(result.error_code, "invalid_transport")
        smtp_send.assert_not_called()

    def _config(self, root: Path) -> notify.EmailConfig:
        secret = root / "secret"
        secret.write_text("secret-value", encoding="utf-8")
        return notify.load_email_config(
            graph_env(secret),
            settings=notification_settings(),
            smtp_settings_path=root / "smtp-settings.json",
        )

    def test_send_uses_client_credentials_then_json_sendmail_and_accepts_202(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self._config(root)
            token = FakeResponse(
                200,
                json.dumps({"access_token": "access-token", "token_type": "Bearer"}).encode(),
            )
            accepted = FakeResponse(202)
            logs = io.StringIO()
            with redirect_stderr(logs), patch.object(notify, "_graph_urlopen", side_effect=[token, accepted]) as urlopen:
                result = notify.send_email_result(
                    config,
                    "Subject from FortiUpgrade",
                    "Plain text body",
                    "<p>HTML body</p>",
                )

        self.assertTrue(result.sent)
        self.assertEqual(result.provider_status, 202)
        self.assertIn("202", result.message)
        self.assertIn("non confirmée", result.message)
        self.assertFalse(result.delivery_confirmed)
        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(logs.getvalue().count("provider=microsoft_graph"), 2)
        self.assertEqual(logs.getvalue().count("transport=microsoft365"), 2)
        self.assertEqual(logs.getvalue().count("success=true"), 2)
        self.assertIn("stage=token", logs.getvalue())
        self.assertIn("stage=delivery", logs.getvalue())
        self.assertNotIn("access-token", logs.getvalue())
        self.assertNotIn("Authorization", logs.getvalue())
        self.assertNotIn("Content-type", logs.getvalue())
        self.assertNotIn("Plain text body", logs.getvalue())
        self.assertNotIn("secret-value", logs.getvalue())
        self.assertNotIn("provider detail", logs.getvalue())

        token_request = urlopen.call_args_list[0].args[0]
        token_form = urllib.parse.parse_qs(token_request.data.decode("ascii"))
        self.assertEqual(token_form["grant_type"], ["client_credentials"])
        self.assertEqual(token_form["scope"], ["https://graph.microsoft.com/.default"])
        self.assertEqual(token_form["client_id"], [config.graph_client_id])
        self.assertIn("tenant.example.test", token_request.full_url)

        graph_request = urlopen.call_args_list[1].args[0]
        self.assertIn("/users/fortiupgrade%40example.test/sendMail", graph_request.full_url)
        self.assertEqual(graph_request.get_header("Authorization"), "Bearer access-token")
        self.assertEqual(graph_request.get_header("Content-type"), "application/json")
        payload = json.loads(graph_request.data.decode("utf-8"))
        message = payload["message"]
        self.assertEqual(message["subject"], "Subject from FortiUpgrade")
        self.assertEqual(message["body"]["contentType"], "HTML")
        self.assertIn("HTML body", message["body"]["content"])
        self.assertEqual(
            message["toRecipients"],
            [{"emailAddress": {"address": "alerts@example.test"}}],
        )

    def test_admin_test_email_performs_graph_send_not_token_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(Path(tmp))
            with patch.object(
                notify,
                "_graph_urlopen",
                side_effect=[
                    FakeResponse(200, b'{"access_token":"access-token"}'),
                    FakeResponse(202),
                ],
            ) as urlopen:
                result = notify.send_test_email_result(
                    config,
                    recipient="operator@example.test",
                    appearance=config.email_appearance,
                )

        self.assertTrue(result.sent)
        self.assertEqual(urlopen.call_count, 2)
        graph_request = urlopen.call_args_list[1].args[0]
        payload = json.loads(graph_request.data.decode("utf-8"))
        message = payload["message"]
        self.assertEqual(
            message["toRecipients"],
            [{"emailAddress": {"address": "operator@example.test"}}],
        )
        self.assertIn("Validation Microsoft 365", message["subject"])

    def test_token_rejection_is_normalized_without_provider_body_or_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(Path(tmp))
            with patch.object(notify, "_graph_urlopen", side_effect=http_error(400)):
                result = notify.send_email_result(config, "subject", "body")

        self.assertFalse(result.sent)
        self.assertEqual(result.error_code, "microsoft365_token_invalid")
        self.assertFalse(result.retryable)
        self.assertIn("tenant", result.message.lower())
        self.assertNotIn("provider detail", result.message)
        self.assertNotIn("secret-value", result.message)

    def test_graph_http_errors_are_normalized_and_retry_after_is_preserved(self) -> None:
        expected = {
            401: ("microsoft365_unauthorized", False),
            403: ("microsoft365_forbidden", False),
            404: ("microsoft365_sender_not_found", False),
            429: ("microsoft365_throttled", True),
            503: ("microsoft365_server_error", True),
        }
        for status, (error_code, retryable) in expected.items():
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                config = self._config(Path(tmp))
                effects: list[object] = [
                    FakeResponse(200, b'{"access_token":"access-token"}'),
                    http_error(status, retry_after="37" if status == 429 else None),
                ]
                with patch.object(notify, "_graph_urlopen", side_effect=effects):
                    result = notify.send_email_result(config, "subject", "body")
                self.assertFalse(result.sent)
                self.assertEqual(result.error_code, error_code)
                self.assertEqual(result.retryable, retryable)
                self.assertNotIn("provider detail", result.message)
                self.assertNotIn("secret-value", result.message)
                if status == 429:
                    self.assertEqual(result.retry_after_seconds, 37)

    def test_retry_after_preserves_positive_seconds_and_http_dates(self) -> None:
        self.assertEqual(notify._retry_after_seconds({"Retry-After": "172800"}), 172800)
        retry_at = notify.dt.datetime.now(notify.dt.UTC) + notify.dt.timedelta(seconds=172800)
        parsed_http_date = notify._retry_after_seconds(
            {"Retry-After": format_datetime(retry_at, usegmt=True)}
        )
        self.assertIsNotNone(parsed_http_date)
        self.assertGreaterEqual(parsed_http_date, 172790)  # type: ignore[arg-type]
        self.assertLessEqual(parsed_http_date, 172800)  # type: ignore[arg-type]
        self.assertEqual(notify._retry_after_seconds({"Retry-After": "-1"}), 0)
        self.assertIsNone(notify._retry_after_seconds({"Retry-After": "not-a-delay"}))

    def test_timeout_is_normalized_and_does_not_leak_exception_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(Path(tmp))
            with patch.object(
                notify,
                "_graph_urlopen",
                side_effect=TimeoutError("secret-value timeout detail"),
            ):
                result = notify.send_email_result(config, "subject", "body")

        self.assertFalse(result.sent)
        self.assertEqual(result.error_code, "microsoft365_timeout")
        self.assertTrue(result.retryable)
        self.assertNotIn("secret-value", result.message)


class Microsoft365RetryStateTests(unittest.TestCase):
    def test_permanent_failure_has_a_persistent_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="graph-event", summary="x")
            notify.enqueue_and_claim(path, [event], claimant="graph-run", now="2026-09-01T00:00:00Z")
            notify.release_claim(
                path,
                "graph-run",
                now="2026-09-01T00:00:00Z",
                outcome=notify.SmtpResult(
                    False,
                    "Microsoft 365 access denied.",
                    error_code="microsoft365_forbidden",
                    retryable=False,
                    transport="microsoft365",
                ),
            )
            state = notify.load_notify_state(path)
            self.assertIsNotNone(state["outbox"][0]["nextAttemptAt"])
            self.assertEqual(
                notify.enqueue_and_claim(path, [], claimant="too-soon", now="2026-09-01T00:00:01Z"),
                [],
            )
            retry_time = (
                notify.dt.datetime.fromisoformat("2026-09-01T00:00:00+00:00")
                + notify.dt.timedelta(seconds=notify.PERMANENT_RETRY_COOLDOWN_SECONDS + 1)
            ).isoformat().replace("+00:00", "Z")
            claimed = notify.enqueue_and_claim(path, [], claimant="later", now=retry_time)

        self.assertEqual([item.dedup_key for item in claimed], ["graph-event"])

    def test_retry_after_seconds_are_preserved_when_releasing_a_graph_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="graph-retry", summary="x")
            notify.enqueue_and_claim(path, [event], claimant="graph-run", now="2026-09-01T00:00:00Z")
            notify.release_claim(
                path,
                "graph-run",
                now="2026-09-01T00:00:00Z",
                outcome=notify.SmtpResult(
                    False,
                    "Microsoft Graph is busy.",
                    error_code="microsoft365_server_error",
                    retryable=True,
                    retry_after_seconds=172800,
                    transport="microsoft365",
                ),
            )
            state = notify.load_notify_state(path)

        next_attempt = notify.dt.datetime.fromisoformat(
            state["outbox"][0]["nextAttemptAt"].replace("Z", "+00:00")
        )
        self.assertEqual(
            (next_attempt - notify.dt.datetime.fromisoformat("2026-09-01T00:00:00+00:00")).total_seconds(),
            172800,
        )

    def test_extreme_retry_after_saturates_to_maximum_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="graph-overflow", summary="x")
            notify.enqueue_and_claim(path, [event], claimant="graph-run", now="2026-09-01T00:00:00Z")
            notify.release_claim(
                path,
                "graph-run",
                now="2026-09-01T00:00:00Z",
                outcome=notify.SmtpResult(
                    False,
                    "Microsoft Graph is busy.",
                    error_code="microsoft365_server_error",
                    retryable=True,
                    retry_after_seconds=10**30,
                    transport="microsoft365",
                ),
            )
            state = notify.load_notify_state(path)

        self.assertEqual(
            state["outbox"][0]["nextAttemptAt"],
            notify.dt.datetime.max.replace(tzinfo=notify.dt.UTC).isoformat().replace("+00:00", "Z"),
        )

    def test_unknown_failure_transport_is_not_persisted_into_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="invalid-transport", summary="x")
            notify.enqueue_and_claim(path, [event], claimant="bad-config", now="2026-09-01T00:00:00Z")
            notify.release_claim(
                path,
                "bad-config",
                now="2026-09-01T00:00:00Z",
                outcome=notify.SmtpResult(
                    False,
                    "Incomplete",
                    error_code="invalid_transport",
                    retryable=False,
                    transport="invalid",
                ),
            )
            state = notify.load_notify_state(path)
            self.assertIsNone(state["outbox"][0]["lastTransport"])
            self.assertEqual(state["outbox"][0]["lastErrorCode"], "invalid_transport")
            self.assertIsNotNone(state["outbox"][0]["nextAttemptAt"])
            # The same file must remain valid for the next collector process.
            self.assertEqual(len(notify.load_notify_state(path)["outbox"]), 1)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "notify.json"
            event = notify.NotificationEvent(category="DAILY", dedup_key="switch-event", summary="x")
            notify.enqueue_and_claim(path, [event], claimant="graph-run", now="2026-09-01T00:00:00Z")
            notify.release_claim(
                path,
                "graph-run",
                now="2026-09-01T00:00:00Z",
                outcome=notify.SmtpResult(
                    False,
                    "Microsoft 365 access denied.",
                    error_code="microsoft365_forbidden",
                    retryable=False,
                    transport="microsoft365",
                ),
            )
            notify.prepare_retry_for_transport(path, "smtp")
            claimed = notify.enqueue_and_claim(
                path,
                [],
                claimant="smtp-run",
                now="2026-09-01T00:00:01Z",
            )

        self.assertEqual([item.dedup_key for item in claimed], ["switch-event"])
class Microsoft365ConsumerRetryTests(unittest.TestCase):
    def _graph_config(self, root: Path) -> notify.EmailConfig:
        return Microsoft365GraphDeliveryTests()._config(root)

    def _run_watch_failure(
        self,
        failure: object | None,
        *,
        incomplete: bool,
    ) -> tuple[dict[str, Any], str, int, int]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path = root / "state.json"
            health_path = root / "health.json"
            history_path = root / "notify-history.json"
            settings_path = root / "notification-settings.json"
            base_path.write_text(json.dumps(watch.normalize_state({})), encoding="utf-8")
            secret = root / "microsoft365-client-secret"
            if not incomplete:
                secret.write_text("secret-value", encoding="utf-8")
            cve = {
                "id": "CVE-2026-00999",
                "advisoryId": "FG-IR-26-999",
                "title": "Synthetic CVE",
                "severity": "critical",
                "affected": [{"product": "fortigate-fortios", "branch": "7.4"}],
                "publishedAt": "2026-07-17",
                "updatedAt": "2026-07-17",
            }
            arguments = [
                "--cve-catalog",
                "--base", str(base_path),
                "--output", str(base_path),
                "--report", str(root / "report.md"),
                "--health-output", str(health_path),
                "--notify-history-output", str(history_path),
                "--notification-settings-output", str(settings_path),
                "--official-paths-csv", str(root / "no-official.csv"),
                "--advisories-csv", str(root / "no-advisories.csv"),
                "--upgrade-exports", str(root / "no-exports"),
            ]
            environment = graph_env(
                secret if not incomplete else root / "missing-secret",
                FORTIOS_EMAIL_ENABLED="true",
                FORTIOS_SMTP_TO="alerts@example.test",
            )
            effects = (
                []
                if incomplete
                else [FakeResponse(200, b'{"access_token":"access-token"}'), failure]
            )
            logs = io.StringIO()
            with (
                patch.dict(os.environ, environment, clear=False),
                patch.object(watch, "collect_cve_catalog", return_value=({"FG-IR-26-999": [cve]}, [])),
                patch.object(watch, "fetch_psirt_versions", return_value=set()),
                patch.object(notify, "_graph_urlopen", side_effect=effects) as urlopen,
                redirect_stderr(logs),
            ):
                exit_code = watch.main(arguments)
            state = notify.load_notify_state(history_path)
            return state, logs.getvalue(), exit_code, urlopen.call_count

    def _run_scheduled_failure(
        self,
        failure: object | None,
        *,
        incomplete: bool,
    ) -> tuple[dict[str, Any], str, int]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            history_path = root / refresh.DEFAULT_NOTIFY_HISTORY_PATH
            before = {"status": "error", "consecutiveFailures": 1, "lastError": "first"}
            after = {"status": "error", "consecutiveFailures": 2, "lastError": "second"}
            health_path.parent.mkdir(parents=True, exist_ok=True)
            health_path.write_text(
                json.dumps({"sources": {refresh.SOURCE_COMPAT_MATRIX: after}}),
                encoding="utf-8",
            )
            history_path.parent.mkdir(parents=True, exist_ok=True)
            history_path.write_text(
                json.dumps(
                    {
                        "sentKeys": {},
                        "outbox": [],
                        "eolState": {},
                        "checkpoint": {
                            "versionsByProduct": {},
                            "cvesById": {},
                            "health": {refresh.SOURCE_COMPAT_MATRIX: before},
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = self._graph_config(root)
            if incomplete:
                config = replace(config, graph_client_secret="")
            effects = (
                []
                if incomplete
                else [FakeResponse(200, b'{"access_token":"access-token"}'), failure]
            )
            logs = io.StringIO()
            with (
                patch.object(refresh.fortios_notify, "load_email_config", return_value=config),
                patch.object(refresh.fortios_notify, "_graph_urlopen", side_effect=effects) as urlopen,
                redirect_stderr(logs),
            ):
                refresh._notify_compatibility_transition(root=root)
            state = notify.load_notify_state(history_path)
            return state, logs.getvalue(), urlopen.call_count

    def test_watch_main_records_graph_retry_outcomes_without_smtp_fallback(self) -> None:
        for label, failure, error_code, retryable, incomplete in graph_failure_cases():
            with self.subTest(case=label):
                state, logs, exit_code, call_count = self._run_watch_failure(
                    failure,
                    incomplete=incomplete,
                )
                entry = state["outbox"][0]
                self.assertEqual(exit_code, 0)
                self.assertEqual(call_count, 0 if incomplete else 2)
                self.assertEqual(entry["lastTransport"], "microsoft365")
                self.assertEqual(entry["lastErrorCode"], error_code)
                self.assertIsNotNone(entry["nextAttemptAt"])
                self.assertIn("transport=microsoft365", logs)
                self.assertIn("provider=microsoft_graph", logs)
                self.assertIn("success=false", logs)
                self.assertIn(f"retryable={str(retryable).lower()}", logs)
                self.assertNotIn("secret-value", logs)
                self.assertNotIn("access-token", logs)
                self.assertNotIn("provider detail", logs)

    def test_scheduled_compatibility_records_graph_retry_outcomes(self) -> None:
        for label, failure, error_code, retryable, incomplete in graph_failure_cases():
            with self.subTest(case=label):
                state, logs, call_count = self._run_scheduled_failure(
                    failure,
                    incomplete=incomplete,
                )
                entry = state["outbox"][0]
                self.assertEqual(call_count, 0 if incomplete else 2)
                self.assertEqual(entry["lastTransport"], "microsoft365")
                self.assertEqual(entry["lastErrorCode"], error_code)
                self.assertIsNotNone(entry["nextAttemptAt"])
                self.assertIn("transport=microsoft365", logs)
                self.assertIn("provider=microsoft_graph", logs)
                self.assertIn("success=false", logs)
                self.assertIn(f"retryable={str(retryable).lower()}", logs)
                self.assertNotIn("secret-value", logs)
                self.assertNotIn("access-token", logs)
                self.assertNotIn("provider detail", logs)

    def test_scheduled_recovery_persists_graph_failure_for_a_later_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            health_path = root / refresh.DEFAULT_HEALTH_PATH
            history_path = root / refresh.DEFAULT_NOTIFY_HISTORY_PATH
            before = {"status": "error", "consecutiveFailures": 1, "lastError": "first"}
            after = {"status": "error", "consecutiveFailures": 2, "lastError": "second"}
            health_path.parent.mkdir(parents=True, exist_ok=True)
            health_path.write_text(
                json.dumps({"sources": {refresh.SOURCE_COMPAT_MATRIX: after}}),
                encoding="utf-8",
            )
            history_path.parent.mkdir(parents=True, exist_ok=True)
            history_path.write_text(
                json.dumps(
                    {
                        "sentKeys": {},
                        "outbox": [],
                        "eolState": {},
                        "checkpoint": {
                            "versionsByProduct": {},
                            "cvesById": {},
                            "health": {refresh.SOURCE_COMPAT_MATRIX: before},
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = self._graph_config(root)
            effects = [
                FakeResponse(200, b'{"access_token":"access-token"}'),
                http_error(403),
            ]
            with (
                patch.object(refresh.fortios_notify, "load_email_config", return_value=config),
                patch.object(refresh.fortios_notify, "_graph_urlopen", side_effect=effects),
            ):
                refresh._notify_compatibility_transition(root=root)
            state = notify.load_notify_state(history_path)

        self.assertEqual(state["outbox"][0]["lastTransport"], "microsoft365")
        self.assertEqual(state["outbox"][0]["lastErrorCode"], "microsoft365_forbidden")
        self.assertIsNotNone(state["outbox"][0]["nextAttemptAt"])

    def test_collector_persists_graph_failure_without_using_smtp_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_path = root / "state.json"
            health_path = root / "health.json"
            history_path = root / "notify-history.json"
            settings_path = root / "notification-settings.json"
            base_path.write_text(json.dumps(watch.normalize_state({})), encoding="utf-8")
            secret = root / "microsoft365-client-secret"
            secret.write_text("secret-value", encoding="utf-8")
            cve = {
                "id": "CVE-2026-00999",
                "advisoryId": "FG-IR-26-999",
                "title": "Synthetic CVE",
                "severity": "critical",
                "affected": [{"product": "fortigate-fortios", "branch": "7.4"}],
                "publishedAt": "2026-07-17",
                "updatedAt": "2026-07-17",
            }
            arguments = [
                "--cve-catalog",
                "--base", str(base_path),
                "--output", str(base_path),
                "--report", str(root / "report.md"),
                "--health-output", str(health_path),
                "--notify-history-output", str(history_path),
                "--notification-settings-output", str(settings_path),
                "--official-paths-csv", str(root / "no-official.csv"),
                "--advisories-csv", str(root / "no-advisories.csv"),
                "--upgrade-exports", str(root / "no-exports"),
            ]
            environment = graph_env(
                secret,
                FORTIOS_EMAIL_ENABLED="true",
                FORTIOS_SMTP_TO="alerts@example.test",
            )
            with (
                patch.dict(os.environ, environment, clear=False),
                patch.object(watch, "collect_cve_catalog", return_value=({"FG-IR-26-999": [cve]}, [])),
                patch.object(watch, "fetch_psirt_versions", return_value=set()),
                patch.object(
                    notify,
                    "_graph_urlopen",
                    side_effect=[FakeResponse(200, b'{"access_token":"access-token"}'), http_error(403)],
                ),
            ):
                exit_code = watch.main(arguments)
            state = notify.load_notify_state(history_path)

        self.assertEqual(exit_code, 0)
        self.assertEqual(state["outbox"][0]["lastTransport"], "microsoft365")
        self.assertEqual(state["outbox"][0]["lastErrorCode"], "microsoft365_forbidden")
        self.assertIsNotNone(state["outbox"][0]["nextAttemptAt"])


if __name__ == "__main__":
    unittest.main()
