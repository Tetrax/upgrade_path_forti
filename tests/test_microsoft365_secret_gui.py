"""Microsoft 365 client-secret storage and administration contract tests."""

from __future__ import annotations

import http.cookiejar
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import cert_admin  # type: ignore[import-not-found]
import fortios_notify as notify
import fortios_server as server  # type: ignore[import-not-found]

from tests.test_cert_web import login_admin, running_server


def graph_environment(secret_path: Path) -> dict[str, str]:
    return {
        "FORTIOS_EMAIL_TRANSPORT": "microsoft365",
        "FORTIOS_MICROSOFT365_TENANT_ID": "tenant.example.test",
        "FORTIOS_MICROSOFT365_CLIENT_ID": "11111111-2222-3333-4444-555555555555",
        "FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE": str(secret_path),
        "FORTIOS_MICROSOFT365_FROM": "fortiupgrade@example.test",
        "FORTIOS_MICROSOFT365_DISPLAY_NAME": "FortiUpgrade Notifications",
        "FORTIOS_APP_URL": "https://upgrade.example.test/app/",
    }


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
            "recipients": ["alerts@example.test"],
        }
    )


def load_graph_config(environment: dict[str, str], root: Path) -> notify.EmailConfig:
    return notify.load_email_config(
        environment,
        settings=notification_settings(),
        smtp_settings_path=root / "smtp-settings.json",
        email_transport_settings_path=root / "email-transport-settings.json",
    )
def post_secret_request(
    base_url: str,
    opener: urllib.request.OpenerDirector,
    payload: dict[str, object],
    *,
    csrf_token: str = "",
    origin: str | None = None,
) -> tuple[int, dict[str, object]]:
    headers = {
        "Content-Type": "application/json",
        "Origin": base_url if origin is None else origin,
    }
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    request = urllib.request.Request(
        f"{base_url}/api/cert/microsoft365/client-secret",
        data=json.dumps(payload).encode(),
        method="POST",
        headers=headers,
    )
    try:
        with opener.open(request, timeout=8) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        with error:
            try:
                payload = json.load(error)
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = {"error": str(error.reason)}
            return error.code, payload


class Microsoft365ClientSecretStorageTests(unittest.TestCase):
    def test_save_is_atomic_private_and_reloadable_from_the_environment_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "microsoft365" / "client-secret"
            secret_path.parent.mkdir()
            environment = graph_environment(secret_path)

            result = notify.save_microsoft365_client_secret(
                "rotated-secret-value",
                env=environment,
            )
            config = notify.load_email_config(
                environment,
                settings=notify.validate_notification_settings(
                    {
                        "enabled": True,
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
                        "recipients": ["alerts@example.test"],
                    }
                ),
                smtp_settings_path=root / "smtp-settings.json",
                email_transport_settings_path=root / "email-transport-settings.json",
            )
            public = notify.smtp_public_status(config)
            serialized_public = json.dumps(public)
            mode = stat.S_IMODE(secret_path.stat().st_mode)
            secret_bytes = secret_path.read_bytes()

        self.assertEqual(result, "available")
        self.assertEqual(secret_bytes, b"rotated-secret-value")
        self.assertEqual(mode, 0o600)
        self.assertEqual(config.graph_client_secret, "rotated-secret-value")
        self.assertTrue(config.is_complete())
        self.assertEqual(public["microsoft365"]["clientSecretStorageState"], "available")
        self.assertTrue(public["microsoft365"]["canSetClientSecret"])
        self.assertNotIn("rotated-secret-value", serialized_public)
        self.assertNotIn(str(secret_path), serialized_public)
    def test_replace_keeps_the_same_environment_authority_and_refreshes_graph_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "microsoft365" / "client-secret"
            secret_path.parent.mkdir()
            secret_path.write_bytes(b"first-secret")
            secret_path.chmod(0o600)
            environment = graph_environment(secret_path)

            notify.save_microsoft365_client_secret("second-secret", env=environment)
            config = load_graph_config(environment, root)
            _smtp, snapshot_config = notify.load_smtp_snapshot(
                environment,
                settings=notification_settings(),
                settings_path=root / "notification-settings.json",
                smtp_settings_path=root / "smtp-settings.json",
                email_transport_settings_path=root / "email-transport-settings.json",
            )
            saved = secret_path.read_bytes()

        self.assertEqual(saved, b"second-secret")
        self.assertEqual(config.graph_client_secret, "second-secret")
        self.assertEqual(snapshot_config.graph_client_secret, "second-secret")
        self.assertTrue(config.is_complete())

    def test_secret_rotation_does_not_change_transport_or_send_email(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            transport_path = root / "email-transport-settings.json"
            secret_path.write_bytes(b"first-secret")
            transport_path.write_bytes(b'{"transport":"smtp"}\n')
            before_transport = transport_path.read_bytes()
            environment = graph_environment(secret_path)
            with patch.object(notify, "send_email_result") as send_email:
                notify.save_microsoft365_client_secret("replacement-secret", env=environment)
            self.assertEqual(transport_path.read_bytes(), before_transport)
            send_email.assert_not_called()

    def test_rotated_secret_is_reloaded_by_a_separate_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            secret_path.write_bytes(b"first-secret")
            environment = graph_environment(secret_path)
            notify.save_microsoft365_client_secret("second-process-secret", env=environment)
            child_environment = {
                **os.environ,
                **environment,
                "M365_TEST_ROOT": str(root),
            }
            child_code = """
import os
import sys
from pathlib import Path
sys.path.insert(0, os.environ["M365_TEST_SCRIPTS"])
import fortios_notify as child_notify
root = Path(os.environ["M365_TEST_ROOT"])
settings = child_notify.validate_notification_settings({
    "enabled": True,
    "minimumSeverity": "high",
    "products": {
        "fortigate-fortios": True,
        "fortimanager": True,
        "fortianalyzer": True,
        "forticlient-ems": True,
        "forticlient": {"windows": True, "macos": True, "linux": True},
    },
    "recipients": ["alerts@example.test"],
})
config = child_notify.load_email_config(
    env=dict(os.environ),
    settings=settings,
    smtp_settings_path=root / "smtp-settings.json",
    email_transport_settings_path=root / "email-transport-settings.json",
)
print(config.graph_client_secret)
"""
            child_environment["M365_TEST_SCRIPTS"] = str(
                Path(__file__).resolve().parents[1] / "scripts"
            )
            result = subprocess.run(
                [sys.executable, "-c", child_code],
                env=child_environment,
                capture_output=True,
                check=True,
                text=True,
            )

        self.assertEqual(result.stdout.strip(), "second-process-secret")
        self.assertEqual(result.stderr, "")

    def test_empty_submission_rejects_without_erasing_the_previous_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            secret_path.write_bytes(b"previous-secret")
            environment = graph_environment(secret_path)

            with self.assertRaises(notify.Microsoft365SecretValidationError):
                notify.save_microsoft365_client_secret("", env=environment)
            saved = secret_path.read_bytes()

        self.assertEqual(saved, b"previous-secret")

    def test_whitespace_or_control_only_submission_rejects_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            secret_path.write_bytes(b"previous-secret")
            environment = graph_environment(secret_path)

            for candidate in (" \t\r\n", "\x00\x1f", "\u200b"):
                with self.subTest(candidate=repr(candidate)):
                    with self.assertRaises(notify.Microsoft365SecretValidationError):
                        notify.save_microsoft365_client_secret(candidate, env=environment)
                    self.assertEqual(secret_path.read_bytes(), b"previous-secret")

    def test_reader_refuses_a_symlinked_parent_without_reading_through_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            actual_parent = root / "actual-parent"
            actual_parent.mkdir()
            (actual_parent / "client-secret").write_bytes(b"should-not-be-read")
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(actual_parent, target_is_directory=True)
            environment = graph_environment(linked_parent / "client-secret")

            config = load_graph_config(environment, root)

        self.assertEqual(config.graph_client_secret, "")
        self.assertEqual(
            config.graph_client_secret_storage_state,
            notify.MICROSOFT365_SECRET_STORAGE_UNAVAILABLE,
        )
        self.assertFalse(config.is_complete())

    def test_oversize_utf8_submission_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            secret_path.write_bytes(b"previous-secret")
            environment = graph_environment(secret_path)
            oversized = "é" * (notify.MAX_MICROSOFT365_CLIENT_SECRET_BYTES // 2 + 1)

            with self.assertRaises(notify.Microsoft365SecretValidationError):
                notify.save_microsoft365_client_secret(oversized, env=environment)
            saved = secret_path.read_bytes()

        self.assertEqual(saved, b"previous-secret")


    def test_symlink_target_is_refused_and_existing_target_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            actual = root / "actual-secret"
            actual.write_bytes(b"actual-secret")
            secret_path = root / "client-secret"
            secret_path.symlink_to(actual)
            environment = graph_environment(secret_path)

            with self.assertRaises(notify.Microsoft365SecretStorageError):
                notify.save_microsoft365_client_secret("new-secret", env=environment)

            link_target = secret_path.read_bytes()
            actual_value = actual.read_bytes()

        self.assertEqual(link_target, b"actual-secret")
        self.assertEqual(actual_value, b"actual-secret")


    def test_symlink_parent_is_refused_without_creating_or_replacing_a_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            actual_parent = root / "actual-parent"
            actual_parent.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(actual_parent, target_is_directory=True)
            secret_path = linked_parent / "client-secret"
            environment = graph_environment(secret_path)

            with self.assertRaises(notify.Microsoft365SecretStorageError):
                notify.save_microsoft365_client_secret("new-secret", env=environment)

        self.assertFalse((actual_parent / "client-secret").exists())


    def test_nonregular_target_is_refused_without_removing_the_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            secret_path.mkdir()
            environment = graph_environment(secret_path)

            with self.assertRaises(notify.Microsoft365SecretStorageError):
                notify.save_microsoft365_client_secret("new-secret", env=environment)
            still_dir = secret_path.is_dir()

        self.assertTrue(still_dir)


    def test_readonly_external_secret_reports_storage_unavailable_and_preserves_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            secret_path.write_bytes(b"readonly-secret")
            secret_path.chmod(0o400)
            environment = graph_environment(secret_path)

            config = load_graph_config(environment, root)
            with self.assertRaises(notify.Microsoft365SecretStorageError):
                notify.save_microsoft365_client_secret("new-secret", env=environment)
            public = notify.smtp_public_status(config)
            saved = secret_path.read_bytes()

        self.assertEqual(saved, b"readonly-secret")
        self.assertEqual(
            public["microsoft365"]["clientSecretStorageState"],
            "storage-unavailable",
        )
        self.assertFalse(public["microsoft365"]["canSetClientSecret"])

    def test_readonly_filesystem_reports_storage_unavailable_before_a_write_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            environment = graph_environment(secret_path)
            readonly_flags = SimpleNamespace(f_flag=getattr(os, "ST_RDONLY", 1))
            with patch.object(notify.os, "fstatvfs", return_value=readonly_flags):
                config = load_graph_config(environment, root)

        public = notify.smtp_public_status(config)
        self.assertEqual(
            public["microsoft365"]["clientSecretStorageState"],
            "storage-unavailable",
        )
        self.assertFalse(public["microsoft365"]["canSetClientSecret"])

    def test_microsoft365_capability_is_public_before_switching_from_smtp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            environment = {
                **graph_environment(secret_path),
                "FORTIOS_EMAIL_TRANSPORT": "smtp",
            }
            config = load_graph_config(environment, root)
            smtp_settings = notify.load_smtp_settings(
                root / "smtp-settings.json",
                env=environment,
            )
            status = notify.smtp_public_status(config)
            settings = notify.smtp_public_settings(smtp_settings, config)

        self.assertEqual(status["transport"], "smtp")
        self.assertTrue(status["microsoft365"]["canSetClientSecret"])
        self.assertTrue(settings["microsoft365"]["canSetClientSecret"])
        self.assertEqual(settings["microsoft365"]["clientSecretStorageState"], "available")


class _SecretApiHandler:
    def __init__(
        self,
        payload: object,
        *,
        session_available: bool = True,
        csrf_allowed: bool = True,
    ) -> None:
        self.payload = payload
        self.session_available = session_available
        self.csrf_allowed = csrf_allowed
        self.csrf_required: bool | None = None
        self.status: int | None = None
        self.written: dict[str, object] | None = None
        self.max_bytes: int | None = None

    def require_admin_session(self, *, csrf: bool) -> object | None:
        self.csrf_required = csrf
        if not self.session_available:
            self.write_json_response({"error": "Session administrateur requise."}, 401)
            return None
        if csrf and not self.csrf_allowed:
            self.write_json_response({"error": "Jeton CSRF invalide."}, 403)
            return None
        return object()

    def read_json_body(self, *, max_bytes: int) -> object:
        self.max_bytes = max_bytes
        return self.payload

    def smtp_settings_response(self) -> dict[str, object]:
        return {
            "smtp": {
                "transport": "microsoft365",
                "microsoft365": {
                    "clientSecretConfigured": True,
                    "clientSecretStorageState": "available",
                    "canSetClientSecret": True,
                },
            }
        }

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


class Microsoft365ClientSecretApiTests(unittest.TestCase):
    def test_authenticated_secret_endpoint_requires_csrf_and_returns_only_public_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "microsoft365" / "client-secret"
            secret_path.parent.mkdir()
            handler = _SecretApiHandler({"clientSecret": "api-secret-value"})
            with patch.dict(
                os.environ,
                graph_environment(secret_path),
                clear=False,
            ):
                server.FortiosHandler.handle_microsoft365_client_secret_write(handler)  # type: ignore[arg-type]

            saved = secret_path.read_bytes()

        self.assertTrue(handler.csrf_required)
        self.assertEqual(handler.status, 200)
        self.assertEqual(saved, b"api-secret-value")
        self.assertIsNotNone(handler.max_bytes)
        self.assertEqual(
            handler.max_bytes,
            6 * notify.MAX_MICROSOFT365_CLIENT_SECRET_BYTES + 512,
        )
        serialized = json.dumps(handler.written or {})
        self.assertNotIn("api-secret-value", serialized)
        self.assertNotIn('"clientSecret":', serialized)
    def test_empty_endpoint_submission_returns_bad_request_and_preserves_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            secret_path.write_bytes(b"previous-secret")
            handler = _SecretApiHandler({"clientSecret": ""})
            with patch.dict(os.environ, graph_environment(secret_path), clear=False):
                server.FortiosHandler.handle_microsoft365_client_secret_write(handler)  # type: ignore[arg-type]
            saved = secret_path.read_bytes()

        self.assertEqual(handler.status, 400)
        self.assertEqual(saved, b"previous-secret")
        self.assertNotIn('"clientSecret":', json.dumps(handler.written or {}))

    def test_malformed_endpoint_payload_is_bad_request_not_an_internal_error(self) -> None:
        handler = _SecretApiHandler([{"clientSecret": "malformed-secret"}])
        with patch.dict(os.environ, {}, clear=False):
            server.FortiosHandler.handle_microsoft365_client_secret_write(handler)  # type: ignore[arg-type]

        self.assertEqual(handler.status, 400)
        self.assertNotIn("malformed-secret", json.dumps(handler.written or {}))

    def test_invalid_json_body_is_bad_request_without_echoing_the_body(self) -> None:
        handler = _SecretApiHandler({})

        def raise_invalid_body(*, max_bytes: int) -> object:
            del max_bytes
            raise ValueError("invalid body containing secret-value")

        handler.read_json_body = raise_invalid_body  # type: ignore[method-assign]
        server.FortiosHandler.handle_microsoft365_client_secret_write(handler)  # type: ignore[arg-type]

        self.assertEqual(handler.status, 400)
        self.assertNotIn("secret-value", json.dumps(handler.written or {}))

    def test_storage_unavailable_endpoint_is_503_and_does_not_mutate_or_echo_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret_path = root / "client-secret"
            secret_path.write_bytes(b"existing-secret")
            secret_path.chmod(0o400)
            handler = _SecretApiHandler({"clientSecret": "replacement-secret"})
            with patch.dict(os.environ, graph_environment(secret_path), clear=False):
                server.FortiosHandler.handle_microsoft365_client_secret_write(handler)  # type: ignore[arg-type]
            saved = secret_path.read_bytes()

        self.assertEqual(handler.status, 503)
        self.assertEqual(saved, b"existing-secret")
        serialized = json.dumps(handler.written or {})
        self.assertEqual(
            (handler.written or {}).get("errorCode"),
            "storage-unavailable",
        )
        self.assertNotIn("replacement-secret", serialized)


class Microsoft365ClientSecretUiTests(unittest.TestCase):
    def test_graph_secret_control_is_masked_write_only_and_uses_its_own_button_endpoint(self) -> None:
        root = Path(__file__).resolve().parents[1] / "app" / "cert"
        html = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "cert.js").read_text(encoding="utf-8")

        self.assertIn('id="m365-client-secret"', html)
        self.assertIn('id="m365-client-secret" type="password"', html)
        self.assertIn('id="save-m365-secret-button" type="button"', html)
        self.assertNotIn('<form id="m365-secret-form"', html)
        self.assertIn('apiRequest("microsoft365/client-secret"', script)
        self.assertIn('byId("m365-client-secret").value = ""', script)
        self.assertIn("clientSecretStorageState", script)
        self.assertIn("canSetClientSecret", script)
        save_start = script.index("async function saveMicrosoft365ClientSecret()")
        save_end = script.index('byId("save-m365-secret-button").addEventListener', save_start)
        save_function = script[save_start:save_end]
        self.assertNotIn("renderSmtpSettings(result)", save_function)
        self.assertIn("renderMicrosoft365SecretStatus(result)", save_function)

    def test_secret_request_body_limit_allows_maximum_utf8_secret(self) -> None:
        self.assertGreaterEqual(
            server.MAX_MICROSOFT365_CLIENT_SECRET_BODY_BYTES,
            6 * notify.MAX_MICROSOFT365_CLIENT_SECRET_BYTES + 512,
        )


class Microsoft365ClientSecretHttpTests(unittest.TestCase):
    def test_post_is_same_origin_authenticated_and_csrf_protected_while_get_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            credentials_path = root / "credentials.json"
            cert_admin.write_credentials(
                credentials_path,
                cert_admin.credential_payload("admin", "http-test-password"),
            )
            secret_path = root / "microsoft365" / "client-secret"
            secret_path.parent.mkdir()
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials_path),
                **graph_environment(secret_path),
            }
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            with running_server(environment) as base_url:
                with self.assertRaises(urllib.error.HTTPError) as missing_get:
                    opener.open(
                        f"{base_url}/api/cert/microsoft365/client-secret",
                        timeout=8,
                    )
                self.assertEqual(missing_get.exception.code, 404)

                unauthenticated_status, unauthenticated_response = post_secret_request(
                    base_url,
                    opener,
                    {"clientSecret": "unauthenticated-secret"},
                )
                self.assertEqual(unauthenticated_status, 401)
                self.assertNotIn("unauthenticated-secret", json.dumps(unauthenticated_response))
                self.assertFalse(secret_path.exists())

                login_status, login_response, _cookie = login_admin(
                    base_url,
                    "admin",
                    "http-test-password",
                    opener=opener,
                )
                self.assertEqual(login_status, 200)
                csrf_token = str(login_response["csrfToken"])

                csrf_status, csrf_response = post_secret_request(
                    base_url,
                    opener,
                    {"clientSecret": "invalid-csrf-secret"},
                    csrf_token="wrong-csrf-token",
                )
                self.assertEqual(csrf_status, 403)
                self.assertNotIn("invalid-csrf-secret", json.dumps(csrf_response))
                self.assertFalse(secret_path.exists())

                origin_status, origin_response = post_secret_request(
                    base_url,
                    opener,
                    {"clientSecret": "cross-origin-secret"},
                    csrf_token=csrf_token,
                    origin="http://attacker.example",
                )
                self.assertEqual(origin_status, 403)
                self.assertNotIn("cross-origin-secret", json.dumps(origin_response))
                self.assertFalse(secret_path.exists())

                success_status, success_response = post_secret_request(
                    base_url,
                    opener,
                    {"clientSecret": "http-success-secret"},
                    csrf_token=csrf_token,
                )
                self.assertEqual(success_status, 200)
                self.assertEqual(secret_path.read_bytes(), b"http-success-secret")
                self.assertNotIn("http-success-secret", json.dumps(success_response))


if __name__ == "__main__":
    unittest.main()
