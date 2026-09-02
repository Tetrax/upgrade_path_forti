"""Integration contracts for the converged certificate and notification runtime."""

from __future__ import annotations

import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from tests.test_cert_web import cert_admin, running_server

ROOT = Path(__file__).resolve().parents[1]


class ConvergedRuntimeTests(unittest.TestCase):
    def test_trusted_https_proxy_session_can_read_notification_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
                "FORTIOS_TEST_DATA_DIR": str(root / "data"),
            }
            proxy_headers = {
                "Host": "fortiupgrade.example",
                "X-Forwarded-Proto": "https",
                "X-Real-IP": "198.51.100.7",
            }

            with running_server(environment) as base_url:
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "valentin", "password": "mot-de-passe-solide"}
                    ).encode(),
                    method="POST",
                    headers={
                        **proxy_headers,
                        "Content-Type": "application/json",
                        "Origin": "https://fortiupgrade.example",
                    },
                )
                with urllib.request.urlopen(login, timeout=3) as response:
                    login_payload = json.load(response)
                    set_cookie = response.headers.get("Set-Cookie", "")

                cookie = set_cookie.split(";", 1)[0]
                settings = urllib.request.Request(
                    f"{base_url}/api/cert/notifications",
                    headers={**proxy_headers, "Cookie": cookie},
                )
                with urllib.request.urlopen(settings, timeout=3) as response:
                    settings_payload = json.load(response)

            self.assertTrue(login_payload["authenticated"])
            self.assertIn("Secure", set_cookie)
            self.assertIn("settings", settings_payload)
            self.assertIn("smtp", settings_payload)

    def test_compose_combines_smtp_with_read_only_certificate_helper(self) -> None:
        content = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        web = content.split("\n  web:\n", 1)[1].split("\n  scheduler:\n", 1)[0]
        scheduler = content.split("\n  scheduler:\n", 1)[1]

        for variable in (
            "FORTIOS_SMTP_HOST",
            "FORTIOS_SMTP_PASSWORD_FILE",
            "FORTIOS_SMTP_FROM",
            "FORTIOS_APP_URL",
        ):
            self.assertIn(variable, web)
            self.assertIn(variable, scheduler)

        self.assertIn("FORTIOS_CERT_TRUSTED_PROXY_CIDRS", web)
        self.assertIn("FORTIOS_CERT_HELPER_SOCKET", web)
        self.assertIn(
            ":/opt/fortios/certificates:${FORTIOS_CERTS_MOUNT_MODE:-rw}",
            web,
        )
        self.assertIn(":/run/fortios-cert-helper:ro", web)
        self.assertIn("/opt/fortios/data", web)
        self.assertIn("/opt/fortios/data", scheduler)


if __name__ == "__main__":
    unittest.main()
