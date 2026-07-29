"""HTTP integration tests for the private certificate administration page."""

from __future__ import annotations

import base64
import concurrent.futures
import os
import json
import http.cookiejar
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "scripts" / "fortios_server.py"
sys.path.insert(0, str(ROOT / "scripts"))
import cert_admin  # type: ignore[import-not-found]  # noqa: E402
from tests.test_certctl import HOSTNAME, create_self_signed  # noqa: E402


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def running_server(environment: dict[str, str]) -> Iterator[str]:
    port = free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            str(SERVER),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env={**os.environ, **environment},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    tls_active = bool(environment.get("FORTIOS_TLS_CERT"))
    base_url = f"{'https' if tls_active else 'http'}://127.0.0.1:{port}"
    tls_context = ssl._create_unverified_context() if tls_active else None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                output = process.stdout.read() if process.stdout else ""
                raise AssertionError(f"server exited early ({process.returncode}): {output}")
            try:
                urllib.request.urlopen(
                    f"{base_url}/app/",
                    timeout=0.3,
                    context=tls_context,
                ).close()
                break
            except Exception:
                time.sleep(0.05)
        else:
            raise AssertionError("server did not become ready")
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()


class CertificateWebTests(unittest.TestCase):
    def test_certificate_page_is_hidden_on_plain_http_by_default(self) -> None:
        with running_server({}) as base_url:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(f"{base_url}/cert/", timeout=2)

            self.assertEqual(raised.exception.code, 404)

    def test_local_development_flag_exposes_the_certificate_login_page(self) -> None:
        with running_server({"FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1"}) as base_url:
            try:
                response = urllib.request.urlopen(f"{base_url}/cert/", timeout=2)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read().decode("utf-8")

            self.assertEqual(response.status, 200)
            self.assertIn("Gestion des certificats", body)
            self.assertIn('id="login-form"', body)

    def test_valid_login_creates_an_http_only_session_and_csrf_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                request = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "valentin", "password": "mot-de-passe-solide"},
                    ).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                    },
                )
                try:
                    response = urllib.request.urlopen(request, timeout=3)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    raw_body = response.read().decode("utf-8")
                    try:
                        payload = json.loads(raw_body)
                    except json.JSONDecodeError:
                        payload = {"raw": raw_body}
                    cookie = response.headers.get("Set-Cookie", "")

            self.assertEqual(response.status, 200, payload)
            self.assertTrue(payload["authenticated"])
            self.assertGreaterEqual(len(payload["csrfToken"]), 32)
            self.assertIn("fortios_cert_session=", cookie)
            self.assertIn("HttpOnly", cookie)
            self.assertIn("SameSite=Strict", cookie)

    def test_tls_login_sets_secure_cookie_and_hsts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            certificate, private_key = create_self_signed(root)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_TLS_CERT": str(certificate),
                "FORTIOS_TLS_KEY": str(private_key),
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                request = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "valentin", "password": "mot-de-passe-solide"},
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(
                    request,
                    timeout=3,
                    context=ssl._create_unverified_context(),
                ) as response:
                    cookie = response.headers.get("Set-Cookie", "")
                    hsts = response.headers.get("Strict-Transport-Security", "")

            self.assertIn("Secure", cookie)
            self.assertEqual(hsts, "max-age=31536000")

    def test_authenticated_session_can_read_private_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                )
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "valentin", "password": "mot-de-passe-solide"},
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with opener.open(login, timeout=3) as login_response:
                    login_payload = json.load(login_response)
                try:
                    status_response = opener.open(f"{base_url}/api/cert/status", timeout=3)
                except urllib.error.HTTPError as error:
                    status_response = error
                with status_response:
                    raw_body = status_response.read().decode("utf-8")
                    try:
                        status_payload = json.loads(raw_body)
                    except json.JSONDecodeError:
                        status_payload = {"raw": raw_body}

            self.assertEqual(status_response.status, 200)
            self.assertTrue(status_payload["authenticated"])
            self.assertEqual(status_payload["username"], "valentin")
            self.assertEqual(status_payload["csrfToken"], login_payload["csrfToken"])

    def test_resetting_credentials_revokes_existing_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                )
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "valentin", "password": "mot-de-passe-solide"},
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with opener.open(login, timeout=3):
                    pass

                cert_admin.write_credentials(
                    credentials,
                    cert_admin.credential_payload("valentin", "nouveau-mot-de-passe-solide"),
                )
                with self.assertRaises(urllib.error.HTTPError) as revoked:
                    opener.open(f"{base_url}/api/cert/status", timeout=3)

            self.assertEqual(revoked.exception.code, 401)

    def test_parallel_login_failures_cannot_bypass_the_attempt_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                barrier = threading.Barrier(12)

                def invalid_login() -> int:
                    request = urllib.request.Request(
                        f"{base_url}/api/cert/login",
                        data=json.dumps(
                            {"username": "valentin", "password": "mauvais-mot-de-passe"},
                        ).encode(),
                        method="POST",
                        headers={"Content-Type": "application/json", "Origin": base_url},
                    )
                    barrier.wait(timeout=5)
                    try:
                        urllib.request.urlopen(request, timeout=8).close()
                        return 200
                    except urllib.error.HTTPError as error:
                        return error.code

                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                    statuses = list(executor.map(lambda _index: invalid_login(), range(12)))

            self.assertLessEqual(statuses.count(401), 5, statuses)
            self.assertGreaterEqual(statuses.count(429), 7, statuses)

    def test_slow_login_bodies_do_not_reserve_scrypt_slots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "correct-password"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                parsed = urllib.parse.urlsplit(base_url)
                slow_clients = []
                try:
                    for _ in range(2):
                        client = socket.create_connection((parsed.hostname, parsed.port), timeout=2)
                        client.sendall(
                            (
                                "POST /api/cert/login HTTP/1.1\r\n"
                                f"Host: {parsed.netloc}\r\n"
                                f"Origin: {base_url}\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: 4096\r\n"
                                "Connection: close\r\n\r\n"
                                '{"username":"slow'
                            ).encode("ascii"),
                        )
                        slow_clients.append(client)
                    time.sleep(0.1)

                    request = urllib.request.Request(
                        f"{base_url}/api/cert/login",
                        data=json.dumps(
                            {"username": "valentin", "password": "correct-password"},
                        ).encode(),
                        headers={"Content-Type": "application/json", "Origin": base_url},
                        method="POST",
                    )
                    with urllib.request.urlopen(request, timeout=5) as response:
                        self.assertEqual(response.status, 200)
                finally:
                    for client in slow_clients:
                        client.close()

    def test_authenticated_admin_can_validate_then_install_a_certificate_locally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            output = root / "active"
            certificate, private_key = create_self_signed(root)
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_DIRECT_INSTALL": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_OUTPUT_DIR": str(output),
                "FORTIOS_TLS_HOSTNAME": HOSTNAME,
            }
            with running_server(environment) as base_url:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                )
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "valentin", "password": "mot-de-passe-solide"},
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with opener.open(login, timeout=3) as login_response:
                    csrf_token = json.load(login_response)["csrfToken"]

                upload = {
                    "certificateBase64": base64.b64encode(certificate.read_bytes()).decode(),
                    "privateKeyBase64": base64.b64encode(private_key.read_bytes()).decode(),
                    "chainBase64": "",
                    "password": "",
                }
                validate = urllib.request.Request(
                    f"{base_url}/api/cert/validate",
                    data=json.dumps(upload).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    },
                )
                try:
                    validate_response = opener.open(validate, timeout=8)
                except urllib.error.HTTPError as error:
                    validate_response = error
                with validate_response:
                    raw_body = validate_response.read().decode("utf-8")
                    try:
                        validation = json.loads(raw_body)
                    except json.JSONDecodeError:
                        validation = {"raw": raw_body}

                self.assertEqual(validate_response.status, 200, validation)
                self.assertTrue(validation["valid"])
                self.assertEqual(validation["hostname"], HOSTNAME)
                self.assertIn("validationToken", validation)
                self.assertGreaterEqual(len(validation["validationToken"]), 32)
                self.assertFalse(output.exists(), "la validation seule ne doit rien activer")

                install_without_ticket = urllib.request.Request(
                    f"{base_url}/api/cert/install",
                    data=json.dumps(upload).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    },
                )
                with self.assertRaises(urllib.error.HTTPError) as missing_ticket:
                    opener.open(install_without_ticket, timeout=8)
                self.assertEqual(missing_ticket.exception.code, 409)
                self.assertFalse(output.exists(), "l'activation exige le ticket de prévalidation")

                upload["validationToken"] = validation["validationToken"]
                install = urllib.request.Request(
                    f"{base_url}/api/cert/install",
                    data=json.dumps(upload).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    },
                )
                with opener.open(install, timeout=8) as install_response:
                    installation = json.load(install_response)

            self.assertEqual(install_response.status, 200, installation)
            self.assertTrue(installation["installed"])
            self.assertTrue((output / "fullchain.pem").is_file())
            self.assertTrue((output / "privkey.pem").is_file())

    def test_reset_revokes_an_install_request_already_reading_its_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            output = root / "active"
            certificate, private_key = create_self_signed(root)
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_DIRECT_INSTALL": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_OUTPUT_DIR": str(output),
                "FORTIOS_TLS_HOSTNAME": HOSTNAME,
            }
            with running_server(environment) as base_url:
                cookie_jar = http.cookiejar.CookieJar()
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(cookie_jar),
                )
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "valentin", "password": "mot-de-passe-solide"},
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with opener.open(login, timeout=3) as login_response:
                    csrf_token = json.load(login_response)["csrfToken"]

                upload = {
                    "certificateBase64": base64.b64encode(certificate.read_bytes()).decode(),
                    "privateKeyBase64": base64.b64encode(private_key.read_bytes()).decode(),
                    "chainBase64": "",
                    "password": "",
                }
                validate = urllib.request.Request(
                    f"{base_url}/api/cert/validate",
                    data=json.dumps(upload).encode(),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    },
                )
                with opener.open(validate, timeout=8) as validate_response:
                    upload["validationToken"] = json.load(validate_response)["validationToken"]

                body = json.dumps(upload).encode()
                parsed = urllib.parse.urlsplit(base_url)
                cookie = "; ".join(f"{item.name}={item.value}" for item in cookie_jar)
                client = socket.create_connection((parsed.hostname, parsed.port), timeout=5)
                try:
                    headers = (
                        "POST /api/cert/install HTTP/1.1\r\n"
                        f"Host: {parsed.netloc}\r\n"
                        f"Origin: {base_url}\r\n"
                        f"Cookie: {cookie}\r\n"
                        f"X-CSRF-Token: {csrf_token}\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                    split = len(body) // 2
                    client.sendall(headers + body[:split])
                    time.sleep(0.1)
                    cert_admin.write_credentials(
                        credentials,
                        cert_admin.credential_payload("valentin", "nouveau-mot-de-passe"),
                    )
                    client.sendall(body[split:])
                    response = b""
                    while True:
                        chunk = client.recv(65536)
                        if not chunk:
                            break
                        response += chunk
                finally:
                    client.close()

            self.assertIn(b" 401 ", response.partition(b"\r\n")[0])
            self.assertFalse(output.exists())

    def test_certificate_upload_rejects_an_invalid_csrf_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_TLS_HOSTNAME": HOSTNAME,
            }
            with running_server(environment) as base_url:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                )
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "valentin", "password": "mot-de-passe-solide"},
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with opener.open(login, timeout=3):
                    pass
                upload = urllib.request.Request(
                    f"{base_url}/api/cert/validate",
                    data=b"{}",
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": "jeton-falsifie",
                    },
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    opener.open(upload, timeout=3)

            self.assertEqual(raised.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
