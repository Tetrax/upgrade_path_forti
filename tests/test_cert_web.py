"""HTTP integration tests for the private certificate administration page."""

from __future__ import annotations

import atexit
import base64
import concurrent.futures
import http.cookiejar
import json
import os
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
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "scripts" / "fortios_server.py"
PASSWORD_SERVER_TEMPORARIES: list[tempfile.TemporaryDirectory[str]] = []
sys.path.insert(0, str(ROOT / "scripts"))
import cert_admin  # type: ignore[import-not-found]
import cert_helper  # type: ignore[import-not-found]

from tests.test_certctl import HOSTNAME, create_self_signed


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
            except urllib.error.URLError:
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


@contextmanager
def running_password_server(
    password: str = "mot-de-passe-actuel",
) -> Iterator[tuple[str, Path]]:
    temporary = tempfile.TemporaryDirectory()
    PASSWORD_SERVER_TEMPORARIES.append(temporary)
    credentials = Path(temporary.name) / "credentials.json"
    cert_admin.write_credentials(
        credentials,
        cert_admin.credential_payload("admin", password),
    )
    environment = {
        "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
        "FORTIOS_CERT_ADMIN_FILE": str(credentials),
    }
    with running_server(environment) as base_url:
        yield base_url, credentials


@atexit.register
def cleanup_password_server_temporaries() -> None:
    while PASSWORD_SERVER_TEMPORARIES:
        PASSWORD_SERVER_TEMPORARIES.pop().cleanup()


def post_setup(
    base_url: str,
    *,
    username: str = "admin",
    password: str = "premier-mot-de-passe",
    confirmation: str | None = None,
    opener: urllib.request.OpenerDirector | None = None,
) -> tuple[int, dict[str, object], str]:
    request = urllib.request.Request(
        f"{base_url}/api/cert/setup",
        data=json.dumps(
            {
                "username": username,
                "password": password,
                "passwordConfirmation": password if confirmation is None else confirmation,
            }
        ).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Origin": base_url},
    )
    client = opener or urllib.request.build_opener()
    try:
        with client.open(request, timeout=8) as response:
            return response.status, json.load(response), response.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as error:
        with error:
            return error.code, json.load(error), error.headers.get("Set-Cookie", "")


def login_admin(
    base_url: str,
    username: str,
    password: str,
    *,
    opener: urllib.request.OpenerDirector | None = None,
) -> tuple[int, dict[str, object], str]:
    request = urllib.request.Request(
        f"{base_url}/api/cert/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Origin": base_url},
    )
    client = opener or urllib.request.build_opener()
    try:
        with client.open(request, timeout=8) as response:
            return response.status, json.load(response), response.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as error:
        with error:
            return error.code, json.load(error), error.headers.get("Set-Cookie", "")


def post_password_change(
    base_url: str,
    opener: urllib.request.OpenerDirector,
    csrf_token: str,
    *,
    current_password: str,
    new_password: str,
    confirmation: str | None = None,
    origin: str | None = None,
) -> tuple[int, dict[str, object], str]:
    request = urllib.request.Request(
        f"{base_url}/api/cert/password",
        data=json.dumps(
            {
                "currentPassword": current_password,
                "newPassword": new_password,
                "confirmation": new_password if confirmation is None else confirmation,
            }
        ).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Origin": base_url if origin is None else origin,
            "X-CSRF-Token": csrf_token,
        },
    )
    try:
        with opener.open(request, timeout=8) as response:
            return response.status, json.load(response), response.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as error:
        with error:
            content_type = error.headers.get_content_type()
            payload = json.load(error) if content_type == "application/json" else {"error": error.reason}
            return error.code, payload, error.headers.get("Set-Cookie", "")


class CertificateWebTests(unittest.TestCase):
    def test_certificate_page_is_hidden_on_plain_http_by_default(self) -> None:
        with running_server({}) as base_url:
            for path in ("/cert/", "/app/cert/"):
                with self.subTest(path=path):
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        urllib.request.urlopen(f"{base_url}{path}", timeout=2)

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
            self.assertIn("Administration", body)
            self.assertIn("Certificats", body)
            self.assertIn('id="login-form"', body)

    def test_certificate_page_contains_the_first_run_account_form(self) -> None:
        with running_server({"FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1"}) as base_url:
            with urllib.request.urlopen(f"{base_url}/cert/", timeout=2) as response:
                body = response.read().decode("utf-8")
            with urllib.request.urlopen(f"{base_url}/cert/cert.js", timeout=2) as response:
                script = response.read().decode("utf-8")

        self.assertIn("Première configuration", body)
        self.assertIn('id="setup-form"', body)
        self.assertIn('id="setup-username"', body)
        self.assertIn('value="admin"', body)
        self.assertIn('id="setup-password-confirmation"', body)
        self.assertIn('apiRequest("setup"', script)

    def test_new_install_without_admin_directory_requires_web_setup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "missing-admin" / "credentials.json"
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with (
                running_server(environment) as base_url,
                urllib.request.urlopen(
                    f"{base_url}/api/cert/status", timeout=3
                ) as response,
            ):
                payload = json.load(response)

            self.assertEqual(response.status, 200)
            self.assertFalse(payload["authenticated"])
            self.assertTrue(payload["setupRequired"])
            self.assertFalse(credentials.parent.exists())

    def test_web_setup_creates_first_account_and_authenticated_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                )
                status, setup_payload, cookie = post_setup(base_url, opener=opener)
                with opener.open(f"{base_url}/api/cert/status", timeout=3) as response:
                    status_payload = json.load(response)

            self.assertEqual(status, 200, setup_payload)
            self.assertTrue(setup_payload["authenticated"])
            self.assertIn("fortios_cert_session=", cookie)
            self.assertTrue(status_payload["authenticated"])
            self.assertEqual(status_payload["username"], "admin")
            self.assertTrue(
                cert_admin.verify_credentials(
                    credentials, "admin", "premier-mot-de-passe"
                )
            )

    def test_second_web_setup_is_refused_without_replacing_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                self.assertEqual(post_setup(base_url)[0], 200)
                self.assertEqual(post_setup(base_url, password="second-mot-de-passe")[0], 409)

            self.assertTrue(
                cert_admin.verify_credentials(
                    credentials, "admin", "premier-mot-de-passe"
                )
            )
            self.assertFalse(
                cert_admin.verify_credentials(
                    credentials, "admin", "second-mot-de-passe"
                )
            )

    def test_web_setup_preserves_username_password_and_confirmation_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                self.assertEqual(post_setup(base_url, username="admin invalide")[0], 400)
                self.assertEqual(post_setup(base_url, password="onze-octets", confirmation="différent")[0], 400)
                self.assertEqual(post_setup(base_url, password="court")[0], 400)
                self.assertEqual(post_setup(base_url, password="😀😀😀")[0], 200)

            self.assertTrue(cert_admin.verify_credentials(credentials, "admin", "😀😀😀"))

    def test_two_concurrent_web_setups_create_exactly_one_account(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                barrier = threading.Barrier(2)

                def setup(password: str) -> int:
                    barrier.wait(timeout=5)
                    return post_setup(base_url, password=password)[0]

                passwords = ("premier-mot-de-passe", "second-mot-de-passe")
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    statuses = list(executor.map(setup, passwords))

            self.assertEqual(sorted(statuses), [200, 409], statuses)
            accepted = [
                password
                for password in passwords
                if cert_admin.verify_credentials(credentials, "admin", password)
            ]
            self.assertEqual(len(accepted), 1)

    def test_corrupt_credentials_never_reenable_anonymous_setup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            credentials.parent.mkdir()
            credentials.write_text("{corrompu", encoding="utf-8")
            original = credentials.read_bytes()
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(f"{base_url}/api/cert/status", timeout=3)
                with raised.exception as response:
                    status_payload = json.load(response)
                setup_status = post_setup(base_url)[0]

            self.assertEqual(raised.exception.code, 503)
            self.assertFalse(status_payload["setupRequired"])
            self.assertIn("administrateur", status_payload["error"])
            self.assertEqual(setup_status, 409)
            self.assertEqual(credentials.read_bytes(), original)

    def test_existing_installation_recreates_lock_without_changing_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "admin" / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-original"),
            )
            original = credentials.read_bytes()
            lock_path = cert_admin.credential_lock_path(credentials)
            lock_path.unlink()
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                login = urllib.request.Request(
                    f"{base_url}/api/cert/login",
                    data=json.dumps(
                        {"username": "admin", "password": "mot-de-passe-original"}
                    ).encode(),
                    method="POST",
                    headers={"Content-Type": "application/json", "Origin": base_url},
                )
                with urllib.request.urlopen(login, timeout=5) as response:
                    payload = json.load(response)

            self.assertEqual(response.status, 200, payload)
            self.assertTrue(lock_path.is_file())
            self.assertEqual(credentials.read_bytes(), original)
            self.assertTrue(
                cert_admin.verify_credentials(
                    credentials, "admin", "mot-de-passe-original"
                )
            )

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

    def test_trusted_reverse_proxy_https_enables_login_and_secure_cookie(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
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
                        "Host": "fortiupgrade.example",
                        "Origin": "https://fortiupgrade.example",
                        "X-Forwarded-Proto": "https",
                        "X-Real-IP": "198.51.100.7",
                    },
                )
                with urllib.request.urlopen(request, timeout=3) as response:
                    cookie = response.headers.get("Set-Cookie", "")
                    hsts = response.headers.get("Strict-Transport-Security", "")

            self.assertIn("Secure", cookie)
            self.assertEqual(hsts, "max-age=31536000")

    def test_trusted_proxy_rate_limits_the_forwarded_client_not_the_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            environment = {
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
            }
            with running_server(environment) as base_url:
                def login(password: str, client_ip: str):
                    return urllib.request.urlopen(
                        urllib.request.Request(
                            f"{base_url}/api/cert/login",
                            data=json.dumps(
                                {"username": "valentin", "password": password},
                            ).encode(),
                            method="POST",
                            headers={
                                "Content-Type": "application/json",
                                "Host": "fortiupgrade.example",
                                "Origin": "https://fortiupgrade.example",
                                "X-Forwarded-Proto": "https",
                                "X-Real-IP": client_ip,
                            },
                        ),
                        timeout=3,
                    )

                for _ in range(5):
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        login("mauvais-mot-de-passe", "198.51.100.7")
                    self.assertEqual(raised.exception.code, 401)

                with login("mot-de-passe-solide", "198.51.100.8") as response:
                    payload = json.load(response)

            self.assertTrue(payload["authenticated"])

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

    def test_password_rotation_invalidates_all_sessions_and_replaces_the_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-actuel"),
            )
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
            }
            with running_server(environment) as base_url:
                openers = [
                    urllib.request.build_opener(
                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
                    )
                    for _ in range(2)
                ]
                sessions = [
                    login_admin(
                        base_url,
                        "admin",
                        "mot-de-passe-actuel",
                        opener=opener,
                    )
                    for opener in openers
                ]
                self.assertTrue(all(status == 200 for status, _, _ in sessions), sessions)

                status, payload, cookie = post_password_change(
                    base_url,
                    openers[0],
                    str(sessions[0][1]["csrfToken"]),
                    current_password="mot-de-passe-actuel",
                    new_password="nouveau-mot-de-passe",
                )

                revoked_statuses = []
                for opener in openers:
                    try:
                        opener.open(f"{base_url}/api/cert/status", timeout=3).close()
                        revoked_statuses.append(200)
                    except urllib.error.HTTPError as error:
                        revoked_statuses.append(error.code)
                old_status = login_admin(
                    base_url,
                    "admin",
                    "mot-de-passe-actuel",
                )[0]
                new_status = login_admin(
                    base_url,
                    "admin",
                    "nouveau-mot-de-passe",
                )[0]

            self.assertEqual(status, 200, payload)
            self.assertEqual(payload["message"], "Mot de passe modifié.")
            self.assertIn("Max-Age=0", cookie)
            self.assertEqual(revoked_statuses, [401, 401])
            self.assertEqual(old_status, 401)
            self.assertEqual(new_status, 200)

    def test_password_rotation_requires_an_authenticated_session(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            status, _payload, _cookie = post_password_change(
                base_url,
                opener,
                "missing-session-token",
                current_password="mot-de-passe-actuel",
                new_password="nouveau-mot-de-passe",
            )

        self.assertEqual(status, 401)
        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_rejects_an_invalid_csrf_token(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            login_status, _login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            self.assertEqual(login_status, 200)
            status, _payload, _cookie = post_password_change(
                base_url,
                opener,
                "invalid-csrf-token",
                current_password="mot-de-passe-actuel",
                new_password="nouveau-mot-de-passe",
            )

        self.assertEqual(status, 403)
        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_rejects_an_invalid_origin(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            login_status, login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            self.assertEqual(login_status, 200)
            status, _payload, _cookie = post_password_change(
                base_url,
                opener,
                str(login_payload["csrfToken"]),
                current_password="mot-de-passe-actuel",
                new_password="nouveau-mot-de-passe",
                origin="https://invalid.example",
            )

        self.assertEqual(status, 403)
        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_bounds_invalid_json_requests(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            login_status, login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            self.assertEqual(login_status, 200)
            for body in (b"{", b"[]"):
                with self.subTest(body=body):
                    request = urllib.request.Request(
                        f"{base_url}/api/cert/password",
                        data=body,
                        method="POST",
                        headers={
                            "Content-Type": "application/json",
                            "Origin": base_url,
                            "X-CSRF-Token": str(login_payload["csrfToken"]),
                        },
                    )
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        opener.open(request, timeout=3)
                    with raised.exception:
                        self.assertEqual(raised.exception.code, 400)
                        self.assertEqual(
                            json.load(raised.exception)["error"],
                            "Requête de rotation invalide.",
                        )
            with opener.open(f"{base_url}/api/cert/status", timeout=3) as response:
                self.assertEqual(response.status, 200)

        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_rejects_an_incorrect_current_password(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            login_status, login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            self.assertEqual(login_status, 200)
            status, payload, _cookie = post_password_change(
                base_url,
                opener,
                str(login_payload["csrfToken"]),
                current_password="mot-de-passe-incorrect",
                new_password="nouveau-mot-de-passe",
            )
            with opener.open(f"{base_url}/api/cert/status", timeout=3) as response:
                session_status = response.status

        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "Mot de passe actuel incorrect.")
        self.assertEqual(session_status, 200)
        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_rejects_a_mismatched_confirmation(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            _status, login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            status, payload, _cookie = post_password_change(
                base_url,
                opener,
                str(login_payload["csrfToken"]),
                current_password="mot-de-passe-actuel",
                new_password="nouveau-mot-de-passe",
                confirmation="confirmation-differente",
            )

        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "Les mots de passe ne correspondent pas.")
        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_rejects_a_short_new_password(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            _status, login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            status, payload, _cookie = post_password_change(
                base_url,
                opener,
                str(login_payload["csrfToken"]),
                current_password="mot-de-passe-actuel",
                new_password="court",
            )

        self.assertEqual(status, 400)
        self.assertIn("entre 12 et 1024 octets UTF-8", str(payload["error"]))
        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_rejects_a_long_new_password(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            _status, login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            status, payload, _cookie = post_password_change(
                base_url,
                opener,
                str(login_payload["csrfToken"]),
                current_password="mot-de-passe-actuel",
                new_password="é" * 513,
            )

        self.assertEqual(status, 400)
        self.assertIn("entre 12 et 1024 octets UTF-8", str(payload["error"]))
        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_rejects_the_current_password_as_the_new_password(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            _status, login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            status, payload, _cookie = post_password_change(
                base_url,
                opener,
                str(login_payload["csrfToken"]),
                current_password="mot-de-passe-actuel",
                new_password="mot-de-passe-actuel",
            )

        self.assertEqual(status, 400)
        self.assertEqual(
            payload["error"],
            "Le nouveau mot de passe doit être différent du mot de passe actuel.",
        )
        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_fails_closed_when_credentials_are_corrupted(self) -> None:
        with running_password_server() as (base_url, credentials):
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            _status, login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            corrupted = b'{"username":"admin"}\n'
            credentials.write_bytes(corrupted)
            status, payload, _cookie = post_password_change(
                base_url,
                opener,
                str(login_payload["csrfToken"]),
                current_password="mot-de-passe-actuel",
                new_password="nouveau-mot-de-passe",
            )
            after = credentials.read_bytes()

        self.assertEqual(status, 503)
        self.assertEqual(payload["error"], "Compte administrateur indisponible.")
        self.assertEqual(after, corrupted)

    def test_two_concurrent_password_rotations_cannot_both_succeed(self) -> None:
        with running_password_server() as (base_url, _credentials):
            openers = [
                urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
                )
                for _ in range(2)
            ]
            sessions = [
                login_admin(
                    base_url,
                    "admin",
                    "mot-de-passe-actuel",
                    opener=opener,
                )
                for opener in openers
            ]
            self.assertTrue(all(status == 200 for status, _, _ in sessions), sessions)
            barrier = threading.Barrier(2)
            replacements = ("nouveau-mot-de-passe-a", "nouveau-mot-de-passe-b")

            def rotate(index: int) -> tuple[int, str]:
                barrier.wait(timeout=5)
                status, _payload, _cookie = post_password_change(
                    base_url,
                    openers[index],
                    str(sessions[index][1]["csrfToken"]),
                    current_password="mot-de-passe-actuel",
                    new_password=replacements[index],
                )
                return status, replacements[index]

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(rotate, range(2)))

            winners = [password for status, password in results if status == 200]
            losers = [password for status, password in results if status != 200]
            old_status = login_admin(base_url, "admin", "mot-de-passe-actuel")[0]
            winner_status = login_admin(base_url, "admin", winners[0])[0]
            loser_status = login_admin(base_url, "admin", losers[0])[0]

        self.assertEqual(len(winners), 1, results)
        self.assertEqual(len(losers), 1, results)
        self.assertIn(next(status for status, _password in results if status != 200), (401, 409))
        self.assertEqual(old_status, 401)
        self.assertEqual(winner_status, 200)
        self.assertEqual(loser_status, 401)

    def test_password_rotation_rate_limits_incorrect_current_password_attempts(self) -> None:
        with running_password_server() as (base_url, credentials):
            original = credentials.read_bytes()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
            _status, login_payload, _cookie = login_admin(
                base_url,
                "admin",
                "mot-de-passe-actuel",
                opener=opener,
            )
            statuses = [
                post_password_change(
                    base_url,
                    opener,
                    str(login_payload["csrfToken"]),
                    current_password="mot-de-passe-incorrect",
                    new_password="nouveau-mot-de-passe",
                )[0]
                for _ in range(4)
            ]

        self.assertEqual(statuses, [400, 400, 400, 429])
        self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_reports_an_unavailable_helper_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-actuel"),
            )
            original = credentials.read_bytes()
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_HELPER_SOCKET": str(root / "missing-helper.sock"),
            }
            with running_server(environment) as base_url:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
                )
                _status, login_payload, _cookie = login_admin(
                    base_url,
                    "admin",
                    "mot-de-passe-actuel",
                    opener=opener,
                )
                status, payload, _cookie = post_password_change(
                    base_url,
                    opener,
                    str(login_payload["csrfToken"]),
                    current_password="mot-de-passe-actuel",
                    new_password="nouveau-mot-de-passe",
                )

            self.assertEqual(status, 503)
            self.assertEqual(payload["error"], "Compte administrateur indisponible.")
            self.assertEqual(credentials.read_bytes(), original)

    def test_password_rotation_bounds_an_invalid_helper_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "mot-de-passe-actuel"),
            )
            original = credentials.read_bytes()
            output = root / "active"
            output.mkdir()
            socket_path = root / "run" / "helper.sock"
            socket_path.parent.mkdir()
            processor = cert_helper.CertificateInstallProcessor(
                hostname=HOSTNAME,
                output_dir=output,
                credentials_file=credentials,
                allowed_uid=os.getuid(),
                allowed_gid=os.getgid(),
            )
            processor.process = lambda *_args, **_kwargs: {"ok": True}  # type: ignore[method-assign]
            helper_server = cert_helper.CertificateHelperServer(socket_path, processor)
            helper_thread = threading.Thread(target=helper_server.serve_forever, daemon=True)
            helper_thread.start()
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_HELPER_SOCKET": str(socket_path),
                "FORTIOS_TLS_HOSTNAME": HOSTNAME,
            }
            try:
                with running_server(environment) as base_url:
                    opener = urllib.request.build_opener(
                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
                    )
                    login_status, login_payload, _cookie = login_admin(
                        base_url,
                        "admin",
                        "mot-de-passe-actuel",
                        opener=opener,
                    )
                    self.assertEqual(login_status, 200)
                    status, payload, _cookie = post_password_change(
                        base_url,
                        opener,
                        str(login_payload["csrfToken"]),
                        current_password="mot-de-passe-actuel",
                        new_password="nouveau-mot-de-passe",
                    )
                    with opener.open(f"{base_url}/api/cert/status", timeout=3) as response:
                        self.assertEqual(response.status, 200)
            finally:
                helper_server.shutdown()
                helper_server.server_close()
                helper_thread.join(timeout=3)

            self.assertEqual(status, 503)
            self.assertEqual(payload["error"], "Compte administrateur indisponible.")
            self.assertEqual(credentials.read_bytes(), original)

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

    def test_authenticated_admin_can_install_through_the_unix_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            output = root / "active"
            certificate, private_key = create_self_signed(root)
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("valentin", "mot-de-passe-solide"),
            )
            socket_path = root / "run" / "helper.sock"
            socket_path.parent.mkdir()
            processor = cert_helper.CertificateInstallProcessor(
                hostname=HOSTNAME,
                output_dir=output,
                credentials_file=credentials,
                allowed_uid=os.getuid(),
                allowed_gid=os.getgid(),
            )
            helper_server = cert_helper.CertificateHelperServer(socket_path, processor)
            helper_thread = threading.Thread(target=helper_server.serve_forever, daemon=True)
            helper_thread.start()
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_HELPER_SOCKET": str(socket_path),
                "FORTIOS_TLS_HOSTNAME": HOSTNAME,
            }
            try:
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
                    headers = {
                        "Content-Type": "application/json",
                        "Origin": base_url,
                        "X-CSRF-Token": csrf_token,
                    }
                    validate = urllib.request.Request(
                        f"{base_url}/api/cert/validate",
                        data=json.dumps(upload).encode(),
                        method="POST",
                        headers=headers,
                    )
                    with opener.open(validate, timeout=8) as validate_response:
                        validation = json.load(validate_response)

                    upload["validationToken"] = validation["validationToken"]
                    install = urllib.request.Request(
                        f"{base_url}/api/cert/install",
                        data=json.dumps(upload).encode(),
                        method="POST",
                        headers=headers,
                    )
                    with opener.open(install, timeout=8) as install_response:
                        installation = json.load(install_response)
            finally:
                helper_server.shutdown()
                helper_server.server_close()
                helper_thread.join(timeout=3)

            self.assertTrue(installation["installed"])
            self.assertFalse(installation["restartRequired"])
            self.assertTrue((output / "fullchain.pem").is_file())
            self.assertTrue((output / "privkey.pem").is_file())

    def test_web_setup_uses_the_helper_without_touching_active_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "admin" / "credentials.json"
            output = root / "active"
            output.mkdir()
            (output / "fullchain.pem").write_bytes(b"existing-certificate")
            (output / "privkey.pem").write_bytes(b"existing-private-key")
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            socket_path = root / "run" / "helper.sock"
            socket_path.parent.mkdir()
            processor = cert_helper.CertificateInstallProcessor(
                hostname=HOSTNAME,
                output_dir=output,
                credentials_file=credentials,
                allowed_uid=os.getuid(),
                allowed_gid=os.getgid(),
            )
            setup_seen = threading.Event()
            original_process = processor.process

            def record_process(
                message: dict[str, object], *, peer_uid: int, peer_gid: int
            ) -> dict[str, object]:
                if message.get("action") == "setup":
                    setup_seen.set()
                return original_process(message, peer_uid=peer_uid, peer_gid=peer_gid)

            processor.process = record_process  # type: ignore[method-assign]
            helper_server = cert_helper.CertificateHelperServer(socket_path, processor)
            helper_thread = threading.Thread(target=helper_server.serve_forever, daemon=True)
            helper_thread.start()
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_HELPER_SOCKET": str(socket_path),
                "FORTIOS_TLS_HOSTNAME": HOSTNAME,
            }
            try:
                with running_server(environment) as base_url:
                    opener = urllib.request.build_opener(
                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                    )
                    status, payload, _ = post_setup(base_url, opener=opener)
                    second_status = post_setup(
                        base_url,
                        password="second-mot-de-passe",
                    )[0]
                    with opener.open(f"{base_url}/api/cert/status", timeout=3) as response:
                        authenticated = json.load(response)
            finally:
                helper_server.shutdown()
                helper_server.server_close()
                helper_thread.join(timeout=3)

            self.assertEqual(status, 200, payload)
            self.assertEqual(second_status, 409)
            self.assertTrue(setup_seen.is_set())
            self.assertTrue(authenticated["authenticated"])
            self.assertTrue(
                cert_admin.verify_credentials(
                    credentials,
                    "admin",
                    "premier-mot-de-passe",
                )
            )
            self.assertEqual(
                {path.name: path.read_bytes() for path in output.iterdir()},
                before,
            )

    def test_password_rotation_uses_the_helper_without_touching_active_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "admin" / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "current-password"),
            )
            output = root / "active"
            output.mkdir()
            (output / "fullchain.pem").write_bytes(b"existing-certificate")
            (output / "privkey.pem").write_bytes(b"existing-private-key")
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            socket_path = root / "run" / "helper.sock"
            socket_path.parent.mkdir()
            processor = cert_helper.CertificateInstallProcessor(
                hostname=HOSTNAME,
                output_dir=output,
                credentials_file=credentials,
                allowed_uid=os.getuid(),
                allowed_gid=os.getgid(),
            )
            helper_server = cert_helper.CertificateHelperServer(socket_path, processor)
            helper_thread = threading.Thread(target=helper_server.serve_forever, daemon=True)
            helper_thread.start()
            environment = {
                "FORTIOS_CERT_ALLOW_INSECURE_LOCALHOST": "1",
                "FORTIOS_CERT_ADMIN_FILE": str(credentials),
                "FORTIOS_CERT_HELPER_SOCKET": str(socket_path),
                "FORTIOS_TLS_HOSTNAME": HOSTNAME,
            }
            try:
                with running_server(environment) as base_url:
                    opener = urllib.request.build_opener(
                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
                    )
                    login_status, login_payload, _ = login_admin(
                        base_url,
                        "admin",
                        "current-password",
                        opener=opener,
                    )
                    self.assertEqual(login_status, 200, login_payload)
                    status, payload, _ = post_password_change(
                        base_url,
                        opener,
                        str(login_payload["csrfToken"]),
                        current_password="current-password",
                        new_password="replacement-password",
                    )
            finally:
                helper_server.shutdown()
                helper_server.server_close()
                helper_thread.join(timeout=3)

            self.assertEqual(status, 200, payload)
            self.assertFalse(
                cert_admin.verify_credentials(credentials, "admin", "current-password")
            )
            self.assertTrue(
                cert_admin.verify_credentials(credentials, "admin", "replacement-password")
            )
            self.assertEqual(
                {path.name: path.read_bytes() for path in output.iterdir()},
                before,
            )

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
