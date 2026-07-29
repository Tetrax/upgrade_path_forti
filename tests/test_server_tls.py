"""End-to-end TLS coverage for scripts/fortios_server.py."""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "scripts" / "fortios_server.py"
HEALTHCHECK = ROOT / "scripts" / "container_healthcheck.py"
HOSTNAME = "upgrade-path.sns-security.lan"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def create_certificate(directory: Path) -> tuple[Path, Path]:
    cert = directory / "fullchain.pem"
    key = directory / "privkey.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "30",
            "-subj", f"/CN={HOSTNAME}",
            "-addext", f"subjectAltName=DNS:{HOSTNAME}",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


class ServerTlsTests(unittest.TestCase):
    def test_serves_application_over_tls_when_certificate_is_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = create_certificate(Path(tmp))
            port = free_port()
            process = subprocess.Popen(
                [
                    sys.executable, str(SERVER), "--host", "127.0.0.1",
                    "--port", str(port), "--tls-cert", str(cert),
                    "--tls-key", str(key),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            context = ssl._create_unverified_context()
            url = f"https://127.0.0.1:{port}/app/"
            try:
                deadline = time.monotonic() + 5
                last_error: Exception | None = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        output = process.stdout.read() if process.stdout else ""
                        self.fail(f"server exited early ({process.returncode}): {output}")
                    try:
                        with urllib.request.urlopen(url, context=context, timeout=0.5) as response:
                            self.assertEqual(response.status, 200)
                            self.assertIn(b"FortiOS", response.read())
                            break
                    except Exception as error:  # noqa: BLE001 - readiness retry
                        last_error = error
                        time.sleep(0.05)
                else:
                    self.fail(f"TLS server was not ready: {last_error}")

                with self.assertRaises(Exception):
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/app/", timeout=1)

                health = subprocess.run(
                    [sys.executable, str(HEALTHCHECK)],
                    cwd=ROOT,
                    env={
                        **os.environ,
                        "FORTIOS_TLS_CERT": str(cert),
                        "FORTIOS_TLS_KEY": str(key),
                        "FORTIOS_TLS_HOSTNAME": HOSTNAME,
                        "FORTIOS_HEALTHCHECK_PORT": str(port),
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(health.returncode, 0, health.stderr)

            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                if process.stdout:
                    process.stdout.close()

    def test_serves_plain_http_when_tls_is_not_configured(self) -> None:
        port = free_port()
        process = subprocess.Popen(
            [
                sys.executable, str(SERVER), "--host", "127.0.0.1",
                "--port", str(port),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/app/", timeout=0.5,
                    ) as response:
                        self.assertEqual(response.status, 200)
                        break
                except Exception:
                    time.sleep(0.05)
            else:
                self.fail("HTTP server was not ready")

            environment = {
                key: value
                for key, value in os.environ.items()
                if key not in {"FORTIOS_TLS_CERT", "FORTIOS_TLS_KEY", "FORTIOS_TLS_HOSTNAME"}
            }
            environment["FORTIOS_HEALTHCHECK_PORT"] = str(port)
            health = subprocess.run(
                [sys.executable, str(HEALTHCHECK)], cwd=ROOT, env=environment,
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(health.returncode, 0, health.stderr)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
