"""Unit tests for certificate web session primitives."""

from __future__ import annotations

import base64
import concurrent.futures
import inspect
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import cert_web  # type: ignore[import-not-found]
import fortios_server  # type: ignore[import-not-found]

from tests.test_certctl import HOSTNAME, create_self_signed


class CertificateSessionTests(unittest.TestCase):
    def test_certificate_activation_uses_the_privileged_helper_when_configured(self) -> None:
        payload = {
            "certificateBase64": "certificate",
            "privateKeyBase64": "key",
            "chainBase64": "",
            "password": "",
        }
        expected = {"hostname": HOSTNAME}
        helper_socket = Path("/run/fortios-cert-helper/helper.sock")

        with mock.patch.object(
            fortios_server,
            "install_via_helper",
            return_value=expected,
        ) as install:
            result = fortios_server.activate_uploaded_certificate(
                payload,
                HOSTNAME,
                Path("/unused/direct/output"),
                helper_socket=helper_socket,
                credentials_revision="a" * 64,
            )

        self.assertEqual(result, expected)
        install.assert_called_once_with(
            helper_socket,
            payload,
            credentials_revision="a" * 64,
        )

    def test_revoke_invalidates_an_existing_session(self) -> None:
        self.assertTrue(
            hasattr(cert_web.SessionStore, "revoke"),
            "SessionStore.revoke doit être implémenté",
        )
        store = cert_web.SessionStore()
        session_id, _ = store.create("valentin")
        self.assertIsNotNone(store.get(session_id))

        store.revoke(session_id)

        self.assertIsNone(store.get(session_id))

    def test_expired_session_is_removed(self) -> None:
        with mock.patch.object(cert_web.time, "monotonic", return_value=100.0):
            store = cert_web.SessionStore(ttl_seconds=10)
            session_id, _ = store.create("valentin")
        with mock.patch.object(cert_web.time, "monotonic", return_value=111.0):
            self.assertIsNone(store.get(session_id))

    def test_session_store_bounds_authenticated_session_memory(self) -> None:
        store = cert_web.SessionStore(ttl_seconds=60, maximum_sessions=2)
        first_id, _ = store.create("admin")
        store.create("admin")
        store.create("admin")

        self.assertLessEqual(len(store._sessions), 2)
        self.assertIsNone(store.get(first_id))

    def test_login_rate_limiter_blocks_repeated_failures_per_client(self) -> None:
        self.assertTrue(
            hasattr(cert_web, "LoginRateLimiter"),
            "cert_web.LoginRateLimiter doit être implémenté",
        )
        limiter = cert_web.LoginRateLimiter(max_failures=3, window_seconds=300)
        self.assertFalse(limiter.blocked("127.0.0.1"))
        limiter.record_failure("127.0.0.1")
        limiter.record_failure("127.0.0.1")
        self.assertFalse(limiter.blocked("127.0.0.1"))

        limiter.record_failure("127.0.0.1")

        self.assertTrue(limiter.blocked("127.0.0.1"))
        self.assertFalse(limiter.blocked("127.0.0.2"))

    def test_login_rate_limiter_bounds_unique_client_memory(self) -> None:
        self.assertIn("maximum_clients", inspect.signature(cert_web.LoginRateLimiter).parameters)
        limiter = cert_web.LoginRateLimiter(maximum_clients=2)
        limiter.record_failure("192.0.2.1")
        limiter.record_failure("192.0.2.2")
        limiter.record_failure("192.0.2.3")

        self.assertLessEqual(len(limiter._failures), 2)

    def test_login_rate_limiter_reserves_scrypt_slots_atomically(self) -> None:
        self.assertTrue(hasattr(cert_web.LoginRateLimiter, "try_begin"))
        limiter = cert_web.LoginRateLimiter(
            max_failures=5,
            maximum_clients=16,
            maximum_concurrent=2,
        )

        self.assertTrue(limiter.try_begin("192.0.2.10"))
        self.assertTrue(limiter.try_begin("192.0.2.10"))
        self.assertFalse(limiter.try_begin("192.0.2.10"), "le plafond global doit inclure les calculs en cours")
        limiter.finish("192.0.2.10", success=False)
        limiter.finish("192.0.2.10", success=False)
        self.assertTrue(limiter.try_begin("192.0.2.10"))
        limiter.finish("192.0.2.10", success=False)

    def test_web_upload_bridge_accepts_a_password_protected_pfx(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            certificate, private_key = create_self_signed(root)
            bundle = root / "certificate.pfx"
            result = subprocess.run(
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-out",
                    str(bundle),
                    "-inkey",
                    str(private_key),
                    "-in",
                    str(certificate),
                    "-passout",
                    "pass:test-password",
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            output = root / "active"

            written_names: list[str] = []
            original_write_private = cert_web._write_private

            def recording_write(path: Path, data: bytes) -> None:
                written_names.append(path.name)
                original_write_private(path, data)

            with mock.patch.object(cert_web, "_write_private", side_effect=recording_write):
                summary = cert_web.install_uploaded_certificate(
                    {
                        "certificateBase64": base64.b64encode(bundle.read_bytes()).decode(),
                        "privateKeyBase64": "",
                        "chainBase64": "",
                        "password": "test-password",
                    },
                    HOSTNAME,
                    output,
                )

            self.assertEqual(summary["hostname"], HOSTNAME)
            self.assertTrue((output / "fullchain.pem").is_file())
            self.assertTrue((output / "privkey.pem").is_file())
            self.assertNotIn("password", written_names)

    def test_concurrent_install_summaries_describe_each_uploaded_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_dir = root / "first"
            second_dir = root / "second"
            first_dir.mkdir()
            second_dir.mkdir()
            first_cert, first_key = create_self_signed(first_dir)
            second_cert, second_key = create_self_signed(second_dir)
            output = root / "active"

            def payload(certificate: Path, private_key: Path) -> dict[str, str]:
                return {
                    "certificateBase64": base64.b64encode(certificate.read_bytes()).decode(),
                    "privateKeyBase64": base64.b64encode(private_key.read_bytes()).decode(),
                    "chainBase64": "",
                    "password": "",
                }

            def fingerprint(certificate: Path) -> str:
                value = cert_web.certctl.run_openssl(
                    "x509",
                    "-in",
                    str(certificate),
                    "-noout",
                    "-fingerprint",
                    "-sha256",
                ).stdout
                return value.decode("ascii").strip().partition("=")[2]

            expected = [fingerprint(first_cert), fingerprint(second_cert)]

            barrier = threading.Barrier(2)
            original_summary = cert_web.certificate_summary

            def synchronized_summary(directory: Path, hostname: str):
                barrier.wait(timeout=10)
                return original_summary(directory, hostname)

            with (
                mock.patch.object(cert_web, "certificate_summary", side_effect=synchronized_summary),
                concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,
            ):
                futures = [
                    executor.submit(cert_web.install_uploaded_certificate, payload(cert, key), HOSTNAME, output)
                    for cert, key in ((first_cert, first_key), (second_cert, second_key))
                ]
                summaries = [future.result(timeout=15) for future in futures]

            self.assertNotEqual(
                summaries[0]["sha256Fingerprint"],
                summaries[1]["sha256Fingerprint"],
            )
            self.assertEqual(
                [summary["sha256Fingerprint"] for summary in summaries],
                expected,
            )

    def test_web_cleanup_failure_after_activation_is_only_a_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            certificate, private_key = create_self_signed(root)
            output = root / "active"
            payload = {
                "certificateBase64": base64.b64encode(certificate.read_bytes()).decode(),
                "privateKeyBase64": base64.b64encode(private_key.read_bytes()).decode(),
                "chainBase64": "",
                "password": "",
            }

            with mock.patch.object(
                cert_web,
                "_remove_temporary_directory",
                side_effect=OSError("simulated cleanup failure"),
            ):
                summary = cert_web.install_uploaded_certificate(payload, HOSTNAME, output)

            self.assertEqual(summary["hostname"], HOSTNAME)
            self.assertTrue((output / "fullchain.pem").is_file())
            self.assertTrue((output / "privkey.pem").is_file())

    def test_validation_ticket_is_bound_to_one_session_payload_and_use(self) -> None:
        self.assertTrue(
            hasattr(cert_web, "ValidationTicketStore"),
            "cert_web.ValidationTicketStore doit être implémenté",
        )
        store = cert_web.ValidationTicketStore(ttl_seconds=60)
        payload = {
            "certificateBase64": "Y2VydGlmaWNhdA==",
            "privateKeyBase64": "Y2xl",
            "chainBase64": "",
            "password": "",
        }
        ticket = store.issue("session-a", payload)

        self.assertFalse(store.consume(ticket, "session-b", payload))
        self.assertFalse(store.consume(ticket, "session-a", {**payload, "password": "modifie"}))
        self.assertTrue(store.consume(ticket, "session-a", payload))
        self.assertFalse(store.consume(ticket, "session-a", payload), "un ticket doit être à usage unique")

    def test_email_preview_store_is_session_bound_short_lived_and_memory_bounded(self) -> None:
        with mock.patch.object(cert_web.time, "monotonic", return_value=100.0):
            store = cert_web.EmailPreviewStore(ttl_seconds=10, maximum=2)
            first = store.issue("session-a", "<p>first</p>")
            second = store.issue("session-a", "<p>second</p>")
            third = store.issue("session-a", "<p>third</p>")
            self.assertIsNone(store.get(first, "session-a"))
            self.assertIsNone(store.get(second, "session-b"))
            self.assertEqual(store.get(second, "session-a"), "<p>second</p>")
            self.assertEqual(store.get(third, "session-a"), "<p>third</p>")
            self.assertLessEqual(len(store._documents), 2)

        with mock.patch.object(cert_web.time, "monotonic", return_value=111.0):
            self.assertIsNone(store.get(second, "session-a"))

    def test_uploaded_base64_is_strictly_decoded_and_size_limited(self) -> None:
        with self.assertRaises(cert_web.certctl.CertificateError):
            cert_web._decode_upload({"certificate": "%%%"}, "certificate", 10)
        with self.assertRaises(cert_web.certctl.CertificateError):
            cert_web._decode_upload(
                {"certificate": base64.b64encode(b"1234").decode()},
                "certificate",
                3,
            )


if __name__ == "__main__":
    unittest.main()
