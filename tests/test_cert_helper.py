"""Security and integration tests for the privileged certificate helper."""

from __future__ import annotations

import base64
import importlib
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.test_certctl import HOSTNAME, create_self_signed

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


class CertificateHelperProtocolTests(unittest.TestCase):
    def test_decoder_rejects_duplicate_keys_and_non_json_constants(self) -> None:
        protocol = importlib.import_module("cert_helper_protocol")
        invalid_documents = (
            b'{"version":1,"action":"exec","action":"ping"}',
            b'{"version":1,"action":"ping","value":NaN}',
            b'{"version":1,"action":"ping","value":Infinity}',
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                sender, receiver = socket.socketpair()
                try:
                    sender.sendall(protocol.HEADER.pack(len(document)) + document)
                    with self.assertRaises(protocol.ProtocolError):
                        protocol.receive_message(receiver, maximum_bytes=1024)
                finally:
                    sender.close()
                    receiver.close()

        sender, receiver = socket.socketpair()
        try:
            with self.assertRaises(protocol.ProtocolError):
                protocol.send_message(
                    sender,
                    {"value": float("nan")},
                    maximum_bytes=1024,
                )
        finally:
            sender.close()
            receiver.close()

    def test_protocol_round_trip_is_length_prefixed_and_bounded(self) -> None:
        try:
            protocol = importlib.import_module("cert_helper_protocol")
        except ModuleNotFoundError:
            protocol = None
        self.assertIsNotNone(protocol, "cert_helper_protocol doit être implémenté")
        if protocol is None:
            return

        sender, receiver = socket.socketpair()
        try:
            message = {"version": 1, "action": "ping"}
            protocol.send_message(sender, message, maximum_bytes=1024)
            self.assertEqual(protocol.receive_message(receiver, maximum_bytes=1024), message)

            sender.sendall(struct.pack("!I", 1025))
            with self.assertRaises(protocol.ProtocolError):
                protocol.receive_message(receiver, maximum_bytes=1024)
        finally:
            sender.close()
            receiver.close()

    def test_install_client_strips_web_only_fields_and_rejects_helper_errors(self) -> None:
        protocol = importlib.import_module("cert_helper_protocol")
        socket_path = Path("/run/fortios-cert-helper/helper.sock")
        payload = {
            "certificateBase64": "Y2VydA==",
            "privateKeyBase64": "a2V5",
            "chainBase64": "",
            "password": "secret",
            "validationToken": "web-only",
            "outputDir": "/arbitrary/path",
        }
        with mock.patch.object(
            protocol,
            "request_helper",
            return_value={"ok": True, "summary": {"hostname": "example.test"}},
        ) as request:
            summary = protocol.install_via_helper(
                socket_path,
                payload,
                credentials_revision="a" * 64,
            )

        self.assertEqual(summary, {"hostname": "example.test"})
        sent = request.call_args.args[1]
        self.assertEqual(
            set(sent["payload"]),
            {"certificateBase64", "privateKeyBase64", "chainBase64", "password"},
        )
        self.assertEqual(sent["credentialsRevision"], "a" * 64)
        self.assertNotIn("hostname", sent)
        self.assertNotIn("outputDir", sent["payload"])

        with mock.patch.object(
            protocol,
            "request_helper",
            return_value={"ok": False, "error": "certificat invalide"},
        ), self.assertRaisesRegex(protocol.HelperError, "certificat invalide"):
            protocol.install_via_helper(
                socket_path,
                payload,
                credentials_revision="a" * 64,
            )

    def test_install_waits_for_a_definitive_response_after_sending(self) -> None:
        protocol = importlib.import_module("cert_helper_protocol")
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = Path(tmp) / "helper.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            listener.listen(1)

            def delayed_helper() -> None:
                connection, _ = listener.accept()
                with connection:
                    protocol.receive_message(connection, maximum_bytes=protocol.MAX_REQUEST_BYTES)
                    threading.Event().wait(0.1)
                    protocol.send_message(
                        connection,
                        {"ok": True, "summary": {"commonName": "example.test"}},
                        maximum_bytes=protocol.MAX_RESPONSE_BYTES,
                    )

            thread = threading.Thread(target=delayed_helper, daemon=True)
            thread.start()
            try:
                summary = protocol.install_via_helper(
                    socket_path,
                    {
                        "certificateBase64": "certificate",
                        "privateKeyBase64": "key",
                        "chainBase64": "",
                        "password": "",
                    },
                    credentials_revision="a" * 64,
                    timeout_seconds=0.02,
                )
            finally:
                thread.join(timeout=2)
                listener.close()
            self.assertEqual(summary["commonName"], "example.test")


class CertificateHelperServiceTests(unittest.TestCase):
    def test_server_makes_runtime_directory_searchable_by_the_allowed_group(self) -> None:
        cert_admin = importlib.import_module("cert_admin")
        cert_helper = importlib.import_module("cert_helper")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime_dir = root / "run"
            runtime_dir.mkdir(mode=0o700)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "very-secret-password"),
            )
            processor = cert_helper.CertificateInstallProcessor(
                credentials_file=credentials,
                hostname=HOSTNAME,
                output_dir=root / "active",
                allowed_uid=os.getuid(),
                allowed_gid=os.getgid(),
            )

            with mock.patch.object(cert_helper.os, "chown") as chown:
                server = cert_helper.CertificateHelperServer(
                    runtime_dir / "helper.sock",
                    processor,
                    socket_gid=os.getgid(),
                )
                server.server_close()

            chown.assert_any_call(runtime_dir, 0, os.getgid())
            self.assertEqual(runtime_dir.stat().st_mode & 0o777, 0o750)

    def test_nginx_reloader_tests_configuration_before_reloading(self) -> None:
        helper = importlib.import_module("cert_helper")
        completed = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        with mock.patch.object(helper.subprocess, "run", return_value=completed) as run:
            helper.NginxReloader()()

        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["/usr/sbin/nginx", "-t"],
                ["/usr/bin/systemctl", "reload", "nginx"],
            ],
        )
        self.assertTrue(all(call.kwargs["check"] for call in run.call_args_list))
        self.assertTrue(all(call.kwargs["capture_output"] for call in run.call_args_list))

    def test_nginx_reloader_returns_a_fixed_error_without_command_output(self) -> None:
        helper = importlib.import_module("cert_helper")
        failure = subprocess.CalledProcessError(
            1,
            ["/usr/sbin/nginx", "-t"],
            stderr=b"sensitive host path",
        )
        with (
            mock.patch.object(helper.subprocess, "run", side_effect=failure),
            self.assertRaises(helper.CertificateReloadError) as raised,
        ):
            helper.NginxReloader()()

        self.assertIn("rechargement Nginx", str(raised.exception))
        self.assertNotIn("sensitive host path", str(raised.exception))

    def test_reload_failure_restores_the_previous_active_certificate(self) -> None:
        cert_admin = importlib.import_module("cert_admin")
        cert_web = importlib.import_module("cert_web")
        helper = importlib.import_module("cert_helper")
        protocol = importlib.import_module("cert_helper_protocol")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_dir = root / "first"
            second_dir = root / "second"
            first_dir.mkdir()
            second_dir.mkdir()
            first_certificate, first_key = create_self_signed(first_dir)
            second_certificate, second_key = create_self_signed(second_dir)
            output = root / "active"
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "helper-service-password"),
            )
            revision = cert_admin.credentials_revision(credentials)

            def payload(certificate: Path, private_key: Path) -> dict[str, str]:
                return {
                    "certificateBase64": base64.b64encode(certificate.read_bytes()).decode(),
                    "privateKeyBase64": base64.b64encode(private_key.read_bytes()).decode(),
                    "chainBase64": "",
                    "password": "",
                }

            cert_web.install_uploaded_certificate(
                payload(first_certificate, first_key), HOSTNAME, output
            )
            previous_fullchain = (output / "fullchain.pem").read_bytes()
            reloader = mock.Mock(side_effect=[RuntimeError("nginx reload failed"), None])
            processor = helper.CertificateInstallProcessor(
                hostname=HOSTNAME,
                output_dir=output,
                credentials_file=credentials,
                allowed_uid=1000,
                allowed_gid=1000,
                reload_callback=reloader,
            )

            with self.assertRaisesRegex(RuntimeError, "nginx reload failed"):
                processor.process(
                    {
                        "version": protocol.PROTOCOL_VERSION,
                        "action": "install",
                        "credentialsRevision": revision,
                        "payload": payload(second_certificate, second_key),
                    },
                    peer_uid=1000,
                    peer_gid=1000,
                )

            self.assertEqual((output / "fullchain.pem").read_bytes(), previous_fullchain)
            self.assertEqual(reloader.call_count, 2)

    def test_helper_rechecks_credentials_revision_and_blocks_reset_until_commit(self) -> None:
        cert_admin = importlib.import_module("cert_admin")
        helper = importlib.import_module("cert_helper")
        protocol = importlib.import_module("cert_helper_protocol")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "initial-password-value"),
            )
            revision = cert_admin.credentials_revision(credentials)
            replacement_credentials = cert_admin.credential_payload(
                "admin",
                "replacement-password-value",
            )
            processor = helper.CertificateInstallProcessor(
                hostname="example.test",
                output_dir=root / "active",
                credentials_file=credentials,
                allowed_uid=1000,
                allowed_gid=1000,
            )
            payload = {
                "certificateBase64": "certificate",
                "privateKeyBase64": "key",
                "chainBase64": "",
                "password": "",
            }
            request = {
                "version": protocol.PROTOCOL_VERSION,
                "action": "install",
                "credentialsRevision": revision,
                "payload": payload,
            }

            with self.assertRaises(helper.HelperAuthorizationError):
                processor.process(
                    {**request, "credentialsRevision": "b" * 64},
                    peer_uid=1000,
                    peer_gid=1000,
                )

            entered_install = threading.Event()
            release_install = threading.Event()
            reset_done = threading.Event()
            errors: list[BaseException] = []

            def blocked_install(*_args: object, **_kwargs: object) -> dict[str, str]:
                entered_install.set()
                if not release_install.wait(2):
                    raise TimeoutError("test install release timed out")
                return {"commonName": "example.test"}

            def run_install() -> None:
                try:
                    processor.process(request, peer_uid=1000, peer_gid=1000)
                except BaseException as error:  # noqa: BLE001 - surfaced in the test thread
                    errors.append(error)

            def reset_credentials() -> None:
                cert_admin.write_credentials(credentials, replacement_credentials)
                reset_done.set()

            with mock.patch.object(helper, "install_uploaded_certificate", side_effect=blocked_install):
                install_thread = threading.Thread(target=run_install)
                install_thread.start()
                self.assertTrue(entered_install.wait(2))
                reset_thread = threading.Thread(target=reset_credentials)
                reset_thread.start()
                self.assertFalse(reset_done.wait(0.1))
                release_install.set()
                install_thread.join(timeout=2)
                reset_thread.join(timeout=2)

            self.assertFalse(errors)
            self.assertTrue(reset_done.is_set())
            self.assertNotEqual(cert_admin.credentials_revision(credentials), revision)

    def test_processor_rejects_wrong_peer_and_arbitrary_operations(self) -> None:
        helper = importlib.import_module("cert_helper")
        protocol = importlib.import_module("cert_helper_protocol")
        processor = helper.CertificateInstallProcessor(
            hostname="example.test",
            output_dir=Path("/fixed/output"),
            credentials_file=Path("/fixed/credentials.json"),
            allowed_uid=1000,
            allowed_gid=1000,
        )
        payload = {
            "certificateBase64": "",
            "privateKeyBase64": "",
            "chainBase64": "",
            "password": "",
        }

        with self.assertRaises(helper.HelperAuthorizationError):
            processor.process(
                {
                    "version": protocol.PROTOCOL_VERSION,
                    "action": "install",
                    "credentialsRevision": "a" * 64,
                    "payload": payload,
                },
                peer_uid=1001,
                peer_gid=1000,
            )
        with self.assertRaises(protocol.ProtocolError):
            processor.process(
                {
                    "version": protocol.PROTOCOL_VERSION,
                    "action": "install",
                    "credentialsRevision": "a" * 64,
                    "payload": {**payload, "outputDir": "/arbitrary/path"},
                },
                peer_uid=1000,
                peer_gid=1000,
            )
        with self.assertRaises(protocol.ProtocolError):
            processor.process(
                {"version": protocol.PROTOCOL_VERSION, "action": "exec", "command": "id"},
                peer_uid=1000,
                peer_gid=1000,
            )

    def test_server_refuses_to_replace_a_regular_file_with_a_socket(self) -> None:
        helper = importlib.import_module("cert_helper")
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = Path(tmp) / "helper.sock"
            socket_path.write_text("do not replace", encoding="utf-8")
            processor = helper.CertificateInstallProcessor(
                hostname="example.test",
                output_dir=Path(tmp) / "active",
                credentials_file=Path(tmp) / "credentials.json",
                allowed_uid=max(os.getuid(), 1),
                allowed_gid=max(os.getgid(), 1),
            )
            with self.assertRaisesRegex(ValueError, "socket géré sûr"):
                helper.CertificateHelperServer(socket_path, processor)

    def test_authorized_web_process_installs_a_revalidated_certificate(self) -> None:
        try:
            helper = importlib.import_module("cert_helper")
            protocol = importlib.import_module("cert_helper_protocol")
        except ModuleNotFoundError:
            helper = None
            protocol = None
        self.assertIsNotNone(helper, "cert_helper doit être implémenté")
        if helper is None or protocol is None:
            return

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert_admin = importlib.import_module("cert_admin")
            credentials = root / "credentials.json"
            cert_admin.write_credentials(
                credentials,
                cert_admin.credential_payload("admin", "helper-service-password"),
            )
            revision = cert_admin.credentials_revision(credentials)
            certificate, private_key = create_self_signed(root)
            bundle = root / "certificate.pfx"
            export = subprocess.run(
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
                    "pass:helper-test-password",
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(export.returncode, 0, export.stderr.decode(errors="replace"))
            output = root / "certificates" / "active"
            socket_path = root / "run" / "helper.sock"
            socket_path.parent.mkdir(mode=0o700)
            processor = helper.CertificateInstallProcessor(
                hostname=HOSTNAME,
                output_dir=output,
                credentials_file=credentials,
                allowed_uid=os.getuid(),
                allowed_gid=os.getgid(),
            )
            server = helper.CertificateHelperServer(socket_path, processor)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                response = protocol.request_helper(
                    socket_path,
                    {
                        "version": protocol.PROTOCOL_VERSION,
                        "action": "install",
                        "credentialsRevision": revision,
                        "payload": {
                            "certificateBase64": base64.b64encode(bundle.read_bytes()).decode(),
                            "privateKeyBase64": "",
                            "chainBase64": "",
                            "password": "helper-test-password",
                        },
                    },
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

            self.assertTrue(response["ok"])
            self.assertEqual(response["summary"]["hostname"], HOSTNAME)
            self.assertTrue((output / "fullchain.pem").is_file())
            self.assertTrue((output / "privkey.pem").is_file())


if __name__ == "__main__":
    unittest.main()