"""Certificate installation CLI tests using real OpenSSL artifacts."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CERTCTL = ROOT / "scripts" / "certctl.py"
HOSTNAME = "upgrade-path.sns-security.lan"
sys.path.insert(0, str(ROOT / "scripts"))
import certctl  # type: ignore[import-not-found]


def run(
    *args: str,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, env=env, check=False)
    if check and result.returncode:
        raise AssertionError(f"command failed ({result.returncode}): {' '.join(args)}\n{result.stdout}\n{result.stderr}")
    return result


def create_self_signed(directory: Path, hostname: str = HOSTNAME) -> tuple[Path, Path]:
    cert = directory / "certificate.crt"
    key = directory / "private.key"
    run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "30",
        "-subj", f"/CN={hostname}", "-addext", f"subjectAltName=DNS:{hostname}",
    )
    return cert, key


def create_cn_only_certificate(directory: Path) -> tuple[Path, Path]:
    cert = directory / "cn-only.pem"
    key = directory / "cn-only.key"
    run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "30",
        "-subj", f"/CN={HOSTNAME}",
    )
    return cert, key


def create_client_auth_only_certificate(directory: Path) -> tuple[Path, Path]:
    cert = directory / "client-auth-only.pem"
    key = directory / "client-auth-only.key"
    run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "30",
        "-subj", f"/CN={HOSTNAME}",
        "-addext", f"subjectAltName=DNS:{HOSTNAME}",
        "-addext", "extendedKeyUsage=clientAuth",
    )
    return cert, key


def create_ca(directory: Path, common_name: str = "SNS Internal Test CA") -> tuple[Path, Path]:
    cert = directory / "ca.pem"
    key = directory / "ca.key"
    run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "30",
        "-subj", f"/CN={common_name}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    return cert, key


def create_ca_signed_leaf(
    directory: Path,
    ca_cert: Path,
    ca_key: Path,
    hostname: str = HOSTNAME,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[Path, Path]:
    request = directory / "leaf.csr"
    cert = directory / "leaf.pem"
    key = directory / "leaf.key"
    extensions = directory / "leaf.ext"
    extensions.write_text(
        f"subjectAltName=DNS:{hostname}\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n",
    )
    run(
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(request), "-subj", f"/CN={hostname}",
    )
    sign_command = [
        "openssl", "x509", "-req", "-in", str(request),
        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(cert), "-days", "30", "-extfile", str(extensions),
    ]
    if not_before is not None:
        sign_command.extend(["-not_before", not_before.strftime("%Y%m%d%H%M%SZ")])
    if not_after is not None:
        sign_command.extend(["-not_after", not_after.strftime("%Y%m%d%H%M%SZ")])
    run(*sign_command)
    return cert, key


def create_intermediate_ca(
    directory: Path,
    issuer_cert: Path,
    issuer_key: Path,
) -> tuple[Path, Path]:
    request = directory / "intermediate.csr"
    cert = directory / "intermediate.pem"
    key = directory / "intermediate.key"
    extensions = directory / "intermediate.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n",
    )
    run(
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(request),
        "-subj", "/CN=SNS Internal Intermediate CA",
    )
    run(
        "openssl", "x509", "-req", "-in", str(request),
        "-CA", str(issuer_cert), "-CAkey", str(issuer_key), "-CAcreateserial",
        "-out", str(cert), "-days", "30", "-extfile", str(extensions),
    )
    return cert, key


class CertificateInstallTests(unittest.TestCase):
    def test_runtime_owner_uses_container_puid_pgid_when_root(self) -> None:
        with (
            mock.patch.object(certctl.os, "geteuid", return_value=0),
            mock.patch.dict(certctl.os.environ, {"PUID": "1234", "PGID": "5678"}),
        ):
            self.assertEqual(certctl.configured_runtime_owner(), (1234, 5678))

    def test_runtime_owner_rejects_root_uid_or_gid(self) -> None:
        for uid, gid in ((0, 1000), (1000, 0)):
            with (
                self.subTest(uid=uid, gid=gid),
                mock.patch.object(certctl.os, "geteuid", return_value=0),
                mock.patch.dict(
                    certctl.os.environ, {"PUID": str(uid), "PGID": str(gid)}, clear=False,
                ),
                self.assertRaises(certctl.CertificateError),
            ):
                    certctl.configured_runtime_owner()

    def test_container_install_keeps_material_root_owned_and_group_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            output = root / "active"
            with (
                mock.patch.object(certctl.os, "geteuid", return_value=0),
                mock.patch.object(certctl.os, "chown") as chown,
                mock.patch("tls_lock.os.fchown") as lock_chown,
                mock.patch.dict(
                    certctl.os.environ, {"PUID": "1234", "PGID": "5678"}, clear=False,
                ),
            ):
                certctl.install_certificate(cert, key, HOSTNAME, output)

            version = output.resolve()
            self.assertEqual((version / "privkey.pem").stat().st_mode & 0o777, 0o640)
            self.assertEqual(version.stat().st_mode & 0o777, 0o750)
            self.assertIn(mock.call(version / "fullchain.pem", 0, 5678), chown.call_args_list)
            self.assertIn(mock.call(version / "privkey.pem", 0, 5678), chown.call_args_list)
            self.assertIn(mock.call(version, 0, 5678), chown.call_args_list)
            lock_chown.assert_called_once_with(mock.ANY, 0, 5678)

    def test_installs_pem_certificate_and_private_key_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            output = root / "active"

            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(output),
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((output / "fullchain.pem").is_file())
            self.assertTrue((output / "privkey.pem").is_file())
            self.assertEqual(os.stat(output / "privkey.pem").st_mode & 0o777, 0o600)
            run("openssl", "x509", "-in", str(output / "fullchain.pem"), "-noout")
            run("openssl", "pkey", "-in", str(output / "privkey.pem"), "-noout")
            self.assertIn(HOSTNAME, result.stdout)

    def test_preserves_chain_embedded_in_fullchain_pem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca_dir = root / "ca"
            ca_dir.mkdir()
            ca_cert, ca_key = create_ca(ca_dir)
            cert, key = create_ca_signed_leaf(root, ca_cert, ca_key)
            source = root / "input-fullchain.pem"
            source.write_bytes(cert.read_bytes() + ca_cert.read_bytes())
            output = root / "active"

            result = run(
                sys.executable, str(CERTCTL), "install", str(source),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(output), check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (output / "fullchain.pem").read_text().count("-----BEGIN CERTIFICATE-----"),
                2,
            )

    def test_orders_an_unordered_embedded_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca_dir = root / "ca"
            intermediate_dir = root / "intermediate"
            ca_dir.mkdir()
            intermediate_dir.mkdir()
            root_cert, root_key = create_ca(ca_dir)
            intermediate_cert, intermediate_key = create_intermediate_ca(
                intermediate_dir, root_cert, root_key,
            )
            cert, key = create_ca_signed_leaf(root, intermediate_cert, intermediate_key)
            source = root / "unordered-fullchain.pem"
            source.write_bytes(
                cert.read_bytes() + root_cert.read_bytes() + intermediate_cert.read_bytes(),
            )
            output = root / "active"
            result = run(
                sys.executable, str(CERTCTL), "install", str(source),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(output), check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = certctl.normalize_certificate_blocks(
                (output / "fullchain.pem").read_bytes(),
            )
            self.assertEqual(
                certctl.certificate_name(installed[0], "issuer"),
                certctl.certificate_name(installed[1], "subject"),
            )
            self.assertEqual(
                certctl.certificate_name(installed[1], "issuer"),
                certctl.certificate_name(installed[2], "subject"),
            )

    def test_installs_password_protected_pkcs12_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca_dir = root / "ca"
            ca_dir.mkdir()
            ca_cert, ca_key = create_ca(ca_dir)
            cert, key = create_ca_signed_leaf(root, ca_cert, ca_key)
            bundle = root / "certificate.pfx"
            password_file = root / "pfx-password"
            password_file.write_text("test-password\n")
            run(
                "openssl", "pkcs12", "-export", "-out", str(bundle),
                "-inkey", str(key), "-in", str(cert),
                "-certfile", str(ca_cert),
                "-passout", "pass:test-password",
            )

            output = root / "active"
            result = run(
                sys.executable, str(CERTCTL), "install", str(bundle),
                "--password-file", str(password_file),
                "--hostname", HOSTNAME, "--output-dir", str(output),
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            run("openssl", "x509", "-in", str(output / "fullchain.pem"), "-noout", "-checkhost", HOSTNAME)
            run("openssl", "pkey", "-in", str(output / "privkey.pem"), "-noout")
            self.assertEqual(
                (output / "fullchain.pem").read_text().count("-----BEGIN CERTIFICATE-----"),
                2,
            )
            self.assertNotIn("test-password", result.stdout + result.stderr)

    def test_pkcs12_cleanup_failure_after_activation_is_only_a_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            certificate, private_key = create_self_signed(root)
            bundle = root / "certificate.pfx"
            run(
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
            )
            output = root / "active"

            with mock.patch.object(
                certctl,
                "cleanup_pkcs12_directory",
                side_effect=OSError("simulated cleanup failure"),
            ):
                certctl.install_certificate(
                    bundle,
                    None,
                    HOSTNAME,
                    output,
                    password=b"test-password",
                )

            self.assertTrue((output / "fullchain.pem").is_file())
            self.assertTrue((output / "privkey.pem").is_file())

    def test_installs_der_certificate_with_separate_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            der_cert = root / "certificate.cer"
            run(
                "openssl", "x509", "-in", str(cert), "-outform", "DER",
                "-out", str(der_cert),
            )
            output = root / "active"

            result = run(
                sys.executable, str(CERTCTL), "install", str(der_cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(output), check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(
                (output / "fullchain.pem").read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
            )
            run("openssl", "x509", "-in", str(output / "fullchain.pem"), "-noout", "-checkhost", HOSTNAME)

    def test_appends_pkcs7_chain_to_leaf_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca_dir = root / "ca"
            ca_dir.mkdir()
            ca_cert, ca_key = create_ca(ca_dir)
            cert, key = create_ca_signed_leaf(root, ca_cert, ca_key)
            chain = root / "chain.p7b"
            run(
                "openssl", "crl2pkcs7", "-nocrl", "-certfile", str(ca_cert),
                "-outform", "DER", "-out", str(chain),
            )
            output = root / "active"

            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--chain", str(chain),
                "--hostname", HOSTNAME, "--output-dir", str(output),
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (output / "fullchain.pem").read_text().count("-----BEGIN CERTIFICATE-----"),
                2,
            )

    def test_installs_encrypted_pkcs8_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            encrypted_key = root / "encrypted-private.pem"
            password_file = root / "key-password"
            password_file.write_text("test-password\n")
            run(
                "openssl", "pkey", "-in", str(key), "-aes-256-cbc",
                "-out", str(encrypted_key), "-passout", "pass:test-password",
            )
            output = root / "active"

            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(encrypted_key), "--password-file", str(password_file),
                "--hostname", HOSTNAME, "--output-dir", str(output),
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            run("openssl", "pkey", "-in", str(output / "privkey.pem"), "-noout")

    def test_accepts_internal_wildcard_for_one_dns_label(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root, "*.sns-security.lan")
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(root / "active"), check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_certificate_for_another_hostname(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root, "unrelated.sns-security.lan")
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(root / "active"), check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "active").exists())

    def test_rejects_cn_only_certificate_without_san(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_cn_only_certificate(root)
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(root / "active"), check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "active").exists())

    def test_rejects_chainless_client_auth_only_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_client_auth_only_certificate(root)
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(root / "active"), check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "active").exists())

    def test_rejects_wrong_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, _ = create_self_signed(root)
            other = root / "other"
            other.mkdir()
            _, wrong_key = create_self_signed(other)
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(wrong_key), "--hostname", HOSTNAME,
                "--output-dir", str(root / "active"), check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "active").exists())

    def test_rejects_malformed_pem_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            chain = root / "broken-chain.pem"
            chain.write_text(
                "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n",
            )
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--chain", str(chain),
                "--hostname", HOSTNAME, "--output-dir", str(root / "active"),
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "active").exists())

    def test_rejects_unrelated_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            unrelated = root / "unrelated"
            unrelated.mkdir()
            unrelated_ca, _ = create_ca(unrelated, "Unrelated CA")
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--chain", str(unrelated_ca),
                "--hostname", HOSTNAME, "--output-dir", str(root / "active"),
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "active").exists())

    def test_rejects_not_yet_valid_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca_dir = root / "ca"
            ca_dir.mkdir()
            ca_cert, ca_key = create_ca(ca_dir)
            cert, key = create_ca_signed_leaf(
                root,
                ca_cert,
                ca_key,
                not_before=datetime.now(timezone.utc) + timedelta(days=1),
            )
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(root / "active"), check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "active").exists())

    def test_rejects_expired_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca_dir = root / "ca"
            ca_dir.mkdir()
            ca_cert, ca_key = create_ca(ca_dir)
            cert, key = create_ca_signed_leaf(
                root,
                ca_cert,
                ca_key,
                not_before=datetime.now(timezone.utc) - timedelta(days=2),
                not_after=datetime.now(timezone.utc) - timedelta(days=1),
            )
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(root / "active"), check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "active").exists())

    def test_failed_renewal_preserves_active_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            output = root / "active"
            first = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(output), check=False,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            previous_target = os.readlink(output)
            previous_certificate = (output / "fullchain.pem").read_bytes()

            other = root / "other"
            other.mkdir()
            wrong_cert, wrong_key = create_self_signed(
                other, "unrelated.sns-security.lan",
            )
            failed = run(
                sys.executable, str(CERTCTL), "install", str(wrong_cert),
                "--key", str(wrong_key), "--hostname", HOSTNAME,
                "--output-dir", str(output), check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(os.readlink(output), previous_target)
            self.assertEqual((output / "fullchain.pem").read_bytes(), previous_certificate)

    def test_successful_renewal_removes_all_superseded_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "active"
            first_dir = root / "first"
            second_dir = root / "second"
            third_dir = root / "third"
            first_dir.mkdir()
            second_dir.mkdir()
            third_dir.mkdir()
            first_cert, first_key = create_self_signed(first_dir)
            second_cert, second_key = create_self_signed(second_dir)
            third_cert, third_key = create_self_signed(third_dir)
            first_target = None
            for index, (cert, key) in enumerate((
                (first_cert, first_key),
                (second_cert, second_key),
                (third_cert, third_key),
            )):
                result = run(
                    sys.executable, str(CERTCTL), "install", str(cert),
                    "--key", str(key), "--hostname", HOSTNAME,
                    "--output-dir", str(output), check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                if index == 0:
                    first_target = os.readlink(output)
            managed = [path for path in root.glob(".active-*") if path.is_dir()]
            self.assertEqual(len(managed), 1)
            self.assertEqual(managed[0].name, os.readlink(output))
            self.assertNotIn(first_target, {path.name for path in managed})

    def test_cleanup_failure_after_commit_does_not_report_activation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_dir = root / "first"
            second_dir = root / "second"
            first_dir.mkdir()
            second_dir.mkdir()
            first_cert, first_key = create_self_signed(first_dir)
            second_cert, second_key = create_self_signed(second_dir)
            output = root / "active"
            certctl.activate_version(
                output,
                first_cert.read_bytes(),
                first_key.read_bytes(),
                None,
            )

            with mock.patch.object(certctl.shutil, "rmtree", side_effect=OSError("simulated cleanup failure")):
                certctl.activate_version(
                    output,
                    second_cert.read_bytes(),
                    second_key.read_bytes(),
                    None,
                )

            installed_fingerprint = run(
                "openssl", "x509", "-in", str(output / "fullchain.pem"),
                "-noout", "-fingerprint", "-sha256",
            ).stdout
            expected_fingerprint = run(
                "openssl", "x509", "-in", str(second_cert),
                "-noout", "-fingerprint", "-sha256",
            ).stdout
            self.assertEqual(installed_fingerprint, expected_fingerprint)

    def test_concurrent_installs_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_dir = root / "first"
            second_dir = root / "second"
            first_dir.mkdir()
            second_dir.mkdir()
            first_cert, first_key = create_self_signed(first_dir)
            second_cert, second_key = create_self_signed(second_dir)
            output = root / "active"
            signal = root / "lock-held"
            release = root / "release"
            blocker = """
import sys, time
from pathlib import Path
import certctl

certificate, key, output, signal, release = map(Path, sys.argv[1:6])
original = certctl.write_durable
blocked = False
def blocking_write(path, data, mode):
    global blocked
    if not blocked:
        blocked = True
        signal.write_text('held')
        while not release.exists():
            time.sleep(0.01)
    return original(path, data, mode)
certctl.write_durable = blocking_write
certctl.install_certificate(certificate, key, sys.argv[6], output)
"""
            environment = {**os.environ, "PYTHONPATH": str(ROOT / "scripts")}
            first = subprocess.Popen(
                [
                    sys.executable, "-c", blocker,
                    str(first_cert), str(first_key), str(output),
                    str(signal), str(release), HOSTNAME,
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment,
            )
            second: subprocess.Popen[str] | None = None
            try:
                deadline = time.monotonic() + 10
                while not signal.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(signal.exists(), "first installer did not acquire the lock")
                second = subprocess.Popen(
                    [
                        sys.executable, str(CERTCTL), "install", str(second_cert),
                        "--key", str(second_key), "--hostname", HOSTNAME,
                        "--output-dir", str(output),
                    ],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env=environment,
                )
                time.sleep(0.2)
                self.assertIsNone(second.poll(), "second installer bypassed the lock")
                release.write_text("continue")
                first_stdout, first_stderr = first.communicate(timeout=15)
                second_stdout, second_stderr = second.communicate(timeout=15)
                self.assertEqual(first.returncode, 0, first_stdout + first_stderr)
                self.assertEqual(second.returncode, 0, second_stdout + second_stderr)
                self.assertTrue((output / "fullchain.pem").is_file())
                managed = [path for path in root.glob(".active-*") if path.is_dir()]
                self.assertEqual(len(managed), 1)
                self.assertEqual(managed[0].name, os.readlink(output))
            finally:
                release.touch()
                if first.poll() is None:
                    first.kill()
                    first.communicate()
                if second is not None and second.poll() is None:
                    second.kill()
                    second.communicate()

    def test_rejects_explicit_chain_with_pkcs12_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            bundle = root / "certificate.p12"
            password = root / "password"
            password.write_text("bundle-password\n")
            run(
                "openssl", "pkcs12", "-export", "-out", str(bundle),
                "-inkey", str(key), "-in", str(cert),
                "-passout", "pass:bundle-password",
            )
            result = run(
                sys.executable, str(CERTCTL), "install", str(bundle),
                "--password-file", str(password), "--chain", str(cert),
                "--hostname", HOSTNAME, "--output-dir", str(root / "active"),
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "active").exists())

    def test_failed_install_leaves_no_temporary_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            output = root / "active"
            output.mkdir()
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(output), check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(root.glob(".active-link-*")), [])

    @unittest.skipUnless(os.geteuid() == 0, "requires root to verify container ownership handoff")
    def test_root_cli_keeps_key_root_owned_and_runtime_group_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = create_self_signed(root)
            output = root / "active"
            environment = {**os.environ, "PUID": "65534", "PGID": "65534"}
            result = run(
                sys.executable, str(CERTCTL), "install", str(cert),
                "--key", str(key), "--hostname", HOSTNAME,
                "--output-dir", str(output), check=False, env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((output / "privkey.pem").stat().st_uid, 0)
            self.assertEqual((output / "privkey.pem").stat().st_gid, 65534)
            self.assertEqual((output / "privkey.pem").stat().st_mode & 0o777, 0o640)
            self.assertEqual(output.resolve().stat().st_mode & 0o777, 0o750)


if __name__ == "__main__":
    unittest.main()
