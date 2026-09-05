"""Renewal must use the authoritative validator/activation/rollback path."""
from __future__ import annotations

import base64
import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_certctl import HOSTNAME, create_self_signed

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
helper = importlib.import_module("cert_helper")


class CertbotRenewalTests(unittest.TestCase):
    def test_renewal_reuses_validator_and_rolls_back_failed_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            old_cert, old_key = create_self_signed(old)
            new_cert, new_key = create_self_signed(new)
            credentials = root / "admin" / "credentials.json"
            helper.cert_admin.write_credentials(
                credentials, helper.cert_admin.credential_payload("admin", "isolated-test-password")
            )
            processor = helper.CertificateInstallProcessor(
                hostname=HOSTNAME, output_dir=root / "active", credentials_file=credentials,
                allowed_uid=1000, allowed_gid=1000,
            )
            processor.install({
                "certificateBase64": base64.b64encode(old_cert.read_bytes()).decode(),
                "privateKeyBase64": base64.b64encode(old_key.read_bytes()).decode(),
                "chainBase64": "", "password": "",
            })
            (new / "fullchain.pem").write_bytes(new_cert.read_bytes())
            (new / "privkey.pem").write_bytes(new_key.read_bytes())
            previous = (root / "active" / "fullchain.pem").read_bytes()
            credential_bytes = credentials.read_bytes()
            processor.reload_callback = mock.Mock(side_effect=[RuntimeError("reload failed"), None])
            with self.assertRaisesRegex(RuntimeError, "reload failed"):
                helper.renew_from_lineage(processor, new)
            self.assertEqual((root / "active" / "fullchain.pem").read_bytes(), previous)
            self.assertEqual(credentials.read_bytes(), credential_bytes)
            self.assertEqual(processor.reload_callback.call_count, 2)
            processor.reload_callback = mock.Mock()
            helper.renew_from_lineage(processor, new)
            self.assertEqual((root / "active" / "fullchain.pem").read_bytes(), new_cert.read_bytes())
            self.assertEqual(credentials.read_bytes(), credential_bytes)
            processor.reload_callback.assert_called_once()

    def test_invalid_lineage_does_not_activate_or_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            processor = mock.Mock()
            with self.assertRaises(OSError):
                helper.renew_from_lineage(processor, Path(directory))
            processor.install.assert_not_called()

    def test_renew_command_is_host_root_only(self):
        with mock.patch.object(helper.os, "geteuid", return_value=1000):
            self.assertEqual(helper.main(["renew"]), 77)
