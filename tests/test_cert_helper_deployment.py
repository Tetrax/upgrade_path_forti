"""Static security contract for the host certificate-helper service."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = (
    ROOT / "docker-compose.yml",
    ROOT / "docker-compose.portainer.yml",
    ROOT / "docker-compose.portainer-import.yml",
)
HELPER_COMPOSE_FILES = COMPOSE_FILES[:2]


class CertificateHelperDeploymentTests(unittest.TestCase):
    def test_privileged_helper_is_not_embedded_as_a_container_service(self) -> None:
        for path in COMPOSE_FILES:
            with self.subTest(path=path.name):
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("  cert-helper:\n", content)

    def test_web_certificate_mount_mode_is_explicit_and_helper_runtime_is_read_only(self) -> None:
        for path in HELPER_COMPOSE_FILES:
            with self.subTest(path=path.name):
                content = path.read_text(encoding="utf-8")
                web = content.split("\n  web:\n", 1)[1].split("\n  cert-helper:\n", 1)[0]
                self.assertIn("FORTIOS_CERT_HELPER_SOCKET", web)
                self.assertIn("FORTIOS_CERT_ADMIN_FILE", web)
                self.assertIn("FORTIOS_CERT_TRUSTED_PROXY_CIDRS", web)
                self.assertIn(
                    ":/opt/fortios/certificates:${FORTIOS_CERTS_MOUNT_MODE:-rw}",
                    web,
                )
                self.assertIn(":/run/fortios-cert-helper:ro", web)

        entrypoint = (ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn('if [ -z "${FORTIOS_CERT_HELPER_SOCKET:-}" ]; then', entrypoint)
        self.assertIn("The read-only certificate volume is unavailable.", entrypoint)

    def test_all_stacks_make_trusted_proxy_mode_explicit(self) -> None:
        for path in COMPOSE_FILES:
            with self.subTest(path=path.name):
                content = path.read_text(encoding="utf-8")
                self.assertIn("FORTIOS_CERT_TRUSTED_PROXY_CIDRS", content)

    def test_host_helper_systemd_unit_is_hardened_and_networkless(self) -> None:
        unit = (ROOT / "deploy" / "fortios-cert-helper.service").read_text(encoding="utf-8")
        self.assertIn("User=root", unit)
        self.assertIn("PrivateNetwork=true", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn(
            "ReadWritePaths=/var/lib/fortiupgrade/certificates /run/fortios-cert-helper "
            "/run/nginx.pid /var/log/nginx",
            unit,
        )
        self.assertIn("RuntimeDirectory=fortios-cert-helper", unit)
        self.assertIn("RuntimeDirectoryMode=0755", unit)
        self.assertIn(
            "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_NET_BIND_SERVICE",
            unit,
        )
        self.assertIn("scripts/cert_helper.py serve", unit)

    def test_nginx_proxy_forwards_https_identity_and_accepts_certificate_uploads(self) -> None:
        nginx = (ROOT / "deploy" / "nginx-fortios-upgrade.conf").read_text(encoding="utf-8")
        self.assertIn("client_max_body_size 56m", nginx)
        self.assertIn("Host $http_host", nginx)
        self.assertIn("X-Real-IP $remote_addr", nginx)
        self.assertIn("X-Forwarded-For $remote_addr", nginx)
        self.assertNotIn("X-Forwarded-For $proxy_add_x_forwarded_for", nginx)
        self.assertIn("X-Forwarded-Proto $scheme", nginx)


if __name__ == "__main__":
    unittest.main()