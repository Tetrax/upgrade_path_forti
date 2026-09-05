"""Portable deployment contracts, checked without secrets or Docker mutation."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DeliveryStackTests(unittest.TestCase):
    def test_images_exclude_live_settings_secrets_and_outbox(self):
        text = (ROOT / '.dockerignore').read_text()
        for pattern in ('data/smtp-password*', 'data/smtp-settings.json*', 'data/fortios-notify-history.json*'):
            self.assertIn(pattern, text)

    def test_portainer_images_are_operator_pinnable_and_network_is_portable(self):
        for name in ('docker-compose.portainer.yml', 'docker-compose.portainer-import.yml'):
            with self.subTest(name=name):
                text = (ROOT / name).read_text()
                self.assertEqual(text.count('image: ${FORTIOS_IMAGE:-ghcr.io/tetrax/upgrade_path_forti:latest}'), 2)
                self.assertNotIn('Subnet-Docker', text)
                self.assertNotIn('ipv4_address:', text)

    def test_every_stack_mounts_a_separate_read_only_secret_directory(self):
        for name in ('docker-compose.yml', 'docker-compose.portainer.yml', 'docker-compose.portainer-import.yml'):
            with self.subTest(name=name):
                text = (ROOT / name).read_text()
                self.assertEqual(text.count(':/run/fortios-secrets:ro'), 2)
                self.assertEqual(text.count('      FORTIOS_SMTP_SECURITY:'), 2)
                self.assertEqual(text.count('      FORTIOS_SMTP_ALLOW_INSECURE:'), 2)
