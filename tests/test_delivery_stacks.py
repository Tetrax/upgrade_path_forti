"""Portable deployment contracts, checked without secrets or Docker mutation."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DeliveryStackTests(unittest.TestCase):
    def test_images_exclude_live_settings_secrets_and_outbox(self):
        text = (ROOT / '.dockerignore').read_text()
        for pattern in (
            'data/smtp-password*', 'data/smtp-settings.json*',
            'data/fortios-notify-history.json*', 'data/email-transport-settings.json*',
            'data/.email-transport-settings.json*', '**/microsoft365-client-secret*',
        ):
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

    def test_every_stack_passes_microsoft365_configuration_to_both_workers(self):
        fields = (
            'TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET_FILE', 'FROM',
            'DISPLAY_NAME', 'MAILBOX_IDENTITY',
        )
        for name in ('docker-compose.yml', 'docker-compose.portainer.yml', 'docker-compose.portainer-import.yml'):
            with self.subTest(name=name):
                text = (ROOT / name).read_text()
                self.assertEqual(text.count('FORTIOS_EMAIL_TRANSPORT: ${FORTIOS_EMAIL_TRANSPORT:-smtp}'), 2)
                for field in fields:
                    variable = f'FORTIOS_MICROSOFT365_{field}'
                    self.assertEqual(text.count(f'{variable}: ${{{variable}:-}}'), 2)
                self.assertEqual(text.count('FORTIOS_MICROSOFT365_TIMEOUT: ${FORTIOS_MICROSOFT365_TIMEOUT:-10}'), 2)
                self.assertNotIn('FORTIOS_MICROSOFT365_CLIENT_SECRET:', text)

    def test_canonical_microsoft365_guide_is_packaged_outside_persistent_docs(self):
        text = (ROOT / 'Dockerfile').read_text()
        self.assertIn('COPY docs/microsoft365.md ./app/cert/microsoft365-guide.md', text)
        self.assertTrue((ROOT / 'docs/microsoft365.md').is_file())

    def test_microsoft365_acceptance_stack_is_isolated_and_collection_opt_in(self):
        text = (ROOT / 'docker-compose.microsoft365-test.yml').read_text()
        self.assertIn('name: fortiupgrade-m365-test', text)
        self.assertIn('127.0.0.1:18443:8000', text)
        self.assertIn('profiles: [collection]', text)
        self.assertIn('FORTIOS_EMAIL_ENABLED: "false"', text)
        self.assertNotIn('ALLOW_INSECURE_LOCALHOST', text)
        self.assertNotIn('container_name:', text)
        self.assertNotIn('external: true', text)
        self.assertEqual(text.count('source: /var/lib/fortiupgrade-m365-test/secrets'), 2)
        self.assertEqual(text.count('read_only: true'), 2)
        self.assertEqual(text.count('create_host_path: false'), 2)
