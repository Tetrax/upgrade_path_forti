"""Opt-in checks of the SMTP secret volume through the real Docker entrypoint."""
import os
import subprocess
import unittest
import uuid


@unittest.skipUnless(os.environ.get('FORTIOS_DOCKER_TEST_IMAGE'), 'requires a built Docker candidate')
class SmtpSecretVolumeTests(unittest.TestCase):
    def setUp(self):
        self.image = os.environ['FORTIOS_DOCKER_TEST_IMAGE']
        self.volume = 'fortiupgrade-smtp-probe-' + uuid.uuid4().hex
        subprocess.run(['docker', 'volume', 'create', self.volume], check=True, capture_output=True)

    def tearDown(self):
        subprocess.run(['docker', 'volume', 'rm', self.volume], check=True, capture_output=True)

    def run_container(self, code, read_only=False):
        mount = f'type=volume,source={self.volume},target=/opt/fortios/smtp-secrets'
        if read_only:
            mount += ',readonly'
        return subprocess.run([
            'docker', 'run', '--rm', '--network', 'none',
            '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL',
            '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'FOWNER',
            '--cap-add', 'SETGID', '--cap-add', 'SETUID',
            '-e', 'PUID=12001', '-e', 'PGID=12002',
            '-e', 'FORTIOS_SMTP_PASSWORD_FILE=/opt/fortios/smtp-secrets/password',
            '--mount', mount, self.image, 'python', '-c', code,
        ], check=False, capture_output=True, text=True, timeout=60)

    def test_web_prepares_private_volume_and_scheduler_reads_without_writing(self):
        written = self.run_container("""
import os, stat
from pathlib import Path
from scripts import fortios_notify as n
p = Path('/opt/fortios/smtp-secrets')
assert os.getuid() == 12001
assert p.stat().st_uid == 12001 and p.stat().st_gid == 12002
assert stat.S_IMODE(p.stat().st_mode) == 0o700
n.save_smtp_password('offline-smtp-test-fixture')
assert (p / 'password').read_text() == 'offline-smtp-test-fixture'
assert stat.S_IMODE((p / 'password').stat().st_mode) == 0o600
""")
        self.assertEqual(written.returncode, 0, written.stderr)
        read = self.run_container("""
from pathlib import Path
from scripts import fortios_notify as n
p = Path('/opt/fortios/smtp-secrets/password')
assert p.read_text() == 'offline-smtp-test-fixture'
try:
    n.save_smtp_password('must-not-be-written')
except n.SmtpPasswordStorageError:
    pass
else:
    raise AssertionError('scheduler can write SMTP password')
assert p.read_text() == 'offline-smtp-test-fixture'
""", read_only=True)
        self.assertEqual(read.returncode, 0, read.stderr)

    def test_read_only_scheduler_can_start_with_missing_password(self):
        started = self.run_container('import os; assert os.getuid() == 12001', read_only=True)
        self.assertEqual(started.returncode, 0, started.stderr)

    def test_hardlink_is_rejected_without_changing_victim_permissions(self):
        prepared = self.run_container("""
import os
from pathlib import Path
p = Path('/opt/fortios/smtp-secrets')
(p / 'victim').write_text('offline-fixture')
(p / 'victim').chmod(0o644)
os.link(p / 'victim', p / 'password')
""")
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        rejected = self.run_container('pass')
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('SMTP secret volume is invalid or unavailable.', rejected.stderr)
        checked = subprocess.run([
            'docker', 'run', '--rm', '--network', 'none', '--user', '12001:12002',
            '--mount', f'type=volume,source={self.volume},target=/opt/fortios/smtp-secrets,readonly',
            '--entrypoint', 'python', self.image, '-c',
            "import os, stat; s=os.stat('/opt/fortios/smtp-secrets/victim'); assert stat.S_IMODE(s.st_mode)==0o644; assert s.st_uid==12001",
        ], check=False, capture_output=True, text=True, timeout=60)
        self.assertEqual(checked.returncode, 0, checked.stderr)
