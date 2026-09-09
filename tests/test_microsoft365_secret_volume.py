"""Opt-in Docker checks of the real entrypoint and portable secret volume.

Run with FORTIOS_DOCKER_TEST_IMAGE set to the candidate image. No network,
operational secrets or existing volumes are used.
"""
import os
import subprocess
import unittest
import uuid


@unittest.skipUnless(os.environ.get('FORTIOS_DOCKER_TEST_IMAGE'), 'requires a built Docker candidate')
class Microsoft365SecretVolumeTests(unittest.TestCase):
    def setUp(self):
        self.image = os.environ['FORTIOS_DOCKER_TEST_IMAGE']
        self.volume = 'fortiupgrade-secret-probe-' + uuid.uuid4().hex
        subprocess.run(['docker', 'volume', 'create', self.volume], check=True, capture_output=True)

    def tearDown(self):
        subprocess.run(['docker', 'volume', 'rm', self.volume], check=True, capture_output=True)

    def run_container(self, code, read_only=False):
        mount = f'type=volume,source={self.volume},target=/opt/fortios/microsoft365-secrets'
        if read_only:
            mount += ',readonly'
        result = subprocess.run([
            'docker', 'run', '--rm', '--network', 'none',
            '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL',
            '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE',
            '--cap-add', 'FOWNER', '--cap-add', 'SETGID', '--cap-add', 'SETUID',
            '-e', 'PUID=12001', '-e', 'PGID=12002',
            '--mount', mount, self.image, 'python', '-c', code,
        ], check=False, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_entrypoint_rejects_hardlink_without_changing_its_target(self):
        self.run_container("""
import os
from pathlib import Path
p = Path('/opt/fortios/microsoft365-secrets')
(p / 'victim').write_text('isolated test fixture')
(p / 'victim').chmod(0o644)
os.link(p / 'victim', p / 'client-secret')
""")
        mount = f'type=volume,source={self.volume},target=/opt/fortios/microsoft365-secrets'
        rejected = subprocess.run([
            'docker', 'run', '--rm', '--network', 'none',
            '-e', 'PUID=12001', '-e', 'PGID=12002',
            '--mount', mount, self.image, 'python', '-c', 'pass',
        ], check=False, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('Microsoft 365 secret volume is invalid or unavailable.', rejected.stderr)
        subprocess.run([
            'docker', 'run', '--rm', '--network', 'none',
            '--mount', mount + ',readonly', '--user', '12001:12002',
            '--entrypoint', 'python', self.image, '-c',
            ("import os, stat; s = os.stat('/opt/fortios/microsoft365-secrets/victim'); "
             "assert stat.S_IMODE(s.st_mode) == 0o644; assert s.st_uid == 12001"),
        ], check=True, capture_output=True, timeout=60)

    def test_web_initializes_private_volume_and_recreation_preserves_secret(self):
        self.run_container("""
import os, stat
from pathlib import Path
from scripts.fortios_notify import save_microsoft365_client_secret
p = Path('/opt/fortios/microsoft365-secrets')
assert os.getuid() == 12001
assert p.stat().st_uid == 12001 and p.stat().st_gid == 12002
assert stat.S_IMODE(p.stat().st_mode) == 0o700
secret = p / 'client-secret'
save_microsoft365_client_secret(
    'integration-fixture-not-a-provider-credential',
    env={'FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE': str(secret)},
)
""")
        self.run_container("""
from pathlib import Path
p = Path('/opt/fortios/microsoft365-secrets/client-secret')
assert p.read_text() == 'integration-fixture-not-a-provider-credential'
assert p.stat().st_mode & 0o777 == 0o600
""")
        self.run_container("""
from pathlib import Path
from scripts import fortios_notify as n
p = Path('/opt/fortios/microsoft365-secrets/client-secret')
env = {'FORTIOS_MICROSOFT365_CLIENT_SECRET_FILE': str(p)}
value, _, error, status = n._load_microsoft365_client_secret(env)
assert value == 'integration-fixture-not-a-provider-credential' and not error
assert not status.can_write
try:
    n.save_microsoft365_client_secret('must-not-be-written', env=env)
except n.Microsoft365SecretStorageError:
    pass
else:
    raise AssertionError('scheduler can overwrite secret')
""", read_only=True)

    def test_read_only_scheduler_can_start_before_web_without_secret(self):
        self.run_container('import os; assert os.getuid() == 12001', read_only=True)
