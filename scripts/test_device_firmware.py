"""Execute the real shell loader in isolated roots; no device access."""
import hashlib
import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'firmware/overlay/usr/local/libexec/nassimhub-device-firmware'


@unittest.skipUnless(os.geteuid() == 0, 'root-owned bundle checks require an isolated root test run')
class FirmwareLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.base = self.root / 'state/.private-firmware'
        self.dest = self.root / 'firmware'
        self.dest.mkdir()
        self.base.mkdir(parents=True, mode=0o700)
        for name in ('modem.mdt', 'mba.mbn', 'wcnss.mdt', 'wlan/prima/WCNSS_qcom_wlan_nv.bin'):
            p = self.base / name
            p.parent.mkdir(parents=True, exist_ok=True)
            for parent in p.parents:
                if parent == self.base.parent:
                    break
                parent.chmod(0o700)
            p.write_bytes(('owned-test-' + name).encode())
            p.chmod(0o600)
        self.manifest()
        # Only fixed absolute installation paths and mount verification change.
        text = SCRIPT.read_text().replace('/var/lib/nassimhub/.private-firmware', str(self.base))
        text = text.replace('/usr/lib/firmware', str(self.dest))
        text = text.replace('/usr/local/libexec/nassimhub-state-check', 'true')
        self.script = self.root / 'loader'
        self.script.write_text(text)

    def tearDown(self):
        self.tmp.cleanup()

    def manifest(self):
        rows = []
        for p in sorted(self.base.rglob('*')):
            if p.is_file() and p.name != 'SHA256SUMS':
                rows.append(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(self.base)))
        p = self.base / 'SHA256SUMS'
        p.write_text('\n'.join(rows) + '\n')
        p.chmod(0o600)

    def run_loader(self, *args):
        return subprocess.run(['sh', str(self.script), *args], capture_output=True, text=True)

    def assert_rejected(self):
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_verified_load_is_idempotent(self):
        self.assertEqual(self.run_loader('--check').returncode, 0)
        self.assertEqual(list(self.dest.iterdir()), [])
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertEqual(self.run_loader().returncode, 0)
        for p in self.base.rglob('*'):
            if p.is_file() and p.name != 'SHA256SUMS':
                self.assertEqual((self.dest / p.relative_to(self.base)).read_bytes(), p.read_bytes())

    def test_corruption_writes_nothing(self):
        (self.base / 'modem.mdt').write_bytes(b'corrupt')
        self.assert_rejected()

    def test_clean_image_without_firmware_directory(self):
        self.dest.rmdir()
        self.assertEqual(self.run_loader('--check').returncode, 0)
        self.assertFalse(self.dest.exists())
        result = self.run_loader()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.dest / 'modem.mdt').read_bytes(), (self.base / 'modem.mdt').read_bytes())

    def test_symlink_destination_rejected(self):
        self.dest.rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        self.dest.symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    def test_path_escape_rejected(self):
        with (self.base / 'SHA256SUMS').open('a') as f:
            f.write('a' * 64 + '  ../../etc/passwd\n')
        self.assert_rejected()

    def test_duplicate_rejected(self):
        p = self.base / 'SHA256SUMS'
        p.write_text(p.read_text() + p.read_text().splitlines()[0] + '\n')
        self.assert_rejected()

    def test_symlink_source_rejected(self):
        p = self.base / 'modem.mdt'
        p.unlink()
        p.symlink_to(self.base / 'mba.mbn')
        self.assert_rejected()

    def test_symlink_parent_rejected(self):
        p = self.base / 'wlan'
        p.rename(self.base / 'old-wlan')
        p.symlink_to(self.base / 'old-wlan', target_is_directory=True)
        self.assert_rejected()

    def test_world_writable_bundle_rejected(self):
        self.base.chmod(0o777)
        self.assert_rejected()

    def test_different_existing_firmware_preserved(self):
        (self.dest / 'modem.mdt').write_bytes(b'existing-firmware')
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertEqual((self.dest / 'modem.mdt').read_bytes(), b'existing-firmware')
        self.assertFalse((self.dest / 'mba.mbn').exists())

    def test_absent_bundle_does_not_provision_radio(self):
        self.base.rename(self.root / 'private-elsewhere')
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertEqual(list(self.dest.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
