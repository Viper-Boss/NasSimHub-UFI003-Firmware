import importlib.util
import pathlib
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('boot', ROOT/'kernel/audio/replace-appended-dtb.py')
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class ToolTests(unittest.TestCase):
    def test_boot_replacement_preserves_ramdisk_and_addresses(self):
        old = boot.FDT_MAGIC + struct.pack('>I', 40) + b'o' * 32
        new = boot.FDT_MAGIC + struct.pack('>I', 48) + b'n' * 40
        fields = [boot.MAGIC, 0, 0x80080000, 8, 0x81000000, 0,
                  0, 0x80000100, 2048, 0, 0, b'UFI003', b'root=LABEL=rootfs', b'', b'']
        source = {'fields': fields, 'page': 2048, 'ramdisk': b'ramdisk!', 'second': b''}
        original = boot.build(source, b'\x1f\x8bkernel' + old)
        parsed = boot.parse(original)
        rebuilt = boot.build(parsed, parsed['kernel'][:-len(old)] + new)
        result = boot.parse(rebuilt)
        self.assertEqual(result['ramdisk'], b'ramdisk!')
        self.assertEqual(result['fields'][2:13], boot.parse(original)['fields'][2:13])
        self.assertEqual(boot.split_kernel(result['kernel'])[1], new)
        self.assertEqual(boot.build(boot.parse(original), boot.parse(original)['kernel']), original)

    def test_boot_truncation_rejected(self):
        with self.assertRaises((SystemExit, struct.error)):
            boot.parse(b'ANDROID!')

    def test_populated_identity_and_password_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            (p/'etc').mkdir()
            (p/'etc/os-release').write_text('VERSION_ID="13"\n')
            (p/'etc/passwd').write_text('nassimhub:x:999:999::/nonexistent:/usr/sbin/nologin\n')
            (p/'etc/shadow').write_text('root:!:0:0:99999:7:::\n')
            def audit():
                return subprocess.run(['python3',str(ROOT/'scripts/audit-rootfs.py'),td],capture_output=True,text=True)
            self.assertEqual(audit().returncode, 0)
            state = p/'var/lib/nassimhub'
            state.mkdir(parents=True)
            secret = 'synthetic-secret-not-for-output'
            (state/'device.json').write_text(secret)
            failed = audit()
            self.assertNotEqual(failed.returncode, 0)
            self.assertNotIn(secret, failed.stdout + failed.stderr)
            (state/'device.json').unlink()
            (p/'etc/shadow').write_text('root:synthetic-password-hash:0:0:99999:7:::\n')
            self.assertNotEqual(audit().returncode, 0)


if __name__ == '__main__':
    unittest.main()
