import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


boot = load('boot', 'kernel/audio/replace-appended-dtb.py')
sys.path.insert(0, str(ROOT/'scripts'))
import genericrules as rules  # noqa: E402
import imagepolicy  # noqa: E402
privacy = load('privacy_check', 'scripts/privacy-check.py')
rootfs_audit = load('audit_rootfs', 'scripts/audit-rootfs.py')
sbom = load('sbom', 'scripts/sbom.py')

# Every fixture below is synthetic and obviously fake. Markers that the source
# privacy check itself looks for are assembled at run time so that this file
# does not contain them.
DASHES = '-' * 5
FAKE_BODY = base64.b64encode(hashlib.sha512(b'synthetic fixture, not a key').digest()).decode()
FAKE_PEM_KEY = f'{DASHES}BEGIN PRIVATE KEY{DASHES}\n{FAKE_BODY}\n{DASHES}END PRIVATE KEY{DASHES}\n'
FAKE_OPENSSH_KEY = f'{DASHES}BEGIN OPENSSH PRIVATE KEY{DASHES}\n{FAKE_BODY}\n{DASHES}END OPENSSH PRIVATE KEY{DASHES}\n'
FAKE_SEED = base64.b64encode(hashlib.sha256(b'synthetic seed fixture').digest()).decode()
FAKE_SEED_JSON = json.dumps({'version': 1, 'device_id': 'synthetic', 'private' + '_seed': FAKE_SEED})
FAKE_RELEASE_KEY = json.dumps({'version': 1, 'kind': 'nassimhub-release-' + 'ed25519', 'key_id': 'test', 'seed': FAKE_SEED}, indent=2)
FAKE_PUBLIC = base64.b64encode(hashlib.sha256(b'synthetic public key fixture').digest()).decode()
PUBLIC_KEYRING = json.dumps({'version': 1, 'ed25519': {'test-2026': FAKE_PUBLIC}}, indent=2) + '\n'
FAKE_IMEI = '0' * 15
FAKE_ICCID = '89' + '0' * 17
FAKE_PHONE = '+1' + '0' * 10


def write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        content = content.encode()
    path.write_bytes(content)
    path.chmod(mode)


def seal_package(package, keys=False, setup_ap=False):
    """(Re)write PACKAGE-MANIFEST.json so that it lists exactly what is in the package."""
    files = []
    for absolute, relative, info in rules.walk_files(package):
        if relative in ('PACKAGE-MANIFEST.json', 'SHA256SUMS'):
            continue
        entry = {'path': relative, 'mode': format(info.st_mode & 0o7777, '04o')}
        if rules.is_regular(info):
            entry.update(type='file', size=info.st_size, sha256=hashlib.sha256(pathlib.Path(absolute).read_bytes()).hexdigest())
        else:
            entry.update(type='symlink', target=os.readlink(absolute))
        files.append(entry)
    updates = ({'release_keys': True, 'status': 'release keys installed'} if keys
               else {'release_keys': False, 'status': 'updates disabled: no release keys'})
    access_point = {'enabled': setup_ap, 'status': imagepolicy.STATUS_ON if setup_ap else imagepolicy.STATUS_OFF}
    write(pathlib.Path(package)/'PACKAGE-MANIFEST.json',
          json.dumps({'schema': 1, 'updates': updates, 'setup_access_point': access_point, 'files': files}))


def make_package(directory, keys=False):
    """A minimal package with the layout package-factory.sh produces."""
    package = pathlib.Path(directory)/'package'
    write(package/'images/boot.img', b'ANDROID!' + b'\0' * 64)
    write(package/'images/rootfs.img', b'\0' * 4096 + b'synthetic ext4 payload' + b'\0' * 4096)
    write(package/'rootfs-overlay/usr/bin/nassimhub-agent', b'\x7fELF' + b'\0' * 9000, 0o755)
    write(package/'rootfs-overlay/etc/nassimhub/agent.conf', 'state_dir = /var/lib/nassimhub\nupdate_channel = stable\n')
    write(package/'rootfs-overlay/etc/NetworkManager/system-connections/nassimhub-usb.nmconnection',
          '[connection]\nid=nassimhub-usb\ntype=ethernet\n', 0o600)
    os.symlink('../nassimhub-agent.service', package/'rootfs-overlay/etc/nassimhub-agent.service')
    for name in ('LICENSE', 'NOTICE.md', 'SOURCE.md', 'THIRD-PARTY-NOTICES.md', 'DEBIAN-PACKAGES.txt'):
        write(package/name, 'synthetic text\n')
    write(package/'LICENSES/GPL-2.0-only.txt', 'synthetic licence text\n')
    write(package/'signatures/README.txt', 'not signed\n')
    write(package/'sbom.spdx.json', json.dumps({'spdxVersion': 'SPDX-2.3', 'checksum': hashlib.sha256(b'x').hexdigest()}))
    write(package/'SHA256SUMS', hashlib.sha256(b'x').hexdigest() + '  LICENSE\n')
    if keys:
        write(package/'rootfs-overlay/etc/nassimhub/ota-keys.json', PUBLIC_KEYRING)
    seal_package(package, keys)
    return package


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


class GenericPackageTests(unittest.TestCase):
    def test_public_selftest_exception_is_exact_and_does_not_hide_another_key(self):
        der = base64.b64decode(FAKE_BODY)
        other_body = base64.b64encode(hashlib.sha256(b'other synthetic key').digest()).decode()
        other = FAKE_PEM_KEY.replace(FAKE_BODY, other_body)
        with mock.patch.object(rules, '_PUBLIC_SELFTEST_KEYS', {hashlib.sha256(der).hexdigest()}):
            self.assertNotIn('private-key', rules.scan_bytes(FAKE_PEM_KEY.encode()))
            self.assertIn('private-key', rules.scan_bytes((FAKE_PEM_KEY + other).encode()))
            with tempfile.TemporaryDirectory() as td:
                image = pathlib.Path(td)/'image'
                write(image, b'\0' * 4080 + FAKE_PEM_KEY.encode() + other.encode())
                self.assertIn('private-key', rules.scan_stream(image, block=4096))

    """privacy-check.py --package: each kind of per-device or personal data, planted and caught."""

    def categories(self, package):
        return {category for category, _ in privacy.check_package(package)}

    def assertCaught(self, relative, content, expected, mode=0o644):
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td)
            self.assertEqual(privacy.check_package(package), [], 'the fixture package is not clean')
            write(package/relative, content, mode)
            seal_package(package)
            findings = privacy.check_package(package)
            self.assertIn((expected, relative), findings, f'{relative}: {expected} not reported; got {findings}')

    def test_clean_package_passes_with_and_without_release_keys(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(privacy.check_package(make_package(td)), [])
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(privacy.check_package(make_package(td, keys=True)), [])

    def test_device_identity(self):
        self.assertCaught('rootfs-overlay/var/lib/nassimhub/device.json', '{}', 'device-identity')
        self.assertCaught('rootfs-overlay/var/lib/nassimhub/pq-identity.json', '{}', 'device-identity')
        # The same content under a name nobody would look for.
        self.assertCaught('rootfs-overlay/etc/nassimhub/notes.txt', FAKE_SEED_JSON, 'device-identity')
        self.assertCaught('rootfs-overlay/etc/machine-id', '0' * 32 + '\n', 'device-identity')
        self.assertCaught('rootfs-overlay/etc/hostname', 'NSH-410-0A0B0C\n', 'device-identity')

    def test_pairing_state(self):
        self.assertCaught('rootfs-overlay/var/lib/nassimhub/pairing.json', '{}', 'pairing-state')
        self.assertCaught('rootfs-overlay/var/lib/nassimhub/transport-key.json', '{}', 'pairing-state')

    def test_admin_password_and_hash(self):
        self.assertCaught('rootfs-overlay/var/lib/nassimhub/admin.json', '{}', 'admin-password')
        self.assertCaught('rootfs-overlay/var/lib/nassimhub/admin-bootstrap.txt', 'synthetic\n', 'admin-password')
        credentials = json.dumps({'salt': 'c' * 32, 'hash': 'd' * 43})
        self.assertCaught('rootfs-overlay/etc/nassimhub/defaults.json', credentials, 'admin-password')
        self.assertCaught('rootfs-overlay/etc/shadow', 'root:$6$' + 'synthetic' * 4 + ':0:0:99999:7:::\n', 'admin-password')

    def test_wifi_credentials(self):
        profile = '[wifi-security]\nkey-mgmt=wpa-psk\npsk=synthetic-not-a-password\n'
        self.assertCaught('rootfs-overlay/etc/NetworkManager/system-connections/home.nmconnection', profile, 'wifi-credential', 0o600)
        self.assertCaught('rootfs-overlay/etc/wpa_supplicant/wpa_supplicant.conf', 'network={\n psk=synthetic-not-a-password\n}\n', 'wifi-credential')
        self.assertCaught('rootfs-overlay/etc/network/interfaces', 'iface wlan0 inet dhcp\n  wpa-psk synthetic-not-a-password\n', 'wifi-credential')
        # The USB profile is allowed only while it carries no secret.
        self.assertCaught('rootfs-overlay/etc/NetworkManager/system-connections/nassimhub-usb.nmconnection',
                          '[connection]\nid=nassimhub-usb\npsk=synthetic-not-a-password\n', 'wifi-credential', 0o600)

    def test_ssh_host_keys_and_authorized_keys(self):
        self.assertCaught('rootfs-overlay/etc/ssh/ssh_host_ed25519_key', FAKE_OPENSSH_KEY, 'ssh-key', 0o600)
        self.assertCaught('rootfs-overlay/etc/ssh/ssh_host_ed25519_key', FAKE_OPENSSH_KEY, 'private-key', 0o600)
        self.assertCaught('rootfs-overlay/etc/ssh/ssh_host_ed25519_key.pub', 'ssh-ed25519 synthetic\n', 'ssh-key')
        self.assertCaught('rootfs-overlay/root/.ssh/authorized_keys', 'ssh-ed25519 synthetic someone@example.invalid\n', 'ssh-key')
        self.assertCaught('rootfs-overlay/root/.ssh/id_ed25519', FAKE_OPENSSH_KEY, 'ssh-key', 0o600)

    def test_device_certificates_and_private_keys(self):
        self.assertCaught('rootfs-overlay/var/lib/nassimhub/device-cert.pem', 'synthetic\n', 'device-certificate')
        self.assertCaught('rootfs-overlay/var/lib/nassimhub/admin-tls-key.pem', FAKE_PEM_KEY, 'device-certificate', 0o600)
        self.assertCaught('rootfs-overlay/etc/ssl/private/server.key', 'synthetic\n', 'key-file')
        # A PEM private key is found by its content whatever the file is called.
        self.assertCaught('rootfs-overlay/usr/share/doc/readme.txt', 'see below\n' + FAKE_PEM_KEY, 'private-key')
        self.assertCaught('rootfs-overlay/usr/share/doc/readme2.txt', FAKE_OPENSSH_KEY, 'private-key')

    def test_release_private_key_is_never_shipped(self):
        self.assertCaught('rootfs-overlay/etc/nassimhub/test.ed25519.key', FAKE_RELEASE_KEY, 'release-private-key', 0o600)
        self.assertCaught('rootfs-overlay/etc/nassimhub/release.json', FAKE_RELEASE_KEY, 'release-private-key')
        with tempfile.TemporaryDirectory() as td:
            # A private key file installed where the public keyring belongs.
            package = make_package(td, keys=True)
            write(package/'rootfs-overlay/etc/nassimhub/ota-keys.json', FAKE_RELEASE_KEY)
            seal_package(package, keys=True)
            categories = self.categories(package)
            self.assertIn('release-key-file-not-public', categories)
            self.assertIn('release-private-key', categories)

    def test_modem_calibration_and_protected_partitions(self):
        for name in ('modemst1.bin', 'modemst2.img', 'fsg.img', 'fsc.bin', 'persist.img', 'ModemST1.bin.gz', 'backup.qcn'):
            self.assertCaught('images/' + name, b'synthetic', 'modem-calibration')
        self.assertCaught('rootfs-overlay/var/lib/rmtfs/modem_fs1', b'synthetic', 'modem-calibration')
        self.assertCaught('rootfs-overlay/boot/efi/modem_fsg', b'synthetic', 'modem-calibration')
        self.assertCaught('images/aboot.mbn', b'synthetic', 'protected-partition')
        self.assertCaught('images/sbl1.mbn', b'synthetic', 'protected-partition')
        # Only the two reviewed images belong in images/, whatever else is called.
        self.assertCaught('images/userdata.img', b'synthetic', 'unexpected-image')
        self.assertEqual(rules.partition_stem('persistent.conf'), 'persistent.conf')
        self.assertEqual(rules.name_findings('persistent.conf'), [])

    def test_imei_iccid_and_phone_numbers(self):
        self.assertCaught('rootfs-overlay/etc/nassimhub/modem.txt', f'IMEI: {FAKE_IMEI}\n', 'imei')
        self.assertCaught('rootfs-overlay/etc/nassimhub/modem.txt', f'imsi={FAKE_IMEI}\n', 'imsi')
        self.assertCaught('rootfs-overlay/etc/nassimhub/sim.txt', f'iccid = {FAKE_ICCID}\n', 'iccid')
        self.assertCaught('rootfs-overlay/etc/nassimhub/sim.txt', f'card {FAKE_ICCID} inserted\n', 'iccid')
        self.assertCaught('rootfs-overlay/etc/nassimhub/line.txt', f'own_number = {FAKE_PHONE}\n', 'phone-number')
        self.assertCaught('rootfs-overlay/etc/nassimhub/line.txt', f'forward to {FAKE_PHONE} always\n', 'phone-number')

    def test_logs_and_sms(self):
        self.assertCaught('rootfs-overlay/var/log/nassimhub/agent.log', 'synthetic\n', 'log')
        self.assertCaught('rootfs-overlay/var/log/nassimhub/agent.log.1', 'synthetic\n', 'log')
        self.assertCaught('rootfs-overlay/var/log/journal/system.journal', b'synthetic', 'log')
        self.assertCaught('rootfs-overlay/var/lib/nassimhub/sms-requests.json', '{}', 'sms')
        self.assertCaught('rootfs-overlay/root/sms-export.csv', 'synthetic\n', 'sms')
        self.assertCaught('rootfs-overlay/root/call.wav', b'RIFFsynthetic', 'recording')

    def test_per_device_acceptance_markers(self):
        self.assertCaught('rootfs-overlay/etc/nassimhub/local-volte.enabled', '', 'per-device-acceptance-marker')
        self.assertCaught('rootfs-overlay/etc/nassimhub/voice-audio.verified', '', 'per-device-acceptance-marker')

    def test_entropy_catches_an_unlabelled_secret_but_not_digests(self):
        token = base64.urlsafe_b64encode(hashlib.sha256(b'synthetic token fixture').digest()).decode().rstrip('=')
        self.assertCaught('rootfs-overlay/etc/nassimhub/extra.conf', f'setup = {token}\n', 'high-entropy-secret-like-value')
        self.assertCaught('rootfs-overlay/etc/nassimhub/blob.bin', hashlib.sha256(b'synthetic blob').digest(), 'opaque-binary-blob')
        digests = ''.join(hashlib.sha256(bytes([i])).hexdigest() + f'  file{i}\n' for i in range(50))
        self.assertFalse(rules.has_secret_like_token(digests))
        self.assertFalse(rules.has_secret_like_token('usr/local/libexec/nassimhub-state-check-and-some-more-path-text\n'))
        self.assertTrue(rules.has_secret_like_token(token))

    def test_key_material_inside_an_image_is_found_across_block_boundaries(self):
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td)
            for payload, expected in ((FAKE_PEM_KEY, 'private-key'), (FAKE_SEED_JSON, 'device-identity'), (FAKE_RELEASE_KEY, 'release-private-key')):
                write(package/'images/rootfs.img', b'\0' * 5000 + payload.encode() + b'\0' * 5000)
                seal_package(package)
                self.assertIn((expected, 'images/rootfs.img'), privacy.check_package(package))
            image = package/'images/rootfs.img'
            # Straddling the scanner's block boundary.
            write(image, b'\0' * (4096 - 20) + FAKE_PEM_KEY.encode() + b'\0' * 4096)
            self.assertIn('private-key', rules.scan_stream(str(image), block=4096, overlap=512))
            # The bare marker, as it appears as a constant in ssh-keygen, is not a key.
            write(image, b'\0' * 100 + f'{DASHES}BEGIN OPENSSH PRIVATE KEY{DASHES}\n'.encode() + b'\0usage: %s\0' * 10)
            self.assertEqual(rules.scan_stream(str(image)), [])

    def test_manifest_must_match_the_package(self):
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td)
            write(package/'rootfs-overlay/etc/nassimhub/agent.conf', 'state_dir = /somewhere/else\n')
            self.assertIn(('differs-from-package-manifest', 'rootfs-overlay/etc/nassimhub/agent.conf'), privacy.check_package(package))
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td)
            write(package/'extra.txt', 'synthetic\n')
            findings = privacy.check_package(package)
            self.assertIn(('unexpected-file', 'extra.txt'), findings)
            self.assertIn(('not-in-package-manifest', 'extra.txt'), findings)
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td)
            (package/'NOTICE.md').unlink()
            self.assertIn(('listed-but-missing', 'NOTICE.md'), privacy.check_package(package))

    def test_manifest_must_say_when_updates_are_disabled(self):
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td)
            seal_package(package, keys=True)  # claims keys that are not there
            self.assertIn(('manifest-misstates-release-keys', 'PACKAGE-MANIFEST.json'), privacy.check_package(package))
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td, keys=True)
            seal_package(package, keys=False)  # ships keys but says updates are disabled
            self.assertIn(('manifest-misstates-release-keys', 'PACKAGE-MANIFEST.json'), privacy.check_package(package))
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td, keys=True)
            (package/'rootfs-overlay/etc/nassimhub/ota-keys.json').chmod(0o666)
            seal_package(package, keys=True)
            self.assertIn(('release-key-file-mode', 'rootfs-overlay/etc/nassimhub/ota-keys.json'), privacy.check_package(package))

    def test_findings_never_echo_the_value(self):
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td)
            write(package/'rootfs-overlay/etc/nassimhub/notes.txt', FAKE_SEED_JSON + f'\nIMEI: {FAKE_IMEI}\n' + FAKE_PEM_KEY)
            seal_package(package)
            result = subprocess.run([sys.executable, str(ROOT/'scripts/privacy-check.py'), '--package', str(package)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            for secret in (FAKE_SEED, FAKE_IMEI, FAKE_BODY):
                self.assertNotIn(secret, result.stdout + result.stderr)

    def test_public_keyring_shape(self):
        self.assertIsNone(rules.public_keyring_problem(PUBLIC_KEYRING.encode()))
        self.assertIsNotNone(rules.public_keyring_problem(FAKE_RELEASE_KEY.encode()))
        self.assertIsNotNone(rules.public_keyring_problem(b'{"version":1,"ed25519":{}}'))
        self.assertIsNotNone(rules.public_keyring_problem(json.dumps({'version': 1, 'ed25519': {'k': 'c2hvcnQ='}}).encode()))
        self.assertIsNotNone(rules.public_keyring_problem(json.dumps({'version': 1, 'ed25519': {'k': FAKE_PUBLIC}, 'seed': 'x'}).encode()))
        self.assertIsNotNone(rules.public_keyring_problem(json.dumps({'version': 1, 'ed25519': {'k': FAKE_PUBLIC}, 'ml_dsa': {'k': {'algorithm': 'ml-dsa-87', 'public_key': FAKE_PUBLIC}}}).encode()))
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td)/'key.json'
            write(path, FAKE_RELEASE_KEY)
            result = subprocess.run([sys.executable, str(ROOT/'scripts/privacy-check.py'), '--public-keyring', str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(FAKE_SEED, result.stdout + result.stderr)

    def test_ota_release_directory(self):
        with tempfile.TemporaryDirectory() as td:
            release = pathlib.Path(td)
            write(release/'nassimhub-agent', b'\x7fELF' + b'\0' * 9000, 0o755)
            write(release/'manifest.json', json.dumps({'release_id': 'agent-9.9.1', 'version': '9.9.1'}))
            write(release/'manifest.signed.json', json.dumps({'manifest': {'release_id': 'agent-9.9.1'}, 'key_id': 'test-2026', 'signature': FAKE_BODY}))
            write(release/'ota-keys.json', PUBLIC_KEYRING)
            write(release/'SHA256SUMS', hashlib.sha256(b'x').hexdigest() + '  nassimhub-agent\n')
            self.assertEqual(privacy.check_ota_release(release), [])
            write(release/'test-2026.ed25519.key', FAKE_RELEASE_KEY, 0o600)
            findings = privacy.check_ota_release(release)
            self.assertIn(('release-private-key', 'test-2026.ed25519.key'), findings)
            self.assertIn(('unexpected-file', 'test-2026.ed25519.key'), findings)


class RootfsAuditTests(unittest.TestCase):
    """audit-rootfs.py on a tree shaped like a Debian root filesystem."""

    def clean(self, td):
        root = pathlib.Path(td)
        write(root/'etc/os-release', 'VERSION_ID="13"\n')
        write(root/'etc/passwd', 'nassimhub:x:999:999::/nonexistent:/usr/sbin/nologin\n')
        write(root/'etc/shadow', 'root:!:0:0:99999:7:::\n')
        write(root/'etc/machine-id', '')
        write(root/'etc/nassimhub/agent.conf', 'state_dir = /var/lib/nassimhub\n')
        # Things a real Debian tree has that must NOT trip the audit:
        write(root/'etc/ssl/certs/ca-certificates.crt', f'{DASHES}BEGIN CERTIFICATE{DASHES}\n{FAKE_BODY}\n{DASHES}END CERTIFICATE{DASHES}\n')
        write(root/'usr/share/ca-certificates/mozilla/Synthetic_Root.pem', f'{DASHES}BEGIN CERTIFICATE{DASHES}\n{FAKE_BODY}\n')
        write(root/'usr/bin/ssh-keygen', b'\x7fELF\0' + f'{DASHES}BEGIN OPENSSH PRIVATE KEY{DASHES}\n'.encode() + b'\0%s\0' * 20, 0o755)
        write(root/'usr/lib/python3/dist-packages/synthetic/device.json', '{"model": "generic"}\n')
        write(root/'usr/share/doc/synthetic/changelog.log', 'packaged text\n')
        write(root/'etc/pam.d/common-password', 'password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n')
        (root/'var/lib/nassimhub').mkdir(parents=True)
        (root/'var/log').mkdir(parents=True)
        return root

    def assertRejected(self, relative, content, expected, mode=0o644):
        with tempfile.TemporaryDirectory() as td:
            root = self.clean(td)
            self.assertEqual(rootfs_audit.audit(root), [], 'the fixture rootfs is not clean')
            write(root/relative, content, mode)
            findings = rootfs_audit.audit(root)
            self.assertTrue(any(expected in finding for finding in findings), f'{relative}: {expected!r} not in {findings}')

    def test_clean_debian_like_tree_passes(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(rootfs_audit.audit(self.clean(td)), [])

    def test_reviewed_vendor_script_exception_requires_exact_file_bytes(self):
        text = 'passwd=$(getent passwd "$user")\n'
        with tempfile.TemporaryDirectory() as td:
            root = self.clean(td)
            write(root/'etc/security/namespace.init', text)
            expected = hashlib.sha256(text.encode()).hexdigest()
            with mock.patch.object(rootfs_audit, 'PUBLIC_CONFIG_SCRIPTS', {'etc/security/namespace.init': expected}):
                self.assertEqual(rootfs_audit.audit(root), [])
                write(root/'etc/security/namespace.init', text + 'password=synthetic-test-password\n')
                self.assertIn('credential: etc/security/namespace.init', rootfs_audit.audit(root))

    def test_public_release_keys_are_allowed_private_ones_are_not(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.clean(td)
            write(root/'etc/nassimhub/ota-keys.json', PUBLIC_KEYRING)
            self.assertEqual(rootfs_audit.audit(root), [])
            (root/'etc/nassimhub/ota-keys.json').chmod(0o664)
            self.assertTrue(any('release-key-file-writable' in f for f in rootfs_audit.audit(root)))
        self.assertRejected('etc/nassimhub/ota-keys.json', FAKE_RELEASE_KEY, 'release-key-file-not-public')
        self.assertRejected('etc/nassimhub/local-volte.enabled', 'x', 'etc/nassimhub')
        self.assertRejected('etc/nassimhub/extra.conf', 'x = 1\n', 'unexpected file in etc/nassimhub')

    def test_offenders(self):
        self.assertRejected('root/.ssh/authorized_keys', 'ssh-ed25519 synthetic someone@example.invalid\n', 'root/.ssh')
        self.assertRejected('opt/tools/authorized_keys', 'ssh-ed25519 synthetic someone@example.invalid\n', 'ssh-key: opt/tools/authorized_keys')
        self.assertRejected('etc/ssh/ssh_host_ed25519_key', FAKE_OPENSSH_KEY, 'etc/ssh/ssh_host_ed25519_key', 0o600)
        self.assertRejected('etc/ssl/private/ssl-cert-snakeoil.key', FAKE_PEM_KEY, 'etc/ssl/private', 0o600)
        self.assertRejected('usr/share/synthetic/leftover.txt', FAKE_PEM_KEY, 'private-key: usr/share/synthetic/leftover.txt')
        self.assertRejected('var/lib/rmtfs/modem_fs1', b'synthetic', 'var/lib/rmtfs')
        self.assertRejected('lib/firmware/modemst1.bin', b'synthetic', 'modem-calibration: lib/firmware/modemst1.bin')
        self.assertRejected('persist/sensors/calibration.bin', b'synthetic', 'persist')
        self.assertRejected('var/log/apt/history.log', 'synthetic\n', 'log: var/log/apt/history.log')
        self.assertRejected('var/lib/systemd/random-seed', b'synthetic-seed', 'var/lib/systemd/random-seed')
        self.assertRejected('etc/machine-id', '0' * 32 + '\n', 'etc/machine-id')
        self.assertRejected('etc/wpa_supplicant/wpa_supplicant-wlan0.conf', 'network={\n psk=synthetic-not-a-password\n}\n', 'wifi-credential')
        self.assertRejected('etc/NetworkManager/system-connections/home.nmconnection', '[wifi]\nssid=synthetic\n', 'etc/NetworkManager/system-connections/home.nmconnection')
        self.assertRejected('etc/modem-notes', f'IMEI: {FAKE_IMEI}\n', 'imei: etc/modem-notes')
        self.assertRejected('etc/sim-notes', f'ICCID {FAKE_ICCID}\n', 'iccid: etc/sim-notes')
        self.assertRejected('etc/line-notes', f'phone number: {FAKE_PHONE}\n', 'phone-number: etc/line-notes')
        self.assertRejected('opt/backup/device.json', FAKE_SEED_JSON, 'device-identity: opt/backup/device.json')
        self.assertRejected('opt/backup/admin.json', json.dumps({'salt': 'c' * 32, 'hash': 'd' * 43}), 'admin-password: opt/backup/admin.json')
        self.assertRejected('opt/backup/pairing.json', '{}', 'pairing-state')
        self.assertRejected('var/lib/nassimhub/agent-releases/agent-1/manifest.json', '{}', 'var/lib/nassimhub')
        self.assertRejected('etc/shadow-', 'root:$6$' + 'synthetic' * 4 + ':0:0:99999:7:::\n', 'etc/shadow-')

    def test_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            root = self.clean(td)
            write(pathlib.Path(outside)/'secret.txt', FAKE_PEM_KEY)
            os.symlink(pathlib.Path(outside)/'secret.txt', root/'etc/link-out')
            os.symlink(outside, root/'opt')
            self.assertEqual(rootfs_audit.audit(root), [])


class ImagePolicyTests(unittest.TestCase):
    """What the image grants the agent user, and the opt-in setup access point."""

    POLKIT = 'etc/polkit-1/rules.d/'
    DROPINS = 'etc/systemd/system/nassimhub-agent.service.d/'
    SHARE = 'org.freedesktop.NetworkManager.wifi.share.protected'

    def staged(self, td, setup_ap=False):
        """The tree package-factory.sh stages: clean rootfs + overlay + units (+ the fragment)."""
        root = RootfsAuditTests.clean(self, td)
        shutil.copytree(ROOT/'firmware/overlay', root, dirs_exist_ok=True)
        write(root/'etc/systemd/system/nassimhub-agent.service', (ROOT/'node/deploy/nassimhub-agent.service').read_text())
        write(root/self.DROPINS/'resources.conf', (ROOT/'node/deploy/nassimhub-agent-resources.conf').read_text())
        write(root/'etc/nassimhub/agent.conf', (ROOT/'node/deploy/agent.conf').read_text())
        (root/'etc/NetworkManager/system-connections/nassimhub-usb.nmconnection').chmod(0o600)
        if setup_ap:
            shutil.copytree(ROOT/'firmware/setup-ap-overlay', root, dirs_exist_ok=True)
            write(root/'etc/nassimhub/agent.conf', imagepolicy.enable_setup_ap((ROOT/'node/deploy/agent.conf').read_text()))
            write(root/'usr/sbin/dnsmasq', b'\x7fELF synthetic', 0o755)
        return root

    def rule(self, actions, user='nassimhub'):
        listed = ', '.join(f'"{action}"' for action in actions)
        return ('polkit.addRule(function(action, subject) {\n    var allowed = [' + listed + '];\n'
                f'    if (subject.user === "{user}" && allowed.indexOf(action.id) >= 0) {{\n        return polkit.Result.YES;\n    }}\n}});\n')

    def test_default_image_passes_and_has_no_capability(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.staged(td)
            self.assertEqual(rootfs_audit.audit(root), [])
            texts, dropins = imagepolicy.agent_unit_texts(str(root))
            settings = imagepolicy.unit_settings(texts)
            self.assertEqual([d.rsplit('/', 1)[-1] for d in dropins], ['persistent.conf', 'resources.conf'])
            self.assertEqual(imagepolicy.words(settings, 'CapabilityBoundingSet'), [])
            self.assertEqual(imagepolicy.words(settings, 'AmbientCapabilities'), [])
            # Asking for the access point without its files is refused too.
            findings = rootfs_audit.audit(root, setup_ap=True)
            for expected in ('setup-ap-incomplete: missing ' + imagepolicy.SETUP_AP_POLKIT_FILE,
                             'setup-ap-incomplete: missing ' + imagepolicy.SETUP_AP_DROPIN_FILE,
                             'setup-ap-incomplete: etc/nassimhub/agent.conf does not enable it',
                             'setup-ap-incomplete: no usr/sbin/dnsmasq (Debian package dnsmasq-base)'):
                self.assertIn(expected, findings)

    def test_fragment_is_accepted_only_with_the_switch(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.staged(td, setup_ap=True)
            self.assertEqual(rootfs_audit.audit(root, setup_ap=True), [])
            findings = rootfs_audit.audit(root)
            self.assertIn('setup-ap-file-without-switch: ' + imagepolicy.SETUP_AP_POLKIT_FILE, findings)
            self.assertIn('setup-ap-file-without-switch: ' + imagepolicy.SETUP_AP_DROPIN_FILE, findings)
            self.assertIn('setup-ap-configured-without-switch: etc/nassimhub/agent.conf', findings)
            self.assertIn('agent-unit-capabilities: AmbientCapabilities grants CAP_NET_BIND_SERVICE', findings)
            self.assertIn('agent-unit-capabilities: CapabilityBoundingSet grants CAP_NET_BIND_SERVICE', findings)
            # The command line carries the switch the same way.
            script = str(ROOT/'scripts/audit-rootfs.py')
            self.assertEqual(subprocess.run(['python3', script, '--setup-ap', td], capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run(['python3', script, td], capture_output=True).returncode, 1)
            (root/'usr/sbin/dnsmasq').unlink()
            self.assertIn('setup-ap-incomplete: no usr/sbin/dnsmasq (Debian package dnsmasq-base)', rootfs_audit.audit(root, setup_ap=True))

    def test_committed_rules_grant_exactly_the_documented_actions(self):
        table = imagepolicy.documented_polkit(setup_ap=True)
        for overlay in ('firmware/overlay', 'firmware/setup-ap-overlay'):
            for path in sorted((ROOT/overlay/self.POLKIT).glob('*.rules')):
                relative = self.POLKIT + path.name
                self.assertEqual(imagepolicy.polkit_grant(path.read_text()), ('nassimhub', set(table[relative])), relative)
        self.assertEqual(set(imagepolicy.SETUP_AP_POLKIT[imagepolicy.SETUP_AP_POLKIT_FILE]), {self.SHARE})
        for actions in table.values():
            self.assertFalse(set(actions) & imagepolicy.NEVER_GRANTED)
            self.assertTrue(all(reason for reason in actions.values()), 'every grant needs a stated reason')
        # network-control is NOT part of the fragment: it is the base rule's, and
        # the access point adds one action, not a second copy of a broad one.
        self.assertNotIn('org.freedesktop.NetworkManager.network-control', imagepolicy.SETUP_AP_POLKIT[imagepolicy.SETUP_AP_POLKIT_FILE])

    def test_a_rule_granting_more_than_documented_fails(self):
        base = sorted(imagepolicy.BASE_POLKIT[self.POLKIT + '49-nassimhub-networkmanager.rules'])
        cases = [
            # (file, content, switch, expected finding)
            (imagepolicy.SETUP_AP_POLKIT_FILE, self.rule([self.SHARE, 'org.freedesktop.NetworkManager.wifi.share.open']), True,
             'polkit-grants-undocumented-action: ' + imagepolicy.SETUP_AP_POLKIT_FILE + ' (org.freedesktop.NetworkManager.wifi.share.open)'),
            (imagepolicy.SETUP_AP_POLKIT_FILE, self.rule([self.SHARE, 'org.freedesktop.NetworkManager.network-control']), True,
             'polkit-grants-undocumented-action'),
            # The share action smuggled into the base rule, with or without the switch.
            (self.POLKIT + '49-nassimhub-networkmanager.rules', self.rule(base + [self.SHARE]), False, 'polkit-grants-undocumented-action'),
            (self.POLKIT + '49-nassimhub-networkmanager.rules', self.rule(base + [self.SHARE]), True, 'polkit-grants-undocumented-action'),
            (imagepolicy.SETUP_AP_POLKIT_FILE, self.rule([self.SHARE], user='www-data'), True, 'polkit-rule-for-another-user'),
            # Shapes that can grant more than a list of names: not interpreted, refused.
            (imagepolicy.SETUP_AP_POLKIT_FILE, 'polkit.addRule(function(action, subject) {\n    if (subject.user === "nassimhub" && '
             'action.id.indexOf("org.freedesktop.NetworkManager.") === 0) {\n        return polkit.Result.YES;\n    }\n});\n', True, 'polkit-rule-unrecognised'),
            (imagepolicy.SETUP_AP_POLKIT_FILE, 'polkit.addRule(function(action, subject) {\n    if (subject.user === "nassimhub") {\n'
             '        return polkit.Result.YES;\n    }\n});\n', True, 'polkit-rule-unrecognised'),
            (imagepolicy.SETUP_AP_POLKIT_FILE, self.rule([self.SHARE]) + 'polkit.addRule(function(action, subject) { return polkit.Result.YES; });\n',
             True, 'polkit-rule-unrecognised'),
            (imagepolicy.SETUP_AP_POLKIT_FILE, self.rule([self.SHARE]).replace('&&', '||'), True, 'polkit-rule-unrecognised'),
            # A rule file for the agent user that nobody documented.
            (self.POLKIT + '60-nassimhub-extra.rules', self.rule(['org.freedesktop.login1.reboot']), True, 'polkit-rule-not-expected'),
            (self.POLKIT + '60-local.rules', self.rule(['org.freedesktop.login1.reboot']), False, 'polkit-rule-not-expected'),
            ('usr/share/polkit-1/rules.d/60-vendor.rules', self.rule(['org.freedesktop.login1.reboot']), False, 'polkit-rule-not-expected'),
            # The per-device voice rule belongs to install-voice.sh, never to an image.
            (self.POLKIT + '51-nassimhub-modemmanager-voice.rules', (ROOT/'node/deploy/audio/51-nassimhub-modemmanager-voice.rules').read_text(),
             False, 'polkit-rule-not-expected'),
        ]
        for relative, content, switch, expected in cases:
            with tempfile.TemporaryDirectory() as td:
                root = self.staged(td, setup_ap=switch)
                self.assertEqual(rootfs_audit.audit(root, setup_ap=switch), [])
                write(root/relative, content)
                findings = rootfs_audit.audit(root, setup_ap=switch)
                self.assertTrue(any(expected in finding for finding in findings), f'{relative}: {expected!r} not in {findings}')
        # Somebody else's rule that does not concern the agent user is not this audit's business.
        with tempfile.TemporaryDirectory() as td:
            root = self.staged(td)
            write(root/'usr/share/polkit-1/rules.d/50-default.rules',
                  'polkit.addAdminRule(function(action, subject) {\n    return ["unix-group:sudo"];\n});\n')
            self.assertEqual(rootfs_audit.audit(root), [])

    def test_capabilities_drop_ins_and_sysctl(self):
        cases = [
            (self.DROPINS + 'setup-ap.conf', '[Service]\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n',
             True, 'agent-unit-capabilities: CapabilityBoundingSet grants CAP_NET_ADMIN'),
            (self.DROPINS + 'setup-ap.conf', '[Service]\nCapabilityBoundingSet=~CAP_SYS_ADMIN\n', True, 'uses an inverted list'),
            (self.DROPINS + 'resources.conf', '[Service]\nProtectProc=default\nAmbientCapabilities=CAP_NET_RAW\n', False,
             'agent-unit-capabilities: AmbientCapabilities grants CAP_NET_RAW'),
            (self.DROPINS + 'zz-local.conf', '[Service]\nUser=root\n', False, 'agent-unit-runs-as-root'),
            (self.DROPINS + 'zz-local.conf', '[Service]\nMemoryMax=1G\n', False, 'agent-unit-drop-in-not-expected'),
            (self.DROPINS + 'voice.conf', (ROOT/'node/deploy/audio/nassimhub-agent-voice.conf').read_text(), False, 'agent-unit-drop-in-not-expected'),
            ('etc/sysctl.d/90-ports.conf', 'net.ipv4.ip_unprivileged_port_start = 80\n', False, 'unprivileged-port-sysctl: etc/sysctl.d/90-ports.conf'),
            ('etc/sysctl.conf', '# local\nnet/ipv4/ip_unprivileged_port_start=0\n', True, 'unprivileged-port-sysctl: etc/sysctl.conf'),
        ]
        for relative, content, switch, expected in cases:
            with tempfile.TemporaryDirectory() as td:
                root = self.staged(td, setup_ap=switch)
                write(root/relative, content)
                findings = rootfs_audit.audit(root, setup_ap=switch)
                self.assertTrue(any(expected in finding for finding in findings), f'{relative}: {expected!r} not in {findings}')
        # A unit with no bounding set at all has every capability.
        with tempfile.TemporaryDirectory() as td:
            root = self.staged(td)
            unit = root/'etc/systemd/system/nassimhub-agent.service'
            unit.write_text(unit.read_text().replace('CapabilityBoundingSet=\n', ''))
            self.assertIn('agent-unit-capabilities: CapabilityBoundingSet is not set', rootfs_audit.audit(root))

    def test_fragment_changes_the_capability_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as plain, tempfile.TemporaryDirectory() as enabled:
            before = imagepolicy.unit_settings(imagepolicy.agent_unit_texts(str(self.staged(plain)))[0])
            after = imagepolicy.unit_settings(imagepolicy.agent_unit_texts(str(self.staged(enabled, setup_ap=True)))[0])
        changed = {key for key in set(before) | set(after) if before.get(key) != after.get(key)}
        self.assertEqual(changed, {('Service', 'CapabilityBoundingSet'), ('Service', 'AmbientCapabilities'), ('Service', 'SocketBindDeny')})
        self.assertEqual(after[('Service', 'CapabilityBoundingSet')], ['CAP_NET_BIND_SERVICE'])
        self.assertEqual(after[('Service', 'AmbientCapabilities')], ['CAP_NET_BIND_SERVICE'])
        # Everything below 1024 except 80/tcp stays closed to the agent.
        self.assertEqual(after[('Service', 'SocketBindDeny')], ['tcp:1-79', 'tcp:81-1023', 'udp:1-1023'])
        for key in ('NoNewPrivileges', 'PrivateDevices', 'ProtectSystem', 'ProtectKernelTunables', 'ProtectKernelModules', 'RestrictNamespaces',
                    'MemoryDenyWriteExecute', 'SystemCallFilter', 'RestrictAddressFamilies', 'User', 'Restart'):
            self.assertTrue(before[('Service', key)], key)
            self.assertEqual(before[('Service', key)], after[('Service', key)], key)

    def test_unit_hardening_hides_no_telemetry_source(self):
        """node/agent/internal/systemstats reads /sys and /proc as the service user."""
        for setup_ap in (False, True):
            with tempfile.TemporaryDirectory() as td:
                settings = imagepolicy.unit_settings(imagepolicy.agent_unit_texts(str(self.staged(td, setup_ap)))[0])
            self.assertEqual(imagepolicy.telemetry_blockers(settings), [])
            # Read-only is what these two do to /sys and /proc/sys; reading is all the agent does.
            self.assertEqual(imagepolicy.last(settings, 'ProtectKernelTunables'), 'yes')
            self.assertEqual(imagepolicy.last(settings, 'ProtectSystem'), 'strict')
        # The base unit alone hides other users' processes; the resources drop-in is what lifts it.
        base = imagepolicy.unit_settings([(ROOT/'node/deploy/nassimhub-agent.service').read_text()])
        self.assertEqual([directive for directive, _ in imagepolicy.telemetry_blockers(base)], ['ProtectProc=invisible'])
        for text, directive in (('ProcSubset=pid', 'ProcSubset=pid'), ('PrivateNetwork=yes', 'PrivateNetwork=yes'),
                                ('InaccessiblePaths=/sys/class/thermal', 'InaccessiblePaths=/sys/class/thermal'),
                                ('TemporaryFileSystem=/run:ro', 'TemporaryFileSystem=/run:ro'),
                                ('BindReadOnlyPaths=/dev/null:/proc/net/dev', 'BindReadOnlyPaths=/dev/null:/proc/net/dev'),
                                ('InaccessiblePaths=-/sys/block/mmcblk0/device/life_time', 'InaccessiblePaths=-/sys/block/mmcblk0/device/life_time')):
            blocked = imagepolicy.telemetry_blockers(imagepolicy.unit_settings(['[Service]\n' + text + '\n']))
            self.assertEqual([found for found, _ in blocked][:1], [directive])
        self.assertEqual(imagepolicy.telemetry_blockers(imagepolicy.unit_settings(['[Service]\nInaccessiblePaths=/boot\nBindReadOnlyPaths=/etc/ssl\n'])), [])

    def test_enabling_rewrites_only_the_two_keys(self):
        shipped = (ROOT/'node/deploy/agent.conf').read_text()
        self.assertFalse(imagepolicy.conf_enables_setup_ap(shipped), 'the shipped configuration must keep the access point off')
        enabled = imagepolicy.enable_setup_ap(shipped)
        self.assertTrue(imagepolicy.conf_enables_setup_ap(enabled))
        self.assertNotIn('is off until', enabled)
        self.assertIn('NOT yet verified on hardware', enabled)
        def keys(text):
            return {line.split('=', 1)[0].strip(): line.split('=', 1)[1].strip() for line in text.splitlines() if '=' in line and not line.startswith('#')}
        before, after = keys(shipped), keys(enabled)
        self.assertEqual({key for key in before if before[key] != after[key]}, {'provisioning', 'provisioning_ap'})
        self.assertEqual(set(before), set(after))
        # provisioning_ap = auto alone does nothing: provisioning = false turns the access point off.
        self.assertFalse(imagepolicy.conf_enables_setup_ap('provisioning = false\nprovisioning_ap = auto\n'))
        for broken in ('provisioning = false\n', 'provisioning_ap = off\n', 'provisioning = false\nprovisioning_ap = off\nprovisioning_ap = off\n'):
            with self.assertRaises(ValueError):
                imagepolicy.enable_setup_ap(broken)

    def test_package_manifest_must_state_the_setup_access_point(self):
        def categories(package):
            return {category for category, _ in privacy.check_package(package)}
        with tempfile.TemporaryDirectory() as td:
            package = make_package(td)
            self.assertEqual(privacy.check_package(package), [])
            overlay = package/'rootfs-overlay'
            # The fragment and the enabling configuration appear; the manifest still says "not enabled".
            for relative in imagepolicy.SETUP_AP_FILES:
                write(overlay/relative, (ROOT/'firmware/setup-ap-overlay'/relative).read_text())
            write(overlay/'etc/nassimhub/agent.conf', imagepolicy.enable_setup_ap((ROOT/'node/deploy/agent.conf').read_text()))
            seal_package(package)
            self.assertIn('manifest-misstates-setup-access-point', categories(package))
            self.assertIn('setup-ap-file-without-switch', categories(package))
            seal_package(package, setup_ap=True)
            self.assertEqual(privacy.check_package(package), [])
            # Half of it is refused whatever the manifest says.
            (overlay/imagepolicy.SETUP_AP_DROPIN_FILE).unlink()
            seal_package(package, setup_ap=True)
            self.assertIn('setup-ap-incomplete', categories(package))
        with tempfile.TemporaryDirectory() as td:
            # "enabled" claimed for a package that has none of it.
            package = make_package(td)
            seal_package(package, setup_ap=True)
            self.assertEqual(categories(package), {'manifest-misstates-setup-access-point'})
        with tempfile.TemporaryDirectory() as td:
            # A manifest from before this field existed says nothing, which is not "not enabled".
            package = make_package(td)
            manifest = json.loads((package/'PACKAGE-MANIFEST.json').read_text())
            del manifest['setup_access_point']
            write(package/'PACKAGE-MANIFEST.json', json.dumps(manifest))
            self.assertEqual(categories(package), {'manifest-misstates-setup-access-point'})
        with tempfile.TemporaryDirectory() as td:
            # The generated passphrase of one device must never be in a package.
            package = make_package(td)
            write(package/'rootfs-overlay/var/lib/nassimhub/setup-ap-passphrase', 'abcd-efgh-jkmn-pqrs\n', 0o600)
            seal_package(package)
            self.assertIn(('wifi-credential', 'rootfs-overlay/var/lib/nassimhub/setup-ap-passphrase'), privacy.check_package(package))

    def test_package_list_names_what_install_md_names(self):
        packages = json.loads((ROOT/'firmware/debian-packages.json').read_text())
        install = (ROOT/'docs/INSTALL.md').read_text()
        for name in packages['base'] + packages['setup_access_point']['packages']:
            self.assertIn(name, install, f'{name} is in firmware/debian-packages.json but not in docs/INSTALL.md')
        self.assertEqual(imagepolicy.required_packages(str(ROOT)), ['dnsmasq-base'])


class SbomTests(unittest.TestCase):
    BSD3 = ('Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following '
            'conditions are met: ... Neither the name of the copyright holder nor the names of its contributors may be used to endorse ... '
            'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"')
    MIT = ('Permission is hereby granted, free of charge, to any person obtaining a copy of this software ... '
           'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND')

    def test_licence_is_recognised_from_text_or_not_asserted(self):
        self.assertEqual(sbom.classify_licence(self.BSD3), 'BSD-3-Clause')
        self.assertEqual(sbom.classify_licence(self.BSD3.replace('Neither the name of the copyright holder nor the names of its contributors may be used to endorse', '')), 'BSD-2-Clause')
        self.assertEqual(sbom.classify_licence(self.MIT), 'MIT')
        self.assertIsNone(sbom.classify_licence('All rights reserved. Ask the author.'))
        self.assertIsNone(sbom.classify_licence(self.MIT + self.BSD3))  # two licences in one file: a person decides
        # GNU texts do not say -only or -or-later; never guessed.
        self.assertIsNone(sbom.classify_licence('GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007'))
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(sbom.licence_of_directory(td)[0], 'NOASSERTION')
            self.assertEqual(sbom.licence_of_directory(os.path.join(td, 'missing'))[0], 'NOASSERTION')
            write(pathlib.Path(td)/'LICENSE', self.BSD3)
            self.assertEqual(sbom.licence_of_directory(td)[0], 'BSD-3-Clause')
            write(pathlib.Path(td)/'LICENSE-EXTRA.txt', 'something unusual')
            self.assertEqual(sbom.licence_of_directory(td)[0], 'NOASSERTION')

    def test_module_metadata_queries_linked_modules_not_unrelated_tests(self):
        modules = ['example.invalid/linked', 'example.invalid/local']
        output = json.dumps({'Path': modules[0], 'Dir': '/cache/linked'}) + '\n' + json.dumps({'Path': modules[1], 'Replace': {'Dir': '/checkout/node/proto'}})
        with patch.object(sbom, 'run', return_value=output) as run:
            self.assertEqual(sbom.module_directories('/checkout/node/agent', modules),
                             {modules[0]: '/cache/linked', modules[1]: '/checkout/node/proto'})
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[-2:], modules)
        self.assertNotIn('all', arguments)

    def module(self, name, version, licence):
        return {'SPDXID': sbom.spdx_id(f'GoModule-{name}-{version}'), 'name': name, 'versionInfo': version, 'licenseConcluded': licence}

    def test_policy_fails_on_unknown_licences_unless_allowlisted_with_a_reason(self):
        policy = {'allowed': ['BSD-3-Clause', 'MIT'], 'allowlist': []}
        good = {'packages': [self.module('example.invalid/a', 'v1.0.0', 'BSD-3-Clause'), self.module('example.invalid/b', 'v1.0.0', 'MIT AND BSD-3-Clause'),
                             {'SPDXID': 'SPDXRef-Kernel', 'name': 'kernel', 'licenseConcluded': 'NOASSERTION'}]}
        self.assertEqual(sbom.check_policy(good, policy), [])
        unknown = {'packages': [self.module('example.invalid/c', 'v1.0.0', 'NOASSERTION')]}
        self.assertEqual(len(sbom.check_policy(unknown, policy)), 1)
        disallowed = {'packages': [self.module('example.invalid/d', 'v1.0.0', 'SSPL-1.0')]}
        self.assertEqual(len(sbom.check_policy(disallowed, policy)), 1)
        entry = {'module': 'example.invalid/c', 'version': 'v1.0.0', 'licence': 'custom', 'reason': 'reviewed: permissive text in README'}
        self.assertEqual(sbom.check_policy(unknown, dict(policy, allowlist=[entry])), [])
        # Another version of the same module is not covered, and an entry without a reason is itself a failure.
        self.assertEqual(len(sbom.check_policy(unknown, dict(policy, allowlist=[dict(entry, version='v2.0.0')]))), 1)
        self.assertEqual(len(sbom.check_policy(unknown, dict(policy, allowlist=[dict(entry, reason=' ')]))), 2)

    def test_committed_policy_and_mapping_are_usable(self):
        policy = json.loads((ROOT/'scripts/licence-policy.json').read_text())
        self.assertTrue(all(str(entry.get('reason', '')).strip() for entry in policy['allowlist']))
        summary, uncovered, _ = sbom.spdx_coverage()
        self.assertEqual(uncovered, [])
        self.assertGreater(summary['node']['files'], 0)

    def test_coverage_reports_a_file_with_no_header_and_no_rule(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            write(root/'scripts/a.sh', '#!/bin/sh\n# SPDX-License-Identifier: AGPL-3.0-only\n')
            write(root/'scripts/b.sh', '#!/bin/sh\n')
            write(root/'kernel/c.h', '/* SPDX-License-Identifier: GPL-2.0 */\n')
            write(root/'node/d.go', 'package d\n')
            mapping = {'rules': [{'path': 'node/', 'licence': 'AGPL-3.0-only'}]}
            summary, uncovered, licences = sbom.spdx_coverage(root, mapping=mapping)
            self.assertEqual(uncovered, ['scripts/b.sh'])
            self.assertEqual(summary['scripts'], {'files': 2, 'header': 1, 'mapped': 0, 'uncovered': 1})
            self.assertEqual(summary['node']['mapped'], 1)
            self.assertEqual(licences, {'AGPL-3.0-only': 2, 'GPL-2.0': 1})

    def test_buildinfo_parsing(self):
        text = ('/x/nassimhub-agent: go1.27.1\n\tpath\texample.invalid/agent/cmd\n\tmod\texample.invalid/agent\t(devel)\t\n'
                '\tdep\texample.invalid/a\tv1.2.3\th1:AAAA\n\tdep\texample.invalid/b\tv0.0.0\n\t=>\t../b\t(devel)\t\n\tbuild\tCGO_ENABLED=0\n')
        go_version, main, dependencies = sbom.parse_buildinfo(text)
        self.assertEqual((go_version, main), ('go1.27.1', 'example.invalid/agent'))
        self.assertEqual(dependencies[0], {'path': 'example.invalid/a', 'version': 'v1.2.3', 'sum': 'h1:AAAA'})
        self.assertEqual(dependencies[1]['replace']['path'], '../b')


if __name__ == '__main__':
    unittest.main()
