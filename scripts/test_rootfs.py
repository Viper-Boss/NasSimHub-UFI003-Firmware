#!/usr/bin/env python3
"""Unit tests of the rootfs build's offline parts (scripts/rootfs_tools.py,
scripts/rootfs_fetch_index.py) and of the files that describe its inputs.

Everything here is a hand-written, obviously synthetic fixture: the "Debian
archive" is three invented packages read through file://, the "kernel" is a
gzip stream holding a version banner, the "modules" are 200-byte ELF files with
a .modinfo section. Nothing is downloaded, bootstrapped, booted or flashed, and
nothing here says anything about a real Debian 13 system or a UFI003.

    python3 scripts/test_rootfs.py
    python3 scripts/test_rootfs.py --make-fixtures DIR   (inputs for scripts/test-build-rootfs.sh)
"""
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import pathlib
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rootfs_tools as tools  # noqa: E402
import rootfs_fetch_index as fetch_index  # noqa: E402

RELEASE = json.loads((ROOT / 'firmware/upstream.lock.json').read_text())['kernel_version']
TIMESTAMP = '20260101T000000Z'
EPOCH = 1767225600


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


boot_tool = load('boot', 'kernel/audio/replace-appended-dtb.py')

# --- fixtures ---------------------------------------------------------------

BASE = json.loads((ROOT / 'firmware/debian-packages.json').read_text())['base']


def status_text(extra='', versions=None):
    """A dpkg status file: every requested package plus one dependency, all synthetic."""
    versions = versions or {}
    stanzas = []
    for name in BASE + ['synthetic-dependency']:
        stanzas.append(f'Package: {name}\nStatus: install ok installed\nArchitecture: arm64\n'
                       f'Version: {versions.get(name, "1.0-1")}\nDescription: synthetic fixture\n continuation line\n')
    stanzas.append('Package: synthetic-all\nStatus: install ok installed\nArchitecture: all\nSource: synthetic-src (2.0-3)\nVersion: 2.0-3+b1\n')
    stanzas.append('Package: synthetic-removed\nStatus: deinstall ok config-files\nArchitecture: arm64\nVersion: 0.1\n')
    return '\n'.join(stanzas) + extra


def packages_index(versions=None, omit=()):
    versions = versions or {}
    stanzas = []
    for name in BASE + ['synthetic-dependency']:
        if name in omit:
            continue
        version = versions.get(name, '1.0-1')
        stanzas.append(f'Package: {name}\nVersion: {version}\nArchitecture: arm64\nFilename: pool/main/s/{name}_{version}_arm64.deb\n'
                       f'Size: 1234\nSHA256: {hashlib.sha256((name + version).encode()).hexdigest()}\n')
    stanzas.append('Package: synthetic-all\nSource: synthetic-src (2.0-3)\nVersion: 2.0-3+b1\nArchitecture: all\n'
                   f'Filename: pool/main/s/synthetic-all_2.0-3+b1_all.deb\nSize: 99\nSHA256: {"ab" * 32}\n')
    return '\n'.join(stanzas)


def write_archive(directory, suite='trixie', compress='xz', corrupt=False):
    """A file:// "archive": dists/<suite>/InRelease (unsigned) and one Packages index."""
    text = packages_index().encode()
    data = {'xz': lzma.compress, 'gz': lambda raw: gzip.compress(raw, mtime=0), '': bytes}[compress](text)
    relative = 'main/binary-arm64/Packages' + ('.' + compress if compress else '')
    dists = pathlib.Path(directory) / 'dists' / suite
    (dists / 'main/binary-arm64').mkdir(parents=True)
    (dists / relative).write_bytes(data + (b'x' if corrupt else b''))
    (dists / 'InRelease').write_text(
        f'Origin: synthetic fixture\nSuite: {suite}\nSHA256:\n {hashlib.sha256(data).hexdigest()} {len(data)} {relative}\n'
        f' {"0" * 64} 1 main/binary-all/Packages\nMD5Sum-like-trailer: x\n')
    return pathlib.Path(directory).as_uri()


def kernel_image(release=RELEASE, banners=1):
    """A gzip stream holding a "Linux version" banner, with an appended minimal DTB."""
    body = b'\0synthetic kernel fixture, not bootable\0' + b''.join(
        b'Linux version ' + release.encode() + b' (synthetic@fixture) #1 SMP PREEMPT\n\0' for _ in range(banners))
    dtb = boot_tool.FDT_MAGIC + struct.pack('>I', 40) + b'd' * 32
    return gzip.compress(body, mtime=0) + dtb


def boot_image(release=RELEASE, cmdline=b'root=LABEL=rootfs'):
    fields = [boot_tool.MAGIC, 0, 0x80080000, 8, 0x81000000, 0, 0, 0x80000100, 2048, 0, 0, b'UFI003', cmdline, b'', b'']
    return boot_tool.build({'fields': fields, 'page': 2048, 'ramdisk': b'ramdisk!', 'second': b''}, kernel_image(release))


def module(vermagic):
    """A minimal ELF64 little-endian object with a .modinfo section."""
    modinfo = b'license=GPL\0' + (b'vermagic=' + vermagic.encode() + b'\0' if vermagic is not None else b'') + b'name=synthetic\0'
    names = b'\0.modinfo\0.shstrtab\0'
    offset_modinfo = 64
    offset_names = offset_modinfo + len(modinfo)
    shoff = offset_names + len(names)
    header = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\0' * 8 + struct.pack('<HHIQQQIHHHHHH', 1, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 2)
    sections = b'\0' * 64
    sections += struct.pack('<IIQQQQIIQQ', 1, 1, 0, 0, offset_modinfo, len(modinfo), 0, 0, 1, 0)
    sections += struct.pack('<IIQQQQIIQQ', 10, 3, 0, 0, offset_names, len(names), 0, 0, 1, 0)
    return header + modinfo + names + sections


def modules_tree(directory, release=RELEASE, vermagic=None, dep=True):
    base = pathlib.Path(directory) / 'lib/modules' / release
    (base / 'kernel/sound').mkdir(parents=True)
    magic = (vermagic if vermagic is not None else release) + ' SMP preempt mod_unload aarch64'
    (base / 'kernel/sound/synthetic-a.ko').write_bytes(module(magic))
    (base / 'kernel/sound/synthetic-b.ko.xz').write_bytes(lzma.compress(module(magic)))
    (base / 'kernel/sound/synthetic-c.ko.gz').write_bytes(gzip.compress(module(magic), mtime=0))
    if dep:
        (base / 'modules.dep').write_text('kernel/sound/synthetic-a.ko:\n')
    os.symlink('/home/builder/linux', base / 'build')
    return base


def base_tree(root):
    """What a bootstrap leaves behind, in miniature: accounts, os-release, build residue."""
    root = pathlib.Path(root)
    for directory in ('etc/apt/apt.conf.d', 'etc/ssh', 'etc/default', 'usr/bin', 'usr/lib', 'usr/sbin', 'usr/share/zoneinfo/Etc',
                      'var/lib/dpkg', 'var/lib/apt/lists/partial', 'var/cache/apt/archives', 'var/log/apt', 'var/lib/systemd',
                      'var/lib/dbus', 'var/tmp', 'tmp', 'run/lock', 'root', 'dev'):
        (root / directory).mkdir(parents=True, exist_ok=True)
    os.symlink('usr/lib', root / 'lib')
    (root / 'etc/os-release').write_text('PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nVERSION_ID="13"\n')
    (root / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n')
    (root / 'etc/group').write_text('root:x:0:\ndaemon:x:1:\n')
    (root / 'etc/shadow').write_text('root:*:20000:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\n')
    (root / 'etc/gshadow').write_text('root:*::\ndaemon:*::\n')
    (root / 'var/lib/dpkg/status').write_text(status_text())
    # Residue every item of which finalize must remove or replace.
    (root / 'etc/machine-id').write_text('0' * 32 + '\n')
    (root / 'var/lib/dbus/machine-id').write_text('0' * 32 + '\n')
    (root / 'var/lib/systemd/random-seed').write_bytes(b'synthetic seed')
    (root / 'etc/ssh/ssh_host_ed25519_key').write_text('synthetic placeholder, not a key\n')
    (root / 'etc/ssh/ssh_host_ed25519_key.pub').write_text('synthetic placeholder\n')
    (root / 'etc/hostname').write_text('buildhost\n')
    (root / 'etc/resolv.conf').write_text('nameserver 192.0.2.1\n')
    (root / 'etc/apt/apt.conf.d/99mmdebstrap').write_text('synthetic\n')
    (root / 'var/lib/apt/lists/synthetic_Packages').write_text('synthetic\n')
    (root / 'var/cache/apt/archives/synthetic.deb').write_text('synthetic\n')
    (root / 'var/log/dpkg.log').write_text('synthetic log line\n')
    (root / 'var/log/apt/history.log').write_text('synthetic log line\n')
    (root / 'var/lib/dpkg/status-old').write_text('synthetic\n')
    (root / 'root/.bash_history').write_text('synthetic\n')
    (root / 'tmp/leftover').write_text('synthetic\n')
    (root / 'usr/share/zoneinfo/Etc/UTC').write_bytes(b'TZif synthetic')
    (root / 'usr/bin/synthetic').write_text('#!/bin/sh\n')
    os.chmod(root / 'usr/bin/synthetic', 0o755)
    os.chmod(root / 'etc/shadow', 0o640)
    return root


def make_fixtures(directory):
    """Inputs for scripts/test-build-rootfs.sh: bootstrap.tar, boot.img, modules/, firmware/."""
    directory = pathlib.Path(directory)
    with tempfile.TemporaryDirectory() as temporary:
        tree = base_tree(pathlib.Path(temporary) / 'tree')
        with tarfile.open(directory / 'bootstrap.tar', 'w') as archive:
            def clean(info):
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                return info
            archive.add(tree, arcname='.', filter=clean)
    (directory / 'boot.img').write_bytes(boot_image())
    (directory / 'other-boot.img').write_bytes(boot_image(release='6.1.0-synthetic'))
    modules_tree(directory / 'modules')
    modules_tree(directory / 'wrong-modules', vermagic='6.12.49-other')
    (directory / 'firmware/synthetic-model').mkdir(parents=True)
    (directory / 'firmware/synthetic-model/synthetic.mbn').write_bytes(b'synthetic firmware stand-in, same on every unit\n')
    (directory / 'unit-firmware').mkdir()
    (directory / 'unit-firmware/modemst1.bin').write_bytes(b'synthetic stand-in for per-device modem data\n')


def fixture_lock(**changes):
    lock = tools.load_lock(tools.DEFAULT_LOCK)
    resolved = tools.resolve_lock(lock, status_text(), TIMESTAMP, indexes=[packages_index()], release_files=['synthetic'],
                                  kernel={'release': RELEASE, 'boot_img_sha256': 'a' * 64, 'modules_sha256': 'b' * 64},
                                  uid=changes.pop('uid', 990), gid=changes.pop('gid', 990), image_mib=changes.pop('image_mib', 64),
                                  **changes)
    return resolved


# --- tests ------------------------------------------------------------------

class ControlDataTests(unittest.TestCase):
    def test_installed_packages_and_manifest_hash(self):
        packages = tools.installed_packages(status_text())
        names = [package['name'] for package in packages]
        self.assertEqual(names, sorted(names))
        self.assertNotIn('synthetic-removed', names)
        self.assertEqual(len(packages), len(BASE) + 2)
        by_name = {package['name']: package for package in packages}
        self.assertEqual((by_name['synthetic-all']['source'], by_name['synthetic-all']['source_version']), ('synthetic-src', '2.0-3'))
        text, digest = tools.package_manifest(packages)
        self.assertIn('synthetic-all\t2.0-3+b1\tall\n', text)
        self.assertEqual(digest, hashlib.sha256(text.encode()).hexdigest())
        # Order of the input does not matter; one changed version does.
        self.assertEqual(tools.package_manifest(list(reversed(packages)))[1], digest)
        other = tools.installed_packages(status_text(versions={'systemd': '1.0-2'}))
        self.assertNotEqual(tools.package_manifest(other)[1], digest)

    def test_broken_control_data_is_refused(self):
        for text in ('Package: a\nnot a field\n', ' continuation first\n', 'Package: a\nPackage: b\n',
                     'Package: a\nStatus: install ok half-installed\nVersion: 1\nArchitecture: arm64\n',
                     'Package: a\nStatus: install ok installed\nArchitecture: arm64\n',
                     'Status: install ok installed\nVersion: 1\nArchitecture: arm64\n',
                     'Package: a\nStatus: install ok installed\nVersion: 1\nArchitecture: arm64\n\n'
                     'Package: a\nStatus: install ok installed\nVersion: 2\nArchitecture: arm64\n'):
            with self.assertRaises(tools.BuildError, msg=text):
                tools.installed_packages(text)

    def test_packages_index(self):
        entries = tools.index_entries(packages_index())
        fact = entries[('systemd', '1.0-1', 'arm64')]
        self.assertEqual(fact['size'], 1234)
        self.assertEqual(fact['sha256'], hashlib.sha256(b'systemd1.0-1').hexdigest())
        with self.assertRaises(tools.BuildError):
            tools.index_entries('Package: a\nVersion: 1\nArchitecture: arm64\nFilename: x\nSize: 1\n')
        with self.assertRaises(tools.BuildError):
            tools.index_entries('Package: a\nVersion: 1\nArchitecture: arm64\nFilename: x\nSize: 1\nSHA256: nothex\n')

    def test_release_hashes(self):
        hashes = tools.release_hashes(f'Suite: x\nMD5Sum:\n {"1" * 32} 5 a\nSHA256:\n {"2" * 64} 7 main/binary-arm64/Packages.xz\nOther: y\n')
        self.assertEqual(hashes, {'main/binary-arm64/Packages.xz': ('2' * 64, 7)})
        with self.assertRaises(tools.BuildError):
            tools.release_hashes('Suite: x\n')
        with self.assertRaises(tools.BuildError):
            tools.release_hashes('SHA256:\n short 7 a\n')


class FetchIndexTests(unittest.TestCase):
    def test_short_http_body_is_retried_and_never_returned(self):
        class Response(io.BytesIO):
            headers = {'Content-Length': '6'}
        with mock.patch.object(fetch_index.urllib.request, 'urlopen',
                               side_effect=[Response(b'cut'), Response(b'whole!')]) as opened, \
             mock.patch.object(fetch_index.time, 'sleep'):
            self.assertEqual(fetch_index.fetch('https://example.invalid/index'), b'whole!')
            self.assertEqual(opened.call_count, 2)

    def test_short_http_body_fails_after_bounded_retries(self):
        class Response(io.BytesIO):
            headers = {'Content-Length': '6'}
        with mock.patch.object(fetch_index.urllib.request, 'urlopen',
                               side_effect=[Response(b'cut') for _ in range(3)]) as opened, \
             mock.patch.object(fetch_index.time, 'sleep'):
            with self.assertRaises(tools.BuildError):
                fetch_index.fetch('https://example.invalid/index')
            self.assertEqual(opened.call_count, 3)

    def test_index_is_checked_against_inrelease(self):
        for compress in ('xz', 'gz', ''):
            with tempfile.TemporaryDirectory() as directory:
                packages, release = fetch_index.index(write_archive(directory, compress=compress), 'trixie', 'arm64', 'main', '/nonexistent', unsigned=True)
                self.assertEqual(packages, packages_index())
                self.assertIn('synthetic fixture', release)

    def test_corrupt_or_missing_index_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(tools.BuildError):
                fetch_index.index(write_archive(directory, corrupt=True), 'trixie', 'arm64', 'main', '/nonexistent', unsigned=True)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(tools.BuildError):
                fetch_index.index(write_archive(directory), 'trixie', 'riscv64', 'main', '/nonexistent', unsigned=True)

    def test_signature_is_required_outside_test_mode(self):
        # The fixture InRelease is unsigned: without --test-unsigned it must not be accepted.
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(tools.BuildError):
                fetch_index.index(write_archive(directory), 'trixie', 'arm64', 'main', '/nonexistent')
        with self.assertRaises(tools.BuildError):
            fetch_index.fetch('ftp://example.invalid/x')


class LockTests(unittest.TestCase):
    def test_shipped_lock_is_unresolved_and_says_so(self):
        lock = tools.load_lock(tools.DEFAULT_LOCK)
        self.assertEqual(lock['status'], tools.UNRESOLVED)
        self.assertIsNone(lock['packages']['versions'])
        self.assertIsNone(lock['packages']['manifest_sha256'])
        self.assertIsNone(lock['snapshot']['timestamp'])
        self.assertEqual((lock['suite'], lock['architecture']), ('trixie', 'arm64'))
        self.assertIn('snapshot.debian.org', lock['snapshot']['archive'])
        problems = tools.lock_problems(lock)
        self.assertTrue(any('versions' in problem for problem in problems))
        # Nothing device-specific was guessed in the offline container.
        self.assertIsNone(lock['service_user']['uid'])
        self.assertIsNone(lock['image']['size_mib'])
        self.assertIsNone(lock['kernel']['boot_img_sha256'])

    def test_one_package_list(self):
        lock = tools.load_lock(tools.DEFAULT_LOCK)
        self.assertEqual(sorted(lock['packages']['requested']), sorted(BASE))
        self.assertEqual(lock['kernel']['release'], RELEASE)
        self.assertEqual(tools.requested_packages(lock), BASE)
        self.assertEqual(tools.requested_packages(lock, setup_ap=True), BASE + ['dnsmasq-base'])
        with self.assertRaises(tools.BuildError):
            tools.requested_packages(lock, catalogue={'base': ['bad name;rm'], 'setup_access_point': {'packages': []}})

    def test_resolve(self):
        lock = fixture_lock()
        self.assertEqual(lock['status'], tools.RESOLVED)
        self.assertEqual(tools.lock_problems(lock), [])
        self.assertEqual(lock['snapshot']['timestamp'], TIMESTAMP)
        self.assertEqual(lock['source_date_epoch'], EPOCH)
        self.assertEqual(lock['packages']['count'], len(BASE) + 2)
        self.assertEqual(lock['packages']['manifest_sha256'], tools.package_manifest(lock['packages']['versions'])[1])
        systemd = next(package for package in lock['packages']['versions'] if package['name'] == 'systemd')
        self.assertEqual(systemd['deb_sha256'], hashlib.sha256(b'systemd1.0-1').hexdigest())
        self.assertEqual(lock['snapshot']['release_sha256'], [hashlib.sha256(b'synthetic').hexdigest()])

    def test_resolve_refuses_what_did_not_come_from_the_snapshot(self):
        lock = tools.load_lock(tools.DEFAULT_LOCK)
        with self.assertRaises(tools.BuildError):  # installed version is not in the pinned index
            tools.resolve_lock(lock, status_text(versions={'rmtfs': '9.9-9'}), TIMESTAMP, indexes=[packages_index()])
        with self.assertRaises(tools.BuildError):  # a requested package was not installed
            tools.resolve_lock(lock, status_text().replace('Package: rmtfs\nStatus: install ok installed', 'Package: rmtfs\nStatus: deinstall ok config-files'),
                               TIMESTAMP, indexes=[packages_index()])
        with self.assertRaises(tools.BuildError):
            tools.resolve_lock(lock, status_text(), '2026-01-01', indexes=[packages_index()])
        with self.assertRaises(tools.BuildError):  # two indexes disagree about one version
            tools.resolve_lock(lock, status_text(), TIMESTAMP,
                               indexes=[packages_index(), packages_index().replace('Size: 1234', 'Size: 4321', 1)])

    def test_identical_main_and_security_payloads_can_have_different_pool_paths(self):
        lock = tools.load_lock(tools.DEFAULT_LOCK)
        moved = packages_index().replace('Filename: pool/', 'Filename: security-pool/')
        result = tools.resolve_lock(lock, status_text(), TIMESTAMP,
                                    indexes=[packages_index(), moved])
        self.assertEqual(result['packages']['count'], len(BASE) + 2)
        with self.assertRaises(tools.BuildError):
            tools.resolve_lock(tools.load_lock(tools.DEFAULT_LOCK), status_text(), TIMESTAMP,
                               indexes=[packages_index(), moved.replace('SHA256: ', 'SHA256: 0', 1)])

    def test_partial_and_fixture_locks_are_not_release_locks(self):
        lock = tools.load_lock(tools.DEFAULT_LOCK)
        partial = tools.resolve_lock(lock, status_text(), TIMESTAMP, indexes=[packages_index()])
        self.assertTrue(partial['status'].startswith('partially resolved - missing:'))
        self.assertTrue(tools.lock_problems(partial))
        fixture = fixture_lock(test_fixture=True)
        self.assertEqual(fixture['status'], tools.TEST_FIXTURE)
        self.assertEqual(tools.lock_problems(fixture), ["lock status is 'test fixture - not a release lock'"])
        tampered = fixture_lock()
        tampered['packages']['versions'][0]['version'] = '6.6.6'
        self.assertIn('manifest_sha256 does not match the listed package versions', tools.lock_problems(tampered))

    def test_resolved_lock_follows_the_package_list(self):
        lock = fixture_lock()
        with self.assertRaises(tools.BuildError):
            tools.requested_packages(lock, setup_ap=True)

    def test_verify_packages(self):
        lock = fixture_lock()
        with tempfile.TemporaryDirectory() as directory:
            root = base_tree(directory)
            self.assertEqual(tools.verify_packages(lock, root), (len(BASE) + 2, lock['packages']['manifest_sha256']))
            (root / 'var/lib/dpkg/status').write_text(status_text(versions={'modemmanager': '1.0-2'}))
            with self.assertRaises(tools.BuildError) as caught:
                tools.verify_packages(lock, root)
            self.assertIn('modemmanager:arm64 locked 1.0-1, installed 1.0-2', str(caught.exception))
            (root / 'var/lib/dpkg/status').write_text(status_text(extra='\nPackage: extra\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1\n'))
            with self.assertRaises(tools.BuildError) as caught:
                tools.verify_packages(lock, root)
            self.assertIn('extra:arm64 locked absent', str(caught.exception))


class FinalizeTests(unittest.TestCase):
    def test_finalize_removes_everything_per_build_and_per_device(self):
        with tempfile.TemporaryDirectory() as directory:
            root = base_tree(directory)
            tools.finalize(root, EPOCH, {'name': 'nassimhub', 'uid': 990, 'gid': 990})
            for gone in ('var/lib/dbus/machine-id', 'var/lib/systemd/random-seed', 'etc/ssh/ssh_host_ed25519_key',
                         'etc/ssh/ssh_host_ed25519_key.pub', 'etc/resolv.conf', 'etc/apt/apt.conf.d/99mmdebstrap',
                         'var/lib/apt/lists/synthetic_Packages', 'var/lib/apt/lists/partial', 'var/cache/apt/archives',
                         'var/log/dpkg.log', 'var/log/apt/history.log', 'var/lib/dpkg/status-old', 'root/.bash_history',
                         'tmp/leftover', 'run/lock'):
                self.assertFalse(os.path.lexists(root / gone), gone)
            for kept in ('var/lib/apt/lists', 'var/cache/apt', 'var/log/apt', 'tmp', 'run', 'usr/bin/synthetic', 'var/lib/dpkg/status'):
                self.assertTrue((root / kept).exists(), kept)
            self.assertEqual((root / 'etc/machine-id').read_bytes(), b'')
            self.assertEqual((root / 'etc/hostname').read_text(), 'nassimhub-ufi003\n')
            self.assertEqual((root / 'etc/timezone').read_text(), 'Etc/UTC\n')
            self.assertEqual((root / 'etc/default/locale').read_text(), 'LANG=C.UTF-8\n')
            self.assertEqual(os.readlink(root / 'etc/localtime'), '/usr/share/zoneinfo/Etc/UTC')
            self.assertIn('nassimhub:x:990:990::/var/lib/nassimhub:/usr/sbin/nologin', (root / 'etc/passwd').read_text().splitlines())
            self.assertIn('nassimhub:x:990:', (root / 'etc/group').read_text().splitlines())
            self.assertIn('nassimhub:!::0:99999:7:::', (root / 'etc/shadow').read_text().splitlines())
            self.assertIn('nassimhub:!::', (root / 'etc/gshadow').read_text().splitlines())
            self.assertEqual(os.stat(root / 'etc/shadow').st_mode & 0o777, 0o640)
            for directory_name, names, files in os.walk(root):
                for name in names + files:
                    self.assertLessEqual(os.lstat(os.path.join(directory_name, name)).st_mtime, EPOCH, name)
            # The same gate the packager applies to its input accepts the result.
            audit = load('audit_rootfs', 'scripts/audit-rootfs.py')
            self.assertEqual(audit.audit(root), [])
            # Idempotent: a second pass changes nothing.
            before = tools.tree_hash(root)
            tools.finalize(root, EPOCH, {'name': 'nassimhub', 'uid': 990, 'gid': 990})
            self.assertEqual(tools.tree_hash(root), before)

    def test_service_user_ids_are_fixed_and_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = base_tree(directory)
            for uid, gid in ((1, 990), (990, 1), (0, 0), (1000, 1000), (99, 99)):
                with self.assertRaises(tools.BuildError, msg=(uid, gid)):
                    tools.ensure_service_user(root, 'nassimhub', uid, gid)
            self.assertNotIn('nassimhub', (root / 'etc/passwd').read_text())

    def test_usable_password_or_wrong_release_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = base_tree(directory)
            (root / 'etc/shadow').write_text('root::20000:0:99999:7:::\n')
            with self.assertRaises(tools.BuildError):
                tools.finalize(root, EPOCH, {'name': 'nassimhub', 'uid': 990, 'gid': 990})
        with tempfile.TemporaryDirectory() as directory:
            root = base_tree(directory)
            (root / 'etc/os-release').write_text('VERSION_ID="12"\n')
            with self.assertRaises(tools.BuildError):
                tools.finalize(root, EPOCH)

    def test_a_link_out_of_the_tree_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = base_tree(directory)
            (pathlib.Path(outside) / 'keep').write_text('must survive\n')
            (root / 'var/tmp').rmdir()
            os.symlink(outside, root / 'var/tmp')
            (root / 'var/cache/apt').rename(root / 'var/cache/apt.real')
            os.symlink(outside, root / 'var/cache/apt')
            tools.finalize(root, EPOCH, {'name': 'nassimhub', 'uid': 990, 'gid': 990})
            self.assertTrue((pathlib.Path(outside) / 'keep').is_file())


class KernelTests(unittest.TestCase):
    def test_release_is_read_from_the_kernel_itself(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / 'boot.img').write_bytes(boot_image())
            (directory / 'Image.gz').write_bytes(kernel_image())
            (directory / 'Image').write_bytes(gzip.decompress(kernel_image()[:-40]))
            for name in ('boot.img', 'Image.gz', 'Image'):
                self.assertEqual(tools.kernel_release(directory / name), RELEASE, name)
            (directory / 'none').write_bytes(b'no banner here')
            (directory / 'two').write_bytes(b'Linux version 6.1.0-a (x) \0Linux version 6.1.0-b (x) ')
            (directory / 'bad.img').write_bytes(b'ANDROID!' + b'\0' * 20)
            for name in ('none', 'two', 'bad.img'):
                with self.assertRaises(tools.BuildError, msg=name):
                    tools.kernel_release(directory / name)

    def test_vermagic(self):
        self.assertEqual(tools.module_vermagic(module(RELEASE + ' SMP preempt')), RELEASE + ' SMP preempt')
        self.assertIsNone(tools.module_vermagic(module(None)))
        self.assertIsNone(tools.module_vermagic(b'not an ELF file'))
        self.assertIsNone(tools.module_vermagic(module('x')[:80]))

    def test_modules_are_installed_only_when_every_vermagic_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            root = base_tree(directory / 'root')
            modules_tree(directory / 'good')
            self.assertEqual(tools.install_modules(root, directory / 'good', RELEASE), 3)
            installed = root / 'usr/lib/modules' / RELEASE
            self.assertTrue((installed / 'modules.dep').is_file())
            self.assertFalse(os.path.lexists(installed / 'build'), 'the link into the build host was kept')
            self.assertEqual(os.stat(installed / 'kernel/sound/synthetic-a.ko').st_mode & 0o777, 0o644)
            with self.assertRaises(tools.BuildError):  # a second install must not merge two module sets
                tools.install_modules(root, directory / 'good', RELEASE)
        cases = {'prefix only': dict(vermagic=RELEASE + '-dirty'), 'other release': dict(vermagic='6.12.49-other'), 'no modules.dep': dict(dep=False)}
        for label, arguments in cases.items():
            with tempfile.TemporaryDirectory() as directory:
                directory = pathlib.Path(directory)
                root = base_tree(directory / 'root')
                modules_tree(directory / 'bad', **arguments)
                with self.assertRaises(tools.BuildError, msg=label):
                    tools.install_modules(root, directory / 'bad', RELEASE)
                self.assertFalse((root / 'usr/lib/modules' / RELEASE).exists(), label)
                self.assertFalse((root / '.nsh-modules').exists(), label)

    def test_modules_from_a_tar(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            root = base_tree(directory / 'root')
            modules_tree(directory / 'good')
            with tarfile.open(directory / 'modules.tar.gz', 'w:gz') as archive:
                archive.add(directory / 'good/lib', arcname='./lib')
            self.assertEqual(tools.install_modules(root, directory / 'modules.tar.gz', RELEASE), 3)
            with self.assertRaises(tools.BuildError):
                tools.install_modules(base_tree(directory / 'root2'), directory / 'modules.tar.gz', '6.1.0-absent')
            with self.assertRaises(tools.BuildError):
                tools.install_modules(base_tree(directory / 'root3'), directory / 'good', '../escape')
            (directory / 'empty').mkdir()
            with self.assertRaises(tools.BuildError):
                tools.install_modules(base_tree(directory / 'root4'), directory / 'empty', RELEASE)


class FirmwareTests(unittest.TestCase):
    def test_model_firmware_is_listed_and_unit_data_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            make_fixtures(directory)
            root = base_tree(directory / 'root')
            listed = tools.install_firmware(root, directory / 'firmware')
            self.assertEqual([entry['path'] for entry in listed], ['usr/lib/firmware/synthetic-model/synthetic.mbn'])
            self.assertEqual(listed[0]['sha256'], tools.sha256_file(directory / 'firmware/synthetic-model/synthetic.mbn'))
            with self.assertRaises(tools.BuildError):
                tools.install_firmware(root, directory / 'unit-firmware')
            self.assertFalse((root / 'usr/lib/firmware/modemst1.bin').exists())
            # Every per-device name the package gate knows, in any wrapping.
            for name in ('modemst2.img.gz', 'fsg.bin', 'fsc.mbn', 'persist.img', 'backup.qcn', 'export.xqcn', 'modem_fs1', 'nv.efs', 'x.nvm'):
                source = directory / ('refuse-' + name)
                source.mkdir()
                (source / name).write_bytes(b'synthetic')
                with self.assertRaises(tools.BuildError, msg=name):
                    tools.install_firmware(root, source)
            (directory / 'none').mkdir()
            with self.assertRaises(tools.BuildError):
                tools.install_firmware(root, directory / 'none')
            with self.assertRaises(tools.BuildError):
                tools.install_firmware(root, directory / 'does-not-exist')


class TreeAndProvenanceTests(unittest.TestCase):
    def test_tree_hash_sees_content_mode_and_links_but_not_times(self):
        with tempfile.TemporaryDirectory() as directory:
            root = base_tree(directory)
            first = tools.tree_hash(root)
            os.utime(root / 'usr/bin/synthetic', (1, 1))
            self.assertEqual(tools.tree_hash(root), first)
            os.chmod(root / 'usr/bin/synthetic', 0o700)
            self.assertNotEqual(tools.tree_hash(root), first)
            os.chmod(root / 'usr/bin/synthetic', 0o755)
            self.assertEqual(tools.tree_hash(root), first)
            (root / 'usr/bin/synthetic').write_text('#!/bin/sh\n# changed\n')
            self.assertNotEqual(tools.tree_hash(root), first)

    def test_image_time_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'a').mkdir()
            (root / 'a/file one').write_text('x')
            commands = list(tools.image_time_commands(root, EPOCH))
            self.assertEqual(commands[:2], [f'set_inode_field / ctime @{EPOCH}', f'set_inode_field / atime @{EPOCH}'])
            self.assertIn(f'set_inode_field "/a/file one" ctime @{EPOCH}', commands)
            (root / 'a/bad"name').write_text('x')
            with self.assertRaises(tools.BuildError):
                list(tools.image_time_commands(root, EPOCH))

    def test_provenance_has_exactly_three_wordings(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            root = base_tree(directory / 'root')
            boot = directory / 'boot.img'
            boot.write_bytes(boot_image())
            self.assertEqual(tools.provenance('', root)['statement'], 'operator-supplied (unverified provenance)')
            digest, _ = tools.tree_hash(root)
            manifest = {'schema': 1, 'kind': 'nassimhub-ufi003-rootfs-base', 'release_input': True, 'tree_sha256': digest,
                        'lock': {'sha256': 'c' * 64}, 'kernel': {'boot_img_sha256': tools.sha256_file(boot)}, 'source_date_epoch': EPOCH}
            path = directory / 'ROOTFS-MANIFEST.json'
            path.write_text(json.dumps(manifest))
            result = tools.provenance(path, root, boot)
            self.assertEqual(result['statement'], 'built from lock ' + 'c' * 64)
            self.assertTrue(result['built_from_lock'] and result['release_input'])
            path.write_text(json.dumps(dict(manifest, release_input=False, non_release_reasons=['synthetic'])))
            result = tools.provenance(path, root, boot)
            self.assertEqual(result['statement'], 'built by build-rootfs.sh WITHOUT a resolved lock (non-reproducible, not a release input)')
            self.assertFalse(result['built_from_lock'] or result['release_input'])
            # "release_input": "yes" or 1 is not True.
            path.write_text(json.dumps(dict(manifest, release_input='yes')))
            self.assertFalse(tools.provenance(path, root, boot)['built_from_lock'])

    def test_provenance_of_another_tree_or_boot_image_establishes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            root = base_tree(directory / 'root')
            boot = directory / 'boot.img'
            boot.write_bytes(boot_image())
            digest, _ = tools.tree_hash(root)
            manifest = {'schema': 1, 'kind': 'nassimhub-ufi003-rootfs-base', 'release_input': True, 'tree_sha256': digest,
                        'lock': {'sha256': 'c' * 64}, 'kernel': {'boot_img_sha256': tools.sha256_file(boot)}}
            path = directory / 'ROOTFS-MANIFEST.json'
            path.write_text(json.dumps(manifest))
            other = directory / 'other.img'
            other.write_bytes(boot_image(release='6.1.0-synthetic'))
            with self.assertRaises(tools.BuildError):
                tools.provenance(path, root, other)
            (root / 'usr/bin/added-later').write_text('x')
            with self.assertRaises(tools.BuildError):
                tools.provenance(path, root, boot)
            path.write_text(json.dumps(dict(manifest, kind='something-else')))
            with self.assertRaises(tools.BuildError):
                tools.provenance(path, root, boot)


class DocumentedInputsTests(unittest.TestCase):
    def setUp(self):
        self.dependencies = json.loads((ROOT / 'firmware/rootfs-dependencies.json').read_text())

    def test_installed_list_is_the_verified_list_and_nothing_else(self):
        installed = self.dependencies['installed']
        self.assertEqual(sorted(entry['package'] for entry in installed), sorted(BASE))
        install_doc = (ROOT / 'docs/INSTALL.md').read_text()
        for entry in installed:
            self.assertIs(entry['verified_image_list'], True)
            self.assertIn(entry['package'], install_doc)
            self.assertTrue(entry['why'])

    def test_everything_else_is_marked_unverified_and_not_requested(self):
        catalogue = json.loads((ROOT / 'firmware/debian-packages.json').read_text())
        allowed = ('unverified - not in the verified image list', 'must not be installed', 'never taken from Debian by this build')
        for entry in self.dependencies['not_installed']:
            self.assertTrue(entry['status'].startswith(allowed), entry)
            self.assertNotIn(entry['package'], BASE)
        self.assertEqual([entry['package'] for entry in self.dependencies['setup_access_point_only']],
                         catalogue['setup_access_point']['packages'])
        for entry in self.dependencies['setup_access_point_only']:
            self.assertIs(entry['verified_image_list'], False)

    def test_firmware_policy_names_the_refused_data(self):
        policy = self.dependencies['firmware']
        for word in ('modemst1', 'modemst2', 'fsg', 'fsc', 'persist'):
            self.assertIn(word, policy['device_unique_refused'])
        self.assertIn('never downloaded', policy['policy'])

    def test_build_script_never_downloads_firmware_or_kernel(self):
        script = (ROOT / 'scripts/build-rootfs.sh').read_text()
        code = '\n'.join(line for line in script.splitlines() if not line.lstrip().startswith('#'))
        for word in ('wget', 'curl ', 'git clone', 'non-free'):
            self.assertNotIn(word, code)
        # The only network users: mmdebstrap and the index fetcher, both against the two pinned archives.
        self.assertEqual(code.count('rootfs_fetch_index.py'), 1)
        tool = (ROOT / 'scripts/rootfs_tools.py').read_text()
        self.assertNotIn('urllib', tool)
        self.assertNotIn('import socket', tool)


class SbomRootfsTests(unittest.TestCase):
    def setUp(self):
        self.sbom = load('sbom', 'scripts/sbom.py')

    def test_unresolved_lock_lists_nothing_and_says_so(self):
        packages, statement = self.sbom.rootfs_package_set(tools.DEFAULT_LOCK)
        self.assertEqual(packages, [])
        self.assertTrue(statement.startswith('not included: rootfs lock unresolved'), statement)
        self.assertEqual(self.sbom.rootfs_package_set('/nonexistent/lock.json')[0], [])

    def test_resolved_lock_is_listed_and_a_doubtful_one_is_not(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'lock.json'
            lock = fixture_lock()
            path.write_text(json.dumps(lock))
            packages, statement = self.sbom.rootfs_package_set(path)
            self.assertEqual(len(packages), len(BASE) + 2)
            self.assertIn(TIMESTAMP, statement)
            self.assertIn(lock['packages']['manifest_sha256'], statement)
            for label, change in (('fixture', lambda l: l.update(status=tools.TEST_FIXTURE)),
                                  ('partial', lambda l: l.update(status='partially resolved - missing: x')),
                                  ('edited', lambda l: l['packages']['versions'][0].update(version='6.6.6')),
                                  ('no snapshot', lambda l: l['snapshot'].update(timestamp=None))):
                changed = json.loads(json.dumps(lock))
                change(changed)
                path.write_text(json.dumps(changed))
                packages, statement = self.sbom.rootfs_package_set(path)
                self.assertEqual(packages, [], label)
                self.assertTrue(statement.startswith('not included:'), label)


def cli(*arguments):
    return subprocess.run([sys.executable, str(ROOT / 'scripts/rootfs_tools.py'), *arguments], capture_output=True, text=True)


class CommandLineTests(unittest.TestCase):
    def test_lock_resolve_and_check_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / 'status').write_text(status_text())
            (directory / 'Packages').write_text(packages_index())
            (directory / 'InRelease').write_text('synthetic')
            result = cli('lock-resolve', '--lock', str(tools.DEFAULT_LOCK), '--status', str(directory / 'status'), '--timestamp', TIMESTAMP,
                         '--out', str(directory / 'lock.json'), '--index', str(directory / 'Packages'), '--release-file', str(directory / 'InRelease'),
                         '--kernel-release', RELEASE, '--boot-img-sha256', 'a' * 64, '--modules-sha256', 'b' * 64,
                         '--uid', '990', '--gid', '990', '--image-mib', '64')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(cli('lock-check', '--release', str(directory / 'lock.json')).returncode, 0)
            self.assertEqual(cli('lock-include', str(directory / 'lock.json')).stdout.strip(), ','.join(BASE))
            shipped = cli('lock-check', '--release', str(tools.DEFAULT_LOCK))
            self.assertEqual(shipped.returncode, 1)
            self.assertIn('NOT resolved', shipped.stdout)
            self.assertEqual(cli('kernel-release', str(directory / 'status')).returncode, 1)

    def test_tree_list_is_what_tree_hash_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = base_tree(directory)
            listing = cli('tree-list', str(root)).stdout
            self.assertIn('f 0755 ', listing)
            self.assertIn('"usr/bin/synthetic"', listing)
            self.assertEqual(hashlib.sha256(listing.encode()).hexdigest(), cli('tree-hash', str(root)).stdout.split()[0])


if __name__ == '__main__':
    if sys.argv[1:2] == ['--make-fixtures']:
        make_fixtures(sys.argv[2])
        sys.exit(0)
    unittest.main()
