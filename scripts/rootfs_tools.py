#!/usr/bin/env python3
"""The parts of the Debian 13 rootfs build that need no network and no chroot.

scripts/build-rootfs.sh drives these; scripts/test_rootfs.py tests each one on
hand-written fixtures. Standard library only.

    rootfs_tools.py lock-check LOCK [--release]
    rootfs_tools.py lock-include LOCK [--setup-ap]
    rootfs_tools.py lock-resolve --lock LOCK --status DPKG_STATUS --timestamp TS --out LOCK
                                 [--index PACKAGES_FILE ...] [--release-file INRELEASE ...]
                                 [--kernel-release REL --boot-img-sha256 HEX --modules-sha256 HEX]
                                 [--uid N --gid N] [--image-mib N] [--test-fixture]
    rootfs_tools.py verify-packages --lock LOCK --root ROOT
    rootfs_tools.py finalize --root ROOT --lock LOCK --epoch N [--uid N --gid N]
    rootfs_tools.py kernel-release FILE            boot.img (Android v0), Image.gz or Image
    rootfs_tools.py modules --root ROOT --modules DIR_OR_TAR --kernel-release REL
    rootfs_tools.py firmware --root ROOT --dir DIR --out LIST.json
    rootfs_tools.py tree-hash ROOT
    rootfs_tools.py tree-list ROOT                 the lines tree-hash hashes; diff two builds with it
    rootfs_tools.py clamp-mtime ROOT EPOCH
    rootfs_tools.py image-times ROOT EPOCH         debugfs commands that fix inode times
    rootfs_tools.py provenance [--manifest ROOTFS-MANIFEST.json] --root ROOT [--boot-img FILE]

What "locked" means here. The lock file (firmware/rootfs.lock.json) names a
Debian suite, a snapshot.debian.org timestamp and the exact set of packages
(name, version, architecture) that a bootstrap from that snapshot installed,
plus the SHA-256 of that list. A build is release-grade only when the packages
found in the tree are exactly that set. The lock shipped in the repository is
UNRESOLVED (no timestamp, `versions: null`): resolving it needs the network.

Nothing in this file downloads anything, mounts anything or opens a block
device.
"""
import argparse
import calendar
import gzip
import hashlib
import importlib.util
import json
import lzma
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
import zlib

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import genericrules as rules  # noqa: E402

UNRESOLVED = 'unresolved - run build-rootfs.sh --lock on a networked build host'
RESOLVED = 'resolved'
TEST_FIXTURE = 'test fixture - not a release lock'
DEFAULT_LOCK = ROOT / 'firmware' / 'rootfs.lock.json'
PACKAGES_JSON = ROOT / 'firmware' / 'debian-packages.json'
SNAPSHOT = re.compile(r'^\d{8}T\d{6}Z$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
PACKAGE_NAME = re.compile(r'^[a-z0-9][a-z0-9+.-]+$')


class BuildError(Exception):
    """A reason the build must stop; the message is for the operator."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


# --- Debian control data ----------------------------------------------------

def parse_stanzas(text):
    """RFC 822-style stanzas (dpkg status, a Packages index) as a list of dicts.

    Continuation lines (leading space or tab) are joined to their field with a
    newline. A line that is neither a field nor a continuation is an error: a
    truncated or corrupted index must not parse into fewer packages.
    """
    stanzas, current, last = [], {}, None
    for number, line in enumerate(text.split('\n'), 1):
        if not line.strip():
            if current:
                stanzas.append(current)
            current, last = {}, None
            continue
        if line[0] in ' \t':
            if last is None:
                raise BuildError(f'control data line {number}: continuation without a field')
            current[last] += '\n' + line.strip()
            continue
        name, separator, value = line.partition(':')
        if not separator or not name or ' ' in name:
            raise BuildError(f'control data line {number}: not a field')
        if name in current:
            raise BuildError(f'control data line {number}: field {name} appears twice')
        current[name], last = value.strip(), name
    if current:
        stanzas.append(current)
    return stanzas


def source_of(stanza):
    """(source package, source version) of a binary package stanza."""
    source = stanza.get('Source', stanza['Package'])
    match = re.match(r'^(\S+)\s+\((\S+)\)$', source)
    if match:
        return match.group(1), match.group(2)
    return source.split()[0], stanza.get('Version', '')


def installed_packages(status_text):
    """Installed packages of a dpkg status file, sorted by (name, architecture)."""
    packages = []
    for stanza in parse_stanzas(status_text):
        if 'Package' not in stanza:
            raise BuildError('dpkg status has a stanza without a Package field')
        state = stanza.get('Status', '').split()
        if state[-1:] != ['installed']:
            # config-files, half-installed, not-installed: not part of the set,
            # but anything other than a clean state is not a clean bootstrap.
            if state[-1:] not in (['config-files'], ['not-installed']):
                raise BuildError(f"package {stanza['Package']} is in state {' '.join(state) or 'unknown'}")
            continue
        for field in ('Version', 'Architecture'):
            if not stanza.get(field):
                raise BuildError(f"installed package {stanza['Package']} has no {field}")
        source, source_version = source_of(stanza)
        packages.append({'name': stanza['Package'], 'version': stanza['Version'], 'arch': stanza['Architecture'],
                         'source': source, 'source_version': source_version})
    packages.sort(key=lambda package: (package['name'], package['arch']))
    seen = set()
    for package in packages:
        key = (package['name'], package['arch'])
        if key in seen:
            raise BuildError(f"package {package['name']}:{package['arch']} is installed twice")
        seen.add(key)
    return packages


def package_manifest(packages):
    """The package-set manifest text and its SHA-256.

    One line per package, `name<TAB>version<TAB>architecture`, sorted. This is
    what `manifest_sha256` in the lock is the hash of, and what a build
    recomputes from var/lib/dpkg/status to prove it installed the locked set.
    """
    ordered = sorted(packages, key=lambda package: (package['name'], package['arch']))
    text = ''.join(f"{package['name']}\t{package['version']}\t{package['arch']}\n" for package in ordered)
    return text, hashlib.sha256(text.encode()).hexdigest()


def index_entries(packages_text):
    """(name, version, arch) -> archive facts, from a `Packages` index."""
    entries = {}
    for stanza in parse_stanzas(packages_text):
        for field in ('Package', 'Version', 'Architecture', 'Filename', 'SHA256', 'Size'):
            if not stanza.get(field):
                raise BuildError(f"Packages index: {stanza.get('Package', 'a stanza')} has no {field}")
        if not HEX64.match(stanza['SHA256']) or not stanza['Size'].isdigit():
            raise BuildError(f"Packages index: {stanza['Package']} has an unusable SHA256 or Size")
        source, source_version = source_of(stanza)
        key = (stanza['Package'], stanza['Version'], stanza['Architecture'])
        fact = {'filename': stanza['Filename'], 'sha256': stanza['SHA256'], 'size': int(stanza['Size']),
                'source': source, 'source_version': source_version}
        if key in entries and entries[key] != fact:
            # The same version in two indexes (main and security) must be the
            # same file; anything else is two different packages under one name.
            raise BuildError(f"Packages index: {key[0]} {key[1]} is listed twice with different contents")
        entries[key] = fact
    return entries


def release_hashes(text):
    """path -> (sha256, size) from the SHA256 section of a Release/InRelease file."""
    hashes, inside = {}, False
    for line in text.splitlines():
        if line.startswith('SHA256:'):
            inside = True
            continue
        if inside:
            if not line.startswith(' '):
                inside = False
                continue
            fields = line.split()
            if len(fields) != 3 or not HEX64.match(fields[0]) or not fields[1].isdigit():
                raise BuildError('Release file: unreadable SHA256 line')
            hashes[fields[2]] = (fields[0], int(fields[1]))
    if not hashes:
        raise BuildError('Release file has no SHA256 section')
    return hashes


# --- the lock ---------------------------------------------------------------

def load_lock(path):
    try:
        lock = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError) as error:
        raise BuildError(f'lock file {path}: {error}')
    if not isinstance(lock, dict) or lock.get('schema') != 1:
        raise BuildError(f'lock file {path}: unsupported schema')
    return lock


def requested_packages(lock, setup_ap=False, catalogue=None):
    """The package names the bootstrap is asked for.

    Taken from firmware/debian-packages.json (the list docs/INSTALL.md gives
    for the verified image) so that there is one list, not two. A resolved
    lock carries the names it was resolved for and must still agree.
    """
    if catalogue is None:
        catalogue = json.loads(PACKAGES_JSON.read_text())
    names = list(catalogue['base'])
    if setup_ap:
        names += catalogue['setup_access_point']['packages']
    for name in names:
        if not PACKAGE_NAME.match(name):
            raise BuildError(f'package name {name!r} is not usable')
    recorded = lock.get('packages', {}).get('requested')
    if lock.get('status') == RESOLVED and sorted(recorded or []) != sorted(names):
        raise BuildError('the lock was resolved for another package list than firmware/debian-packages.json'
                         + (' with the setup access point' if setup_ap else '') + '; run --lock again')
    return names


def lock_problems(lock):
    """Why this lock cannot produce a release-grade rootfs. Empty when it can."""
    problems = []
    if lock.get('status') != RESOLVED:
        problems.append(f"lock status is {lock.get('status')!r}")
    snapshot = lock.get('snapshot', {})
    if not SNAPSHOT.match(str(snapshot.get('timestamp') or '')):
        problems.append('no snapshot.debian.org timestamp')
    if not isinstance(lock.get('source_date_epoch'), int):
        problems.append('no source_date_epoch')
    packages = lock.get('packages', {})
    versions = packages.get('versions')
    if not isinstance(versions, list) or not versions:
        problems.append('package versions are not resolved (versions: null)')
    elif package_manifest(versions)[1] != packages.get('manifest_sha256'):
        problems.append('manifest_sha256 does not match the listed package versions')
    user = lock.get('service_user', {})
    if not isinstance(user.get('uid'), int) or not isinstance(user.get('gid'), int):
        problems.append('the service user uid/gid are not set')
    kernel = lock.get('kernel', {})
    if not kernel.get('release'):
        problems.append('no kernel release')
    for field in ('boot_img_sha256', 'modules_sha256'):
        if not HEX64.match(str(kernel.get(field) or '')):
            problems.append(f'kernel {field} is not recorded')
    image = lock.get('image', {})
    if not isinstance(image.get('size_mib'), int) or image['size_mib'] <= 0:
        problems.append('the rootfs partition size (image.size_mib) is not recorded')
    return problems


def resolve_lock(lock, status_text, timestamp, indexes=(), release_files=(), kernel=None, uid=None, gid=None,
                 image_mib=None, setup_ap=False, test_fixture=False, catalogue=None):
    """A resolved copy of the lock, from what a bootstrap actually installed."""
    if not SNAPSHOT.match(timestamp):
        raise BuildError('the snapshot timestamp must look like 20260101T000000Z')
    lock = json.loads(json.dumps(lock))
    lock['status'] = UNRESOLVED  # so requested_packages does not compare against the old list
    names = requested_packages(lock, setup_ap, catalogue)
    packages = installed_packages(status_text)
    installed = {package['name'] for package in packages}
    missing = sorted(set(names) - installed)
    if missing:
        raise BuildError('the bootstrap did not install: ' + ', '.join(missing))
    entries = {}
    installed_versions = {(p['name'], p['version'], p['arch']) for p in packages}
    for text in indexes:
        for key, fact in index_entries(text).items():
            if key not in installed_versions:
                continue
            if key in entries:
                # Debian main/security may publish identical .deb bytes under
                # different pool paths. Compare content and source provenance,
                # not the archive-local download location.
                previous = {k: v for k, v in entries[key].items() if k != 'filename'}
                current = {k: v for k, v in fact.items() if k != 'filename'}
                if previous != current:
                    raise BuildError(f'{key[0]} {key[1]} differs between two Packages indexes')
            entries[key] = fact
    if entries:
        for package in packages:
            fact = entries.get((package['name'], package['version'], package['arch']))
            if fact is None:
                # Installed from somewhere other than the pinned snapshot.
                raise BuildError(f"{package['name']} {package['version']} ({package['arch']}) is installed but is not in the "
                                 'pinned Packages indexes')
            package.update(deb_sha256=fact['sha256'], deb_size=fact['size'], filename=fact['filename'])
    text, digest = package_manifest(packages)
    epoch = calendar.timegm(time.strptime(timestamp, '%Y%m%dT%H%M%SZ'))
    lock['snapshot'] = dict(lock.get('snapshot', {}), timestamp=timestamp,
                            release_sha256=[hashlib.sha256(release.encode()).hexdigest() for release in release_files])
    lock['source_date_epoch'] = epoch
    lock['packages'] = {'requested': sorted(names), 'setup_access_point': bool(setup_ap), 'versions': packages,
                        'manifest_sha256': digest, 'count': len(packages),
                        'deb_hashes': 'from the pinned Packages indexes' if entries else 'not recorded'}
    if kernel:
        lock['kernel'] = dict(lock.get('kernel', {}), **kernel)
    if uid is not None and gid is not None:
        lock['service_user'] = dict(lock.get('service_user', {}), uid=uid, gid=gid)
    if image_mib is not None:
        lock['image'] = dict(lock.get('image', {}), size_mib=image_mib)
    lock['status'] = TEST_FIXTURE if test_fixture else RESOLVED
    remaining = [problem for problem in lock_problems(lock) if not problem.startswith('lock status')]
    if remaining and not test_fixture:
        # Package versions are resolved; the rest must be supplied before a
        # release build. Say so in the file itself.
        lock['status'] = 'partially resolved - missing: ' + '; '.join(remaining)
    return lock


def verify_packages(lock, root):
    """Fail unless the tree holds exactly the locked package set. Returns (count, sha256)."""
    status = pathlib.Path(root) / 'var/lib/dpkg/status'
    if not status.is_file():
        raise BuildError('the rootfs has no var/lib/dpkg/status')
    packages = installed_packages(status.read_text(encoding='utf-8', errors='strict'))
    text, digest = package_manifest(packages)
    locked = lock.get('packages', {})
    if not isinstance(locked.get('versions'), list):
        raise BuildError('the lock has no package versions to compare with')
    if digest != locked.get('manifest_sha256'):
        want = {(p['name'], p['arch']): p['version'] for p in locked['versions']}
        have = {(p['name'], p['arch']): p['version'] for p in packages}
        differences = []
        for key in sorted(set(want) | set(have)):
            if want.get(key) != have.get(key):
                differences.append(f"{key[0]}:{key[1]} locked {want.get(key, 'absent')}, installed {have.get(key, 'absent')}")
        raise BuildError('the installed packages are not the locked set:\n  ' + '\n  '.join(differences[:40])
                         + ('' if len(differences) <= 40 else f'\n  ... and {len(differences) - 40} more'))
    return len(packages), digest


# --- finishing a bootstrapped tree -------------------------------------------

def _edit_lines(path, name, line, mode):
    """Replace or append the entry for `name` in a colon-separated account file."""
    existing = path.read_text().splitlines() if path.is_file() else []
    kept = [entry for entry in existing if entry.split(':', 1)[0] != name]
    kept.append(line)
    path.write_text('\n'.join(kept) + '\n')
    os.chmod(path, mode)


def ensure_service_user(root, name, uid, gid, home='/var/lib/nassimhub'):
    """Create the service account by editing the account files, no chroot.

    A system account that cannot log in: locked password, nologin shell. The
    numeric ids are fixed because files on the state partition are owned by
    them: an image that allocated another uid would lock the agent out of its
    own identity on a device that already has one.
    """
    root = pathlib.Path(root)
    etc = root / 'etc'
    for entry in (etc / 'passwd').read_text().splitlines():
        fields = entry.split(':')
        if len(fields) > 2 and fields[0] != name and fields[2] == str(uid):
            raise BuildError(f'uid {uid} already belongs to {fields[0]} in this rootfs')
    for entry in (etc / 'group').read_text().splitlines():
        fields = entry.split(':')
        if len(fields) > 2 and fields[0] != name and fields[2] == str(gid):
            raise BuildError(f'gid {gid} already belongs to {fields[0]} in this rootfs')
    if not 100 <= uid <= 999 or not 100 <= gid <= 999:
        raise BuildError('the service uid and gid must be system ids (100-999)')
    _edit_lines(etc / 'passwd', name, f'{name}:x:{uid}:{gid}::{home}:/usr/sbin/nologin', 0o644)
    _edit_lines(etc / 'group', name, f'{name}:x:{gid}:', 0o644)
    # "!" locks the password; the date field is left empty so the file does
    # not depend on the day of the build.
    _edit_lines(etc / 'shadow', name, f'{name}:!::0:99999:7:::', 0o640)
    if (etc / 'gshadow').is_file():
        _edit_lines(etc / 'gshadow', name, f'{name}:!::', 0o640)


# Removed from the tree, contents and all; the directory itself is kept empty
# where a package expects it. Each line says what would otherwise differ between
# two builds or between two devices.
CLEAR_DIRECTORIES = (
    'var/lib/apt/lists',        # index files of the build
    'var/cache/apt',            # downloaded .deb files and the binary caches
    'var/cache/debconf',        # *-old files carry timestamps
    'var/cache/ldconfig',       # aux-cache is not deterministic
    'var/tmp', 'tmp', 'run',
    'var/lib/systemd/coredump', 'var/lib/NetworkManager', 'root/.cache',
)
REMOVE_GLOBS = (
    'etc/ssh/ssh_host_*',                      # host keys are generated on the device
    'var/lib/dbus/machine-id', 'var/lib/systemd/random-seed', 'var/lib/systemd/credential.secret',
    'root/.bash_history', 'root/.wget-hsts', 'root/.lesshst',
    'var/lib/dpkg/*-old', 'var/lib/dpkg/lock*', 'var/lib/dpkg/triggers/Lock', 'var/lib/apt/extended_states.*',
    'etc/.pwd.lock', 'etc/passwd-', 'etc/group-', 'etc/shadow-', 'etc/gshadow-', 'etc/subuid-', 'etc/subgid-',
    'etc/resolv.conf',                          # copied from the build host by the bootstrap
    'etc/apt/apt.conf.d/99mmdebstrap', 'etc/apt/sources.list.d/0000*',
)
FIXED_FILES = {
    'etc/hostname': 'nassimhub-ufi003\n',
    'etc/hosts': '127.0.0.1\tlocalhost\n127.0.1.1\tnassimhub-ufi003\n::1\tlocalhost ip6-localhost ip6-loopback\n',
    'etc/timezone': 'Etc/UTC\n',
    'etc/default/locale': 'LANG=C.UTF-8\n',
    'etc/machine-id': '',                       # empty: systemd writes one on first boot
}


def _inside(root, relative):
    """root/relative, refusing a path that leaves the tree through a symlink."""
    root = pathlib.Path(root)
    current = root
    for part in pathlib.PurePosixPath(relative).parts[:-1]:
        current = current / part
        if current.is_symlink():
            target = os.readlink(current)
            if target.startswith('/') or '..' in pathlib.PurePosixPath(target).parts:
                # usrmerge links (lib -> usr/lib) are relative and stay inside.
                raise BuildError(f'{relative}: {current.relative_to(root)} is a link out of the tree')
    return root / relative


def finalize(root, epoch, user=None):
    """Turn a bootstrapped tree into a clean, device-independent one."""
    root = pathlib.Path(root)
    if not (root / 'etc/os-release').is_file() or 'VERSION_ID="13"' not in (root / 'etc/os-release').read_text():
        raise BuildError('this tree is not Debian 13 (etc/os-release)')
    if user:
        ensure_service_user(root, user['name'], user['uid'], user['gid'])
    for relative in CLEAR_DIRECTORIES:
        directory = _inside(root, relative)
        if directory.is_symlink():
            continue
        if directory.is_dir():
            for child in directory.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
    # Build-time logs (dpkg.log, apt history, bootstrap.log): the files go, the
    # directories packages created stay as they are.
    logs = _inside(root, 'var/log')
    if logs.is_dir() and not logs.is_symlink():
        for directory, _, files in os.walk(logs):
            for name in files:
                os.unlink(os.path.join(directory, name))
    for pattern in REMOVE_GLOBS:
        for path in root.glob(pattern):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
    for relative, content in FIXED_FILES.items():
        path = _inside(root, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink() or path.exists():
            path.unlink()
        path.write_text(content)
        os.chmod(path, 0o644)
    localtime = root / 'etc/localtime'
    if localtime.is_symlink() or localtime.exists():
        localtime.unlink()
    os.symlink('/usr/share/zoneinfo/Etc/UTC', localtime)
    # Every account must be locked: the image has no password anyone knows.
    for name in ('etc/shadow',):
        for entry in (root / name).read_text().splitlines():
            fields = entry.split(':')
            if len(fields) > 1 and not fields[1].startswith(('!', '*')):
                raise BuildError(f'account {fields[0]} has a usable or empty password in {name}')
    clamp_mtime(root, epoch)


def clamp_mtime(root, epoch):
    """No file in the tree is newer than SOURCE_DATE_EPOCH."""
    count = 0
    for directory, names, files in os.walk(root, followlinks=False):
        for name in [''] + names + files:
            path = os.path.join(directory, name) if name else directory
            info = os.lstat(path)
            if info.st_mtime > epoch:
                os.utime(path, (epoch, epoch), follow_symlinks=False)
                count += 1
    return count


# --- kernel: release string and module vermagic ------------------------------

def _load_boot_tool():
    spec = importlib.util.spec_from_file_location('replace_appended_dtb', ROOT / 'kernel/audio/replace-appended-dtb.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LINUX_BANNER = re.compile(rb'Linux version (\d+\.\d+[^\s\x00]{0,120}) ')


def kernel_release(path):
    """The release string (`uname -r`) of a kernel artefact.

    Accepts an Android v0 boot image (as the board boots), a gzip-compressed
    Image, or a raw Image. The string is read from the kernel's own banner, so
    it is what the kernel will compare module vermagic against.
    """
    data = pathlib.Path(path).read_bytes()
    if data.startswith(b'ANDROID!'):
        boot = _load_boot_tool()
        try:
            kernel = boot.parse(data)['kernel']
        except (SystemExit, struct.error) as error:
            raise BuildError(f'{path}: not a usable Android v0 boot image ({error})')
        data = kernel
    if data[:2] == b'\x1f\x8b':
        # An appended DTB follows the gzip stream; decompressobj stops at its end.
        try:
            data = zlib.decompressobj(wbits=31).decompress(data)
        except zlib.error as error:
            raise BuildError(f'{path}: the kernel does not decompress ({error})')
    releases = {match.group(1).decode('ascii', 'replace') for match in LINUX_BANNER.finditer(data)}
    if len(releases) != 1:
        raise BuildError(f'{path}: expected one "Linux version" banner, found {len(releases)}')
    return releases.pop()


def module_vermagic(data):
    """The vermagic string of a kernel module (ELF64 little-endian .modinfo), or None."""
    if data[:4] != b'\x7fELF' or len(data) < 64 or data[4] != 2 or data[5] != 1:
        return None
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3A)
    if shentsize != 64 or shoff + shnum * 64 > len(data) or shstrndx >= shnum:
        return None

    def section(index):
        name, _type, _flags, _addr, offset, size = struct.unpack_from('<IIQQQQ', data, shoff + index * 64)
        return name, offset, size
    _, names_offset, names_size = section(shstrndx)
    names = data[names_offset:names_offset + names_size]
    for index in range(shnum):
        name, offset, size = section(index)
        if names[name:names.find(b'\0', name)] == b'.modinfo':
            for entry in data[offset:offset + size].split(b'\0'):
                if entry.startswith(b'vermagic='):
                    return entry[len(b'vermagic='):].decode('ascii', 'replace')
    return None


def _module_bytes(path):
    name = str(path)
    data = pathlib.Path(path).read_bytes()
    if name.endswith('.ko'):
        return data
    if name.endswith('.ko.xz'):
        return lzma.decompress(data)
    if name.endswith('.ko.gz'):
        return gzip.decompress(data)
    if name.endswith('.ko.zst'):
        zstd = shutil.which('zstd')
        if not zstd:
            raise BuildError(f'{path}: zstd-compressed module and no zstd program to read it')
        return subprocess.run([zstd, '-dc', name], check=True, capture_output=True).stdout
    return None


def check_vermagic(modules_directory, release):
    """Every module in the directory was built for exactly this kernel. Returns the count."""
    checked, wrong = 0, []
    for directory, _, files in os.walk(modules_directory):
        for name in sorted(files):
            path = os.path.join(directory, name)
            if os.path.islink(path):
                continue
            data = _module_bytes(path)
            if data is None:
                continue
            magic = module_vermagic(data)
            checked += 1
            # "6.12.49-msm8916-g93a71ee9468d SMP preempt mod_unload aarch64":
            # the kernel refuses a module whose first word is not its release.
            if magic is None or magic.split(' ', 1)[0] != release:
                wrong.append(f"{os.path.relpath(path, modules_directory)}: vermagic {magic!r}")
    if wrong:
        raise BuildError(f'kernel modules do not match kernel release {release}:\n  ' + '\n  '.join(wrong[:20]))
    if not checked:
        raise BuildError('the modules input holds no kernel module (*.ko, *.ko.xz, *.ko.gz, *.ko.zst)')
    return checked


def _own_by_root(path, mode):
    os.chmod(path, mode)
    if os.geteuid() == 0:
        os.chown(path, 0, 0)


def install_modules(root, source, release):
    """Install lib/modules/<release> into the tree after the vermagic check."""
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._+-]*$', release):
        raise BuildError(f'kernel release {release!r} is not usable as a directory name')
    root, source = pathlib.Path(root), pathlib.Path(source)
    staging = root / '.nsh-modules'
    if staging.exists():
        shutil.rmtree(staging)
    try:
        if source.is_dir():
            found = None
            for candidate in (source / 'lib/modules' / release, source / 'usr/lib/modules' / release, source / release, source):
                if (candidate / 'modules.dep').is_file() or (candidate / 'kernel').is_dir():
                    found = candidate
                    break
            if found is None:
                raise BuildError(f'{source}: no lib/modules/{release} tree found')
            shutil.copytree(found, staging, symlinks=True)
        else:
            marker = f'lib/modules/{release}/'
            staging.mkdir()
            try:
                archive = tarfile.open(source)
            except (OSError, tarfile.TarError) as error:
                raise BuildError(f'{source}: neither a directory nor a tar archive ({error})')
            with archive:
                members = 0
                for member in archive:
                    name = member.name.lstrip('./')
                    position = name.find(marker)
                    if position < 0 or (position and name[position - 1] != '/'):
                        continue
                    relative = name[position + len(marker):]
                    if not relative or '..' in pathlib.PurePosixPath(relative).parts:
                        continue
                    target = staging / relative
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif member.isreg():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with archive.extractfile(member) as handle, open(target, 'wb') as out:
                            shutil.copyfileobj(handle, out)
                        members += 1
                    elif member.issym() and relative in ('build', 'source'):
                        continue  # links into the build host's source tree
                    else:
                        raise BuildError(f'{source}: unexpected entry {member.name}')
                if not members:
                    raise BuildError(f'{source}: no lib/modules/{release}/ in the archive')
        for link in ('build', 'source'):
            if (staging / link).is_symlink():
                (staging / link).unlink()
        count = check_vermagic(staging, release)
        if not (staging / 'modules.dep').is_file():
            raise BuildError('the modules input has no modules.dep; run depmod when the modules are built '
                             '(this script does not run host tools against the target tree)')
        for directory, _, files in os.walk(staging):
            _own_by_root(directory, 0o755)
            for name in files:
                _own_by_root(os.path.join(directory, name), 0o644)
        parent = root / ('usr/lib/modules' if (root / 'lib').is_symlink() else 'lib/modules')
        parent.mkdir(parents=True, exist_ok=True)
        target = parent / release
        if target.exists():
            raise BuildError(f'{target.relative_to(root)} already exists in the rootfs')
        os.rename(staging, target)
        return count
    finally:
        if staging.exists():
            shutil.rmtree(staging)


# --- operator-supplied firmware ----------------------------------------------

def install_firmware(root, source):
    """Copy operator-supplied firmware into usr/lib/firmware; returns the file list.

    These files are the property of the device vendor. They are never in the
    repository, never downloaded, and a rootfs that contains them must not be
    redistributed by this project. What is accepted is firmware that is the
    same on every unit of the board model; anything that is unique to one unit
    (modemst1/modemst2/fsg/fsc/persist contents, NV/QCN/EFS exports) is refused
    by name, with the same rules the package gate uses.
    """
    root, source = pathlib.Path(root), pathlib.Path(source)
    if not source.is_dir():
        raise BuildError(f'firmware directory {source} does not exist')
    base = root / ('usr/lib/firmware' if (root / 'lib').is_symlink() else 'lib/firmware')
    listed = []
    for absolute, relative, info in rules.walk_files(str(source)):
        if not stat.S_ISREG(info.st_mode):
            raise BuildError(f'firmware/{relative}: only regular files are accepted')
        categories = set(rules.name_findings(relative.rsplit('/', 1)[-1], package=False)) & {'modem-calibration', 'release-private-key'}
        categories.update(rules.scan_stream(absolute))
        if categories:
            raise BuildError(f"firmware/{relative}: refused ({', '.join(sorted(categories))}); per-device modem data and keys "
                             'never go into an image')
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(absolute, target)
        _own_by_root(target, 0o644)
        listed.append({'path': str(target.relative_to(root)), 'size': info.st_size, 'sha256': sha256_file(absolute)})
    if not listed:
        raise BuildError(f'firmware directory {source} is empty')
    return sorted(listed, key=lambda entry: entry['path'])


# --- the tree as a hash, and the image's inode times --------------------------

def tree_lines(root):
    """One line per path: type, mode, owner, size, content hash or link target, xattrs."""
    root = str(root)
    for directory, names, files in os.walk(root, followlinks=False):
        names.sort()
        for name in sorted(names + files):
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, root).replace(os.sep, '/')
            info = os.lstat(path)
            kind = stat.S_IFMT(info.st_mode)
            fields = [format(stat.S_IMODE(info.st_mode), '04o'), str(info.st_uid), str(info.st_gid)]
            if kind == stat.S_IFLNK:
                fields = ['l'] + fields + ['->' + os.readlink(path)]
            elif kind == stat.S_IFDIR:
                fields = ['d'] + fields
            elif kind == stat.S_IFREG:
                fields = ['f'] + fields + [str(info.st_size), sha256_file(path)]
            else:
                raise BuildError(f'{relative}: device nodes, sockets and FIFOs do not belong in the rootfs tree')
            if kind != stat.S_IFLNK:
                try:
                    for attribute in sorted(os.listxattr(path, follow_symlinks=False)):
                        # File capabilities are part of the system; labels a
                        # build host's security module adds are not.
                        if attribute != 'security.capability' and not attribute.startswith('user.'):
                            continue
                        fields.append(attribute + '=' + os.getxattr(path, attribute, follow_symlinks=False).hex())
                except OSError:
                    pass
            yield ' '.join(fields) + ' ' + json.dumps(relative)


def tree_hash(root):
    digest = hashlib.sha256()
    count = 0
    for line in tree_lines(root):
        digest.update(line.encode('utf-8', 'surrogateescape') + b'\n')
        count += 1
    return digest.hexdigest(), count


def image_time_commands(root, epoch):
    """debugfs commands that set every inode's change and access time.

    mke2fs -d copies ctime and atime from the staging files, and those are the
    moment of the build. Modification times are already clamped in the tree.
    """
    yield f'set_inode_field / ctime @{epoch}'
    yield f'set_inode_field / atime @{epoch}'
    root = str(root)
    for directory, names, files in os.walk(root, followlinks=False):
        names.sort()
        for name in sorted(names + files):
            relative = '/' + os.path.relpath(os.path.join(directory, name), root).replace(os.sep, '/')
            if '"' in relative or '\n' in relative or '\\' in relative:
                raise BuildError(f'{relative!r}: a double quote, backslash or newline in a file name cannot be handled')
            yield f'set_inode_field "{relative}" ctime @{epoch}'
            yield f'set_inode_field "{relative}" atime @{epoch}'


def provenance(manifest_path, root, boot_img=None):
    """What a ROOTFS-MANIFEST.json establishes about a directory, for the packager.

    Returns a dict with a `statement` in one of exactly three wordings. The
    directory is re-hashed: a manifest that describes another tree, or a tree
    edited after it was built, establishes nothing.
    """
    unverified = {'statement': 'operator-supplied (unverified provenance)', 'built_from_lock': False, 'release_input': False}
    if not manifest_path:
        return unverified
    manifest = json.loads(pathlib.Path(manifest_path).read_text())
    if manifest.get('kind') != 'nassimhub-ufi003-rootfs-base' or manifest.get('schema') != 1:
        raise BuildError(f'{manifest_path} is not a rootfs manifest written by build-rootfs.sh')
    digest, _ = tree_hash(root)
    if digest != manifest.get('tree_sha256'):
        raise BuildError('the rootfs directory is not the tree its ROOTFS-MANIFEST.json describes (it was changed after it was built, '
                         'or the manifest belongs to another build)')
    if boot_img is not None and sha256_file(boot_img) != (manifest.get('kernel') or {}).get('boot_img_sha256'):
        # The modules in this tree were checked against one kernel only.
        raise BuildError('the boot image is not the one this rootfs was built for (ROOTFS-MANIFEST.json kernel.boot_img_sha256): '
                         'its modules would not load')
    common = {key: manifest.get(key) for key in ('tree_sha256', 'lock', 'snapshot', 'source_date_epoch', 'package_set', 'kernel',
                                                 'firmware', 'bootstrap', 'non_release_reasons', 'image')}
    if manifest.get('release_input') is True:
        return dict(common, statement=f"built from lock {manifest['lock']['sha256']}", built_from_lock=True, release_input=True)
    return dict(common, statement='built by build-rootfs.sh WITHOUT a resolved lock (non-reproducible, not a release input)',
                built_from_lock=False, release_input=False)


# --- command line -----------------------------------------------------------

def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('lock-check')
    check.add_argument('lock')
    check.add_argument('--release', action='store_true')
    include = commands.add_parser('lock-include')
    include.add_argument('lock')
    include.add_argument('--setup-ap', action='store_true')
    resolve = commands.add_parser('lock-resolve')
    resolve.add_argument('--lock', required=True)
    resolve.add_argument('--status', required=True)
    resolve.add_argument('--timestamp', required=True)
    resolve.add_argument('--out', required=True)
    resolve.add_argument('--index', action='append', default=[])
    resolve.add_argument('--release-file', action='append', default=[])
    resolve.add_argument('--kernel-release')
    resolve.add_argument('--boot-img-sha256')
    resolve.add_argument('--modules-sha256')
    resolve.add_argument('--uid', type=int)
    resolve.add_argument('--gid', type=int)
    resolve.add_argument('--image-mib', type=int)
    resolve.add_argument('--setup-ap', action='store_true')
    resolve.add_argument('--test-fixture', action='store_true')
    verify = commands.add_parser('verify-packages')
    verify.add_argument('--lock', required=True)
    verify.add_argument('--root', required=True)
    final = commands.add_parser('finalize')
    final.add_argument('--root', required=True)
    final.add_argument('--lock', required=True)
    final.add_argument('--epoch', type=int, required=True)
    final.add_argument('--uid', type=int)
    final.add_argument('--gid', type=int)
    release = commands.add_parser('kernel-release')
    release.add_argument('file')
    modules = commands.add_parser('modules')
    modules.add_argument('--root', required=True)
    modules.add_argument('--modules', required=True)
    modules.add_argument('--kernel-release', required=True)
    firmware = commands.add_parser('firmware')
    firmware.add_argument('--root', required=True)
    firmware.add_argument('--dir', required=True)
    firmware.add_argument('--out', required=True)
    tree = commands.add_parser('tree-hash')
    tree.add_argument('root')
    listing = commands.add_parser('tree-list')
    listing.add_argument('root')
    clamp = commands.add_parser('clamp-mtime')
    clamp.add_argument('root')
    clamp.add_argument('epoch', type=int)
    times = commands.add_parser('image-times')
    times.add_argument('root')
    times.add_argument('epoch', type=int)
    origin = commands.add_parser('provenance')
    origin.add_argument('--manifest', default='')
    origin.add_argument('--root', required=True)
    origin.add_argument('--boot-img')
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == 'lock-check':
            lock = load_lock(arguments.lock)
            problems = lock_problems(lock)
            if problems:
                print(f'rootfs lock {arguments.lock}: NOT resolved')
                for problem in problems:
                    print('  ' + problem)
                return 1 if arguments.release else 0
            print(f"rootfs lock {arguments.lock}: resolved, snapshot {lock['snapshot']['timestamp']}, "
                  f"{len(lock['packages']['versions'])} packages, manifest sha256 {lock['packages']['manifest_sha256']}")
            return 0
        if arguments.command == 'lock-include':
            print(','.join(requested_packages(load_lock(arguments.lock), arguments.setup_ap)))
            return 0
        if arguments.command == 'lock-resolve':
            kernel = {key: value for key, value in (('release', arguments.kernel_release), ('boot_img_sha256', arguments.boot_img_sha256),
                                                    ('modules_sha256', arguments.modules_sha256)) if value}
            lock = resolve_lock(load_lock(arguments.lock), pathlib.Path(arguments.status).read_text(encoding='utf-8'), arguments.timestamp,
                                indexes=[pathlib.Path(path).read_text(encoding='utf-8') for path in arguments.index],
                                release_files=[pathlib.Path(path).read_text(encoding='utf-8', errors='replace') for path in arguments.release_file],
                                kernel=kernel, uid=arguments.uid, gid=arguments.gid, image_mib=arguments.image_mib,
                                setup_ap=arguments.setup_ap, test_fixture=arguments.test_fixture)
            pathlib.Path(arguments.out).write_text(json.dumps(lock, indent=2) + '\n')
            print(f"wrote {arguments.out}: status {lock['status']!r}, {lock['packages']['count']} packages, "
                  f"manifest sha256 {lock['packages']['manifest_sha256']}")
            return 0
        if arguments.command == 'verify-packages':
            count, digest = verify_packages(load_lock(arguments.lock), arguments.root)
            print(f'package set matches the lock: {count} packages, manifest sha256 {digest}')
            return 0
        if arguments.command == 'finalize':
            lock = load_lock(arguments.lock)
            user = dict(lock.get('service_user', {}))
            if arguments.uid is not None:
                user['uid'] = arguments.uid
            if arguments.gid is not None:
                user['gid'] = arguments.gid
            if not isinstance(user.get('uid'), int) or not isinstance(user.get('gid'), int):
                raise BuildError('the service user needs a uid and a gid (lock service_user, or --service-uid/--service-gid with --unlocked)')
            finalize(arguments.root, arguments.epoch, user)
            print(f"finalized: service user {user['name']} {user['uid']}:{user['gid']}, fixed host files, build residue removed")
            return 0
        if arguments.command == 'kernel-release':
            print(kernel_release(arguments.file))
            return 0
        if arguments.command == 'modules':
            count = install_modules(arguments.root, arguments.modules, arguments.kernel_release)
            print(f'installed {count} kernel modules for {arguments.kernel_release}; every vermagic matches')
            return 0
        if arguments.command == 'firmware':
            listed = install_firmware(arguments.root, arguments.dir)
            pathlib.Path(arguments.out).write_text(json.dumps(listed, indent=2) + '\n')
            print(f'copied {len(listed)} operator-supplied firmware files (NOT redistributable; listed in the rootfs manifest)')
            return 0
        if arguments.command == 'tree-hash':
            digest, count = tree_hash(arguments.root)
            print(f'{digest} {count}')
            return 0
        if arguments.command == 'tree-list':
            for line in tree_lines(arguments.root):
                print(line)
            return 0
        if arguments.command == 'clamp-mtime':
            clamp_mtime(arguments.root, arguments.epoch)
            return 0
        if arguments.command == 'image-times':
            for command in image_time_commands(arguments.root, arguments.epoch):
                print(command)
            return 0
        if arguments.command == 'provenance':
            print(json.dumps(provenance(arguments.manifest, arguments.root, arguments.boot_img)))
            return 0
    except BuildError as error:
        print(f'rootfs_tools: {error}', file=sys.stderr)
        return 1
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
