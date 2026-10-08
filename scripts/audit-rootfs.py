#!/usr/bin/env python3
"""Reject populated device state before packaging; never print secret content.

    audit-rootfs.py [--setup-ap] ROOTFS_DIR

Run on the operator's clean rootfs and again on the staged tree (rootfs +
overlay + agent) immediately before it becomes rootfs.img. The first group of
checks is the original state/account audit; the second makes sure the tree is
GENERIC in the sense of scripts/genericrules.py; the third holds what the tree
grants the agent user (polkit actions, capabilities) to the documented list in
scripts/imagepolicy.py. Symbolic links are never followed: an untrusted rootfs
may link anywhere on the build host.

--setup-ap says the package was asked for with NSH_SETUP_AP=on. Only then are
the files of firmware/setup-ap-overlay/ accepted, and then all of them, the
enabling configuration and dnsmasq are required: half a setup access point is
refused in both directions.
"""
import os
import hashlib
import pathlib
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree, least of all one owned by root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import genericrules as rules  # noqa: E402
import imagepolicy  # noqa: E402

# Shipped by Debian packages, not by a device or a person. Agent state file
# names and labelled-identifier rules are not applied below these: the names
# are generic enough (`device.json`) that a package may legitimately own one.
# Key material and modem calibration names are searched for everywhere.
VENDOR = ('usr/lib/', 'usr/share/', 'usr/include/', 'usr/src/', 'usr/bin/', 'usr/sbin/', 'usr/libexec/',
          'lib/', 'bin/', 'sbin/', 'var/lib/dpkg/', 'var/lib/apt/', 'var/cache/')
# Directories that hold per-device runtime state; anything in them is a finding.
STATE_DIRS = ('var/lib/nassimhub', 'var/lib/NetworkManager', 'root/.ssh', 'root/.config', 'home',
              'var/lib/rmtfs', 'var/lib/iwd', 'var/lib/bluetooth', 'etc/ssl/private', 'persist')
# The only files the image ships in the agent's configuration directory.
NASSIMHUB_ETC = {'agent.conf', 'ota-keys.json'}
# Debian 13 libpam-modules' unmodified namespace helper computes passwd with
# getent; it contains no preset password. An edited copy does not qualify.
PUBLIC_CONFIG_SCRIPTS = {
    'etc/security/namespace.init': '772e5773586a236034156ac660f8d234bf50f4cebf5811b15b55b890b83cef64',
}


def audit(root, setup_ap=False):
    """Findings for a rootfs tree, as short strings naming a rule and a path."""
    root = pathlib.Path(root).resolve()
    bad = []
    for location in STATE_DIRS:
        p = root/location
        if p.is_dir() and not p.is_symlink() and any(p.rglob('*')): bad.append(location)
    for pattern in ('etc/ssh/ssh_host_*_key*','etc/NetworkManager/system-connections/*','etc/nassimhub/*.enabled','etc/nassimhub/*.verified','root/.*history','var/log/*'):
        for p in root.glob(pattern):
            if p.name=='nassimhub-usb.nmconnection' and p.is_file() and 'psk=' not in p.read_text(): continue
            if p.is_file() and p.stat().st_size: bad.append(str(p.relative_to(root)))
    # Device-unique seeds: a shared machine-id or random seed makes every
    # flashed device start from the same "unique" value.
    for name in ('etc/machine-id', 'var/lib/dbus/machine-id', 'var/lib/systemd/random-seed'):
        p = root/name
        if p.is_file() and not p.is_symlink() and p.read_bytes().strip(): bad.append(name)
    if not (root/'etc/os-release').is_file() or 'VERSION_ID="13"' not in (root/'etc/os-release').read_text(): bad.append('expected Debian 13 os-release')
    passwd=(root/'etc/passwd').read_text() if (root/'etc/passwd').exists() else ''
    if not any(line.startswith('nassimhub:') and line.split(':')[2]!='0' for line in passwd.splitlines()): bad.append('missing non-root nassimhub account')
    for name in ('etc/shadow', 'etc/shadow-'):
        shadow=(root/name).read_text() if (root/name).is_file() else ''
        for line in shadow.splitlines():
            fields=line.split(':')
            if len(fields)>1 and not fields[1].startswith(('!','*')): bad.append('unlocked account/password in ' + name); break

    for absolute, relative, info in rules.walk_files(root):
        vendor = relative.startswith(VENDOR)
        name = relative.rsplit('/', 1)[-1]
        if relative.startswith('var/log/') and rules.is_regular(info) and info.st_size:
            bad.append('log: ' + relative)
        if relative.startswith('etc/nassimhub/') and relative[len('etc/nassimhub/'):] not in NASSIMHUB_ETC:
            bad.append('unexpected file in etc/nassimhub: ' + relative)
        categories = set(rules.name_findings(name, package=False))
        if vendor:
            # In vendor directories only the names that are never legitimate.
            categories &= {'modem-calibration', 'release-private-key'}
        if not rules.is_regular(info):
            bad.extend(f'{category}: {relative}' for category in sorted(categories))
            continue
        if info.st_size == 0:
            # An empty placeholder (authorized_keys created by a package
            # script, a truncated machine-id) carries nothing.
            continue
        # Key material is searched for in every regular file, vendor or not.
        categories.update(rules.scan_stream(absolute))
        if not vendor:
            text = rules.read_text(absolute)
            if text is not None:
                entropy = relative == 'etc/nassimhub/agent.conf'
                categories.update(rules.scan_text(text, entropy=entropy))
        expected = PUBLIC_CONFIG_SCRIPTS.get(relative)
        if expected and hashlib.sha256(pathlib.Path(absolute).read_bytes()).hexdigest() == expected:
            categories.discard('credential')
        if relative == 'etc/nassimhub/ota-keys.json':
            with open(absolute, 'rb') as handle:
                if rules.public_keyring_problem(handle.read()):
                    categories.add('release-key-file-not-public')
            # root-owned and not writable by anyone else: the agent verifies
            # updates against keys it must be unable to change (ota/keyring.go).
            if info.st_mode & 0o022:
                categories.add('release-key-file-writable')
        bad.extend(f'{category}: {relative}' for category in sorted(categories))
    bad.extend(imagepolicy.findings(str(root), rules.walk_files(root), setup_ap))
    return sorted(set(bad))


def main(arguments):
    setup_ap = arguments[:1] == ['--setup-ap']
    if setup_ap:
        arguments = arguments[1:]
    if len(arguments) != 1 or not os.path.isdir(arguments[0]):
        print('usage: audit-rootfs.py [--setup-ap] ROOTFS_DIR', file=sys.stderr)
        return 2
    bad = audit(arguments[0], setup_ap)
    if bad:
        print('Clean rootfs audit FAILED:'); print('\n'.join(bad)); return 1
    print('Clean rootfs state/account audit PASS' + (' (setup access point files expected and present)' if setup_ap else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
