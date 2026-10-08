#!/usr/bin/env python3
"""Fail closed on sensitive artifact classes. Reports paths only, never matching values.

    privacy-check.py                         the source tree (what gets committed)
    privacy-check.py --package DIR           a factory package (dist/factory/<version>-<variant>)
    privacy-check.py --ota-release DIR       an OTA release directory (dist/ota/<release-id>)
    privacy-check.py --public-keyring FILE   a release key file that claims to be public

The package and release modes enforce that the output is GENERIC: see
scripts/genericrules.py for what that means and for the limits of the rules.
"""
import hashlib
import json
import os
import pathlib
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree, least of all one owned by root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import genericrules as rules  # noqa: E402
import imagepolicy  # noqa: E402

root = pathlib.Path(__file__).resolve().parents[1]
patterns = [r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
 r'(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}',
 r'(?i)(?:password|passwd|psk|token)\s*[:=]\s*["\']?[^\s"\']{8,}',
 r'(?:C:|D:|F:|G:)[/\\](?:Users|Claude)[/\\][^\s]+']
# Assignment names and synthetic examples require human review; avoid matching code variables.
strong = [re.compile(p) for p in patterns[:2] + patterns[3:]]
forbidden = {'.img','.dtb','.ko','.pem','.key','.pcap','.mp3','.wav','.zip','.7z','.deb','.exe'}


def check_source(tree=root):
    """The committed tree: no binaries, no key material, no tokens, no host paths."""
    bad = []
    for p in tree.rglob('*'):
        if not p.is_file() or any(x in {'.git','build','dist','downloads','private','__pycache__'} for x in p.relative_to(tree).parts): continue
        if p.suffix.lower() in forbidden or p.name in {'device.json','admin-bootstrap.txt'} or '.bak' in p.name: bad.append(str(p.relative_to(tree))); continue
        text = p.read_text(encoding='utf-8')
        if any(rx.search(text) for rx in strong) or rules.scan_bytes(text.encode()): bad.append(str(p.relative_to(tree)))
    return sorted(set(bad))


# What a factory package may contain at its top level. Anything else is
# reported: a package is reviewed by its layout, and a file nobody expects is
# the easiest place for a device dump to hide.
PACKAGE_TOP = {'PACKAGE-MANIFEST.json', 'SHA256SUMS', 'manifest.json', 'BUILDINFO.json', 'LICENSE', 'NOTICE.md',
               'THIRD-PARTY-NOTICES.md', 'SOURCE.md', 'sbom.spdx.json', 'DEBIAN-PACKAGES.txt'}
PACKAGE_DIRS = {'images', 'rootfs-overlay', 'signatures', 'LICENSES'}
PACKAGE_IMAGES = {'images/boot.img', 'images/rootfs.img'}
OVERLAY = 'rootfs-overlay/'
KEYRING_PATH = OVERLAY + 'etc/nassimhub/ota-keys.json'
NO_KEYS = 'updates disabled: no release keys'
OTA_FILES = {'nassimhub-agent', 'BUILDINFO.json', 'manifest.json', 'manifest.signed.json', 'ota-keys.json', 'SHA256SUMS'}


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def scan_file(absolute, relative, info, findings, image=False):
    """Name, content and entropy rules for one file of a package or release."""
    name = relative.rsplit('/', 1)[-1]
    for category in rules.name_findings(name):
        findings.append((category, relative))
    if not rules.is_regular(info):
        return
    if image or info.st_size > rules.TEXT_LIMIT:
        for category in rules.scan_stream(absolute):
            findings.append((category, relative))
        return
    with open(absolute, 'rb') as handle:
        data = handle.read()
    for category in rules.scan_bytes(data):
        findings.append((category, relative))
    text = rules.read_text(absolute)
    if text is None:
        if rules.is_opaque_blob(absolute):
            findings.append(('opaque-binary-blob', relative))
        return
    # Public by construction and full of base64: checked for their shape
    # instead of their entropy.
    public = rules.public_keyring_problem(data) is None or rules.is_signed_manifest(data)
    for category in rules.scan_text(text, entropy=not public):
        findings.append((category, relative))
    if name.endswith('.nmconnection') and re.search(r'(?im)^\s*(?:psk|password)', text):
        findings.append(('wifi-credential', relative))


def check_package(directory):
    """Findings for a factory package directory. Empty means it passed."""
    directory = os.path.abspath(directory)
    findings = []
    manifest_path = os.path.join(directory, 'PACKAGE-MANIFEST.json')
    try:
        with open(manifest_path) as handle:
            manifest = json.load(handle)
        listed = {entry['path']: entry for entry in manifest['files']}
    except (OSError, ValueError, KeyError, TypeError):
        return [('package-manifest-unreadable', 'PACKAGE-MANIFEST.json')]

    present = {}
    for absolute, relative, info in rules.walk_files(directory):
        present[relative] = (absolute, info)
        top = relative.split('/', 1)[0]
        if '/' not in relative and relative not in PACKAGE_TOP:
            findings.append(('unexpected-file', relative))
        elif '/' in relative and top not in PACKAGE_DIRS:
            findings.append(('unexpected-file', relative))
        elif top == 'images' and relative not in PACKAGE_IMAGES:
            # Only the two images this project builds and reviews. A modem,
            # bootloader or NV partition image has no place here whatever it
            # is called.
            findings.append(('unexpected-image', relative))
        scan_file(absolute, relative, info, findings, image=relative in PACKAGE_IMAGES)

    # The manifest is the package's own statement of what it contains; a file
    # it does not list, or lists differently, was added or changed afterwards.
    for relative, (absolute, info) in sorted(present.items()):
        if relative in ('PACKAGE-MANIFEST.json', 'SHA256SUMS'):
            continue
        entry = listed.get(relative)
        if entry is None:
            findings.append(('not-in-package-manifest', relative))
        elif rules.is_regular(info) and (entry.get('size') != info.st_size or entry.get('sha256') != sha256(absolute)
                                         or entry.get('mode') != format(info.st_mode & 0o7777, '04o')):
            findings.append(('differs-from-package-manifest', relative))
    for relative in sorted(set(listed) - set(present)):
        findings.append(('listed-but-missing', relative))

    updates = manifest.get('updates', {})
    if KEYRING_PATH in present:
        absolute, info = present[KEYRING_PATH]
        with open(absolute, 'rb') as handle:
            problem = rules.public_keyring_problem(handle.read())
        if problem:
            findings.append(('release-key-file-not-public', KEYRING_PATH))
        if info.st_mode & 0o7777 != 0o644:
            findings.append(('release-key-file-mode', KEYRING_PATH))
        if updates.get('release_keys') is not True:
            findings.append(('manifest-misstates-release-keys', 'PACKAGE-MANIFEST.json'))
    elif updates.get('release_keys') is not False or updates.get('status') != NO_KEYS:
        # No key file means no update can ever verify; the manifest must say so
        # rather than leave a reader to assume updates work.
        findings.append(('manifest-misstates-release-keys', 'PACKAGE-MANIFEST.json'))

    # The setup access point: what the manifest says against what the overlay
    # holds. It is off unless asked for, it is all-or-nothing, and a package
    # that has it must say so in the words a reader will search for - which
    # include that it has not been verified on hardware.
    statement = manifest.get('setup_access_point')
    statement = statement if isinstance(statement, dict) else {}
    fragment = [relative for relative in imagepolicy.SETUP_AP_FILES if OVERLAY + relative in present]
    configured = False
    if OVERLAY + imagepolicy.AGENT_CONF in present:
        text = rules.read_text(present[OVERLAY + imagepolicy.AGENT_CONF][0])
        configured = text is not None and imagepolicy.conf_enables_setup_ap(text)
    if fragment or configured:
        if len(fragment) != len(imagepolicy.SETUP_AP_FILES) or not configured:
            findings.append(('setup-ap-incomplete', OVERLAY.rstrip('/')))
        if statement.get('enabled') is not True or statement.get('status') != imagepolicy.STATUS_ON:
            findings.append(('manifest-misstates-setup-access-point', 'PACKAGE-MANIFEST.json'))
    elif statement.get('enabled') is not False or statement.get('status') != imagepolicy.STATUS_OFF:
        findings.append(('manifest-misstates-setup-access-point', 'PACKAGE-MANIFEST.json'))
    # What the overlay grants the agent user, held to the documented list.
    overlay = os.path.join(directory, OVERLAY.rstrip('/'))
    if os.path.isdir(overlay):
        enabled = bool(fragment) and statement.get('enabled') is True
        granted = imagepolicy.polkit_findings(list(rules.walk_files(overlay)), enabled) + imagepolicy.unit_findings(overlay, enabled)
        for finding in granted + imagepolicy.sysctl_findings(list(rules.walk_files(overlay))):
            category, _, where = finding.partition(': ')
            findings.append((category, OVERLAY + where if where else OVERLAY.rstrip('/')))
    return sorted(set(findings))


def check_ota_release(directory):
    """Findings for an OTA release directory. Empty means it passed."""
    directory = os.path.abspath(directory)
    findings = []
    for absolute, relative, info in rules.walk_files(directory):
        if relative not in OTA_FILES:
            findings.append(('unexpected-file', relative))
        scan_file(absolute, relative, info, findings, image=relative == 'nassimhub-agent')
        if relative == 'ota-keys.json':
            with open(absolute, 'rb') as handle:
                if rules.public_keyring_problem(handle.read()):
                    findings.append(('release-key-file-not-public', relative))
        if relative == 'manifest.signed.json':
            with open(absolute, 'rb') as handle:
                if not rules.is_signed_manifest(handle.read()):
                    findings.append(('not-a-signed-manifest', relative))
    return sorted(set(findings))


def report(title, findings):
    if findings:
        print(title + ' FAILED, review (category: path; values are never printed):')
        for finding in findings:
            print('  ' + (': '.join(finding) if isinstance(finding, tuple) else finding))
        return 1
    return 0


def main(arguments):
    if not arguments:
        status = report('Privacy check', check_source())
        if not status:
            print('Privacy artifact/token check PASS; manual personal-data review remains required.')
        return status
    if len(arguments) != 2 or arguments[0] not in ('--package', '--ota-release', '--public-keyring'):
        print(__doc__, file=sys.stderr)
        return 2
    mode, target = arguments
    if mode == '--public-keyring':
        try:
            with open(target, 'rb') as handle:
                problem = rules.public_keyring_problem(handle.read(1 << 20))
        except OSError:
            problem = 'cannot be read'
        if problem:
            # The reason, never the content: this may be a private key file.
            print(f'Release key file check FAILED: {os.path.basename(target)} is not a PUBLIC release keyring ({problem}).')
            return 1
        print('Release key file check PASS: public keys only.')
        return 0
    if not os.path.isdir(target):
        print(f'{target} is not a directory', file=sys.stderr)
        return 2
    if mode == '--package':
        status = report('Generic package check', check_package(target))
        if not status:
            print('Generic package check PASS (names, layout, key formats, labelled identifiers); manual review remains required.')
        return status
    status = report('OTA release check', check_ota_release(target))
    if not status:
        print('OTA release check PASS: no private key material; manual review remains required.')
    return status


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
