#!/usr/bin/env python3
"""SBOM (SPDX 2.3 JSON), licence policy and SPDX-coverage checks. Standard library only.

    sbom.py generate --agent build/nassimhub-agent [--buildinfo FILE] [--out sbom.spdx.json]
                     [--notices THIRD-PARTY-NOTICES.md] [--licence-dir DIR] [--no-policy]
                     [--rootfs-lock firmware/rootfs.lock.json]
    sbom.py policy SBOM.spdx.json          re-run the licence policy on an existing SBOM
    sbom.py spdx-coverage [--quiet]        licence coverage of scripts/, kernel/, node/

generate
    Go modules come from the binary itself (`go version -m`: what was actually
    linked, not what go.mod could pull in) and their source directories from
    `go list -m -json all`. A module's licence is read from the licence file in
    its source directory and recognised by its text; when there is no such
    file, or the text is not one this script recognises with confidence, the
    licence is recorded as NOASSERTION. It is never inferred from a module's
    name, host or reputation.
    The non-Go components named in firmware/upstream.lock.json (Debian base,
    kernel, reference builder) are listed with their pinned revisions.
    The Debian packages of the root filesystem are listed one by one ONLY when
    firmware/rootfs.lock.json is resolved (scripts/build-rootfs.sh --lock):
    name, version, architecture, source package and, when the lock has it, the
    SHA-256 of the .deb in the pinned snapshot. With an unresolved lock the
    Debian entry says "not included: rootfs lock unresolved" - no package
    list is guessed. Either way this is what the LOCK pins, not an inventory
    of some image: a package built from another rootfs lists its own packages
    in DEBIAN-PACKAGES.txt.

policy
    Fails on any Go module whose licence is NOASSERTION or not in the allowed
    list of scripts/licence-policy.json, unless that exact module and version
    is in the policy's allowlist WITH a reason.

spdx-coverage
    Counts files carrying an SPDX-License-Identifier header and files covered
    by LICENSES/spdx-map.json (a REUSE-style path-to-licence mapping that
    restates LICENSES/README.md), and fails when a file has neither.

Environment: GO (go command), NSH_GO_FLAGS (extra flags for `go list`, test
use only), SOURCE_DATE_EPOCH (fixes the SBOM creation time).
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / 'scripts' / 'licence-policy.json'
SPDX_MAP = ROOT / 'LICENSES' / 'spdx-map.json'
LOCK = ROOT / 'firmware' / 'upstream.lock.json'
ROOTFS_LOCK = ROOT / 'firmware' / 'rootfs.lock.json'
LICENCE_FILE = re.compile(r'^(?:LICEN[CS]E|COPYING|UNLICENSE)(?:[.-].*)?$', re.IGNORECASE)
NOASSERTION = 'NOASSERTION'


# --- licence recognition ----------------------------------------------------

def classify_licence(text):
    """The SPDX identifier a licence text is recognised as, or None.

    Only texts whose identifier follows from the wording itself are named. The
    GNU family is deliberately NOT named from its text: the licence document is
    the same for "-only" and "-or-later", and which one applies is stated by
    the project, not by the file. Those come back as None and need a reviewed
    allowlist entry.
    """
    flat = ' '.join(text.lower().split())
    flat = flat.replace('“', '"').replace('”', '"').replace("''", '"').replace('``', '"')
    found = []
    if 'apache license' in flat and 'version 2.0' in flat and 'terms and conditions for use, reproduction, and distribution' in flat:
        found.append('Apache-2.0')
    if 'permission is hereby granted, free of charge, to any person obtaining a copy' in flat and 'the software is provided "as is"' in flat:
        found.append('MIT')
    if 'redistribution and use in source and binary forms' in flat and 'this software is provided by' in flat:
        if 'all advertising materials' in flat:
            return None  # BSD-4-Clause and relatives: reviewed by a person.
        if 'neither the name' in flat or 'may not be used to endorse or promote' in flat:
            found.append('BSD-3-Clause')
        else:
            found.append('BSD-2-Clause')
    if 'permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted' in flat:
        found.append('ISC')
    if 'mozilla public license version 2.0' in flat or 'mozilla public license, version 2.0' in flat:
        found.append('MPL-2.0')
    if 'gnu general public license' in flat or 'gnu affero general public license' in flat or 'gnu lesser general public license' in flat:
        return None
    return found[0] if len(found) == 1 else None


def licence_of_directory(directory):
    """(spdx id or NOASSERTION, [licence file paths], note) for a source directory."""
    if not directory or not os.path.isdir(directory):
        return NOASSERTION, [], 'module source directory is not available on this host'
    files = sorted(p for p in pathlib.Path(directory).iterdir() if p.is_file() and LICENCE_FILE.match(p.name))
    if not files:
        return NOASSERTION, [], 'no licence file at the module root'
    identifiers = []
    for path in files:
        identifier = classify_licence(path.read_text(encoding='utf-8', errors='replace'))
        if identifier is None:
            return NOASSERTION, files, f'{path.name} is not a licence text this tool recognises'
        if identifier not in identifiers:
            identifiers.append(identifier)
    return ' AND '.join(identifiers), files, 'recognised from ' + ', '.join(p.name for p in files)


# --- what was built ---------------------------------------------------------

def go_environment():
    environment = dict(os.environ, GOWORK='off', CGO_ENABLED='0', GOFLAGS='')
    return environment


def run(arguments, cwd=None):
    return subprocess.run(arguments, cwd=cwd, env=go_environment(), check=True, capture_output=True, text=True).stdout


def parse_buildinfo(text):
    """`go version -m` output -> (go version, main module path, [dependency dicts])."""
    go_version, main, dependencies = '', '', []
    lines = text.splitlines()
    if lines:
        go_version = lines[0].rsplit(':', 1)[-1].strip()
    for line in lines[1:]:
        fields = line.strip().split('\t')
        if fields[0] == 'mod' and len(fields) > 1:
            main = fields[1]
        elif fields[0] == 'dep' and len(fields) > 2:
            dependencies.append({'path': fields[1], 'version': fields[2], 'sum': fields[3] if len(fields) > 3 else ''})
        elif fields[0] == '=>' and dependencies and len(fields) > 1:
            dependencies[-1]['replace'] = {'path': fields[1], 'version': fields[2] if len(fields) > 2 else '',
                                           'sum': fields[3] if len(fields) > 3 else ''}
    return go_version, main, dependencies


def module_directories(agent_module_dir, module_paths):
    """Source directories for linked modules only; unrelated test dependencies
    need not be present in an offline release builder's module cache.
    Missing linked modules still fail the licence policy, never get guessed.
    """
    go = os.environ.get('GO', 'go')
    extra = os.environ.get('NSH_GO_FLAGS', '').split()
    try:
        output = run([go, 'list', *extra, '-m', '-json', *module_paths], cwd=agent_module_dir)
    except (OSError, subprocess.CalledProcessError):
        return {}
    directories, decoder, index = {}, json.JSONDecoder(), 0
    while index < len(output):
        while index < len(output) and output[index].isspace():
            index += 1
        if index >= len(output):
            break
        module, index = decoder.raw_decode(output, index)
        replaced = module.get('Replace') or {}
        directories[module['Path']] = replaced.get('Dir') or module.get('Dir') or ''
    return directories


def hex_of_h1(value):
    """go.sum `h1:<base64 sha256>` as hex, or '' - recorded as a comment, not as a file checksum."""
    import base64
    if not value.startswith('h1:'):
        return ''
    try:
        return base64.b64decode(value[3:], validate=True).hex()
    except ValueError:
        return ''


def spdx_id(text):
    return 'SPDXRef-' + re.sub(r'[^A-Za-z0-9.-]', '-', text)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def mapped_licence(relative):
    """The licence LICENSES/spdx-map.json assigns to a repository path, or None."""
    rules = json.loads(SPDX_MAP.read_text())['rules']
    matching = [rule for rule in rules if (relative.rstrip('/') + '/').startswith(rule['path'])]
    return max(matching, key=lambda rule: len(rule['path']))['licence'] if matching else None


def generate(arguments):
    agent = pathlib.Path(arguments.agent).resolve()
    go = os.environ.get('GO', 'go')
    go_version, main_module, dependencies = parse_buildinfo(run([go, 'version', '-m', str(agent)]))
    buildinfo = {}
    buildinfo_path = pathlib.Path(arguments.buildinfo) if arguments.buildinfo else agent.parent / 'BUILDINFO.json'
    if buildinfo_path.is_file():
        buildinfo = json.loads(buildinfo_path.read_text())
    node = pathlib.Path(arguments.node).resolve()
    directories = module_directories(node / 'agent', [dep['path'] for dep in dependencies])
    lock = json.loads(pathlib.Path(arguments.lock).read_text())
    rootfs_packages, rootfs_statement = rootfs_package_set(arguments.rootfs_lock)
    project_licence = mapped_licence('node/agent') or NOASSERTION

    epoch = os.environ.get('SOURCE_DATE_EPOCH')
    created = (datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) if epoch
               else datetime.datetime.now(datetime.timezone.utc)).strftime('%Y-%m-%dT%H:%M:%SZ')
    agent_digest = sha256(agent)
    version = buildinfo.get('version', NOASSERTION)

    packages, relationships, notices, texts = [], [], [], []
    firmware_ref, agent_ref = 'SPDXRef-Firmware', 'SPDXRef-Agent'
    packages.append({
        'SPDXID': firmware_ref, 'name': 'nassimhub-ufi003-firmware', 'versionInfo': version,
        'downloadLocation': NOASSERTION, 'filesAnalyzed': False, 'supplier': NOASSERTION,
        'licenseConcluded': NOASSERTION, 'licenseDeclared': mapped_licence('firmware/overlay') or NOASSERTION,
        'copyrightText': NOASSERTION, 'primaryPackagePurpose': 'FIRMWARE',
        'comment': f"Firmware integration for board {lock.get('board', 'unknown')}: overlay, packaging scripts and the agent. "
                   'Licence as stated in LICENSES/README.md and LICENSES/spdx-map.json.',
    })
    packages.append({
        'SPDXID': agent_ref, 'name': 'nassimhub-agent', 'versionInfo': version,
        'downloadLocation': NOASSERTION, 'filesAnalyzed': False, 'supplier': NOASSERTION,
        'licenseConcluded': NOASSERTION, 'licenseDeclared': project_licence,
        'copyrightText': NOASSERTION, 'primaryPackagePurpose': 'APPLICATION',
        'checksums': [{'algorithm': 'SHA256', 'checksumValue': agent_digest}],
        'comment': f"Static {buildinfo.get('goos', 'linux')}/{buildinfo.get('goarch', 'arm64')} binary, main module {main_module}; "
                   f"node tree sha256 {buildinfo.get('node_tree_sha256', 'unknown')}; go.mod: {buildinfo.get('go_mod', 'unknown')}.",
    })
    relationships.append({'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': firmware_ref})
    relationships.append({'spdxElementId': firmware_ref, 'relationshipType': 'CONTAINS', 'relatedSpdxElement': agent_ref})

    # The Go standard library and runtime are linked into every Go binary.
    goroot = ''
    try:
        goroot = run([go, 'env', 'GOROOT']).strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    modules = [{'path': 'std', 'version': go_version, 'dir': goroot, 'name': 'Go standard library and runtime', 'sum': ''}]
    for dependency in dependencies:
        effective = dependency.get('replace', dependency)
        modules.append({'path': dependency['path'], 'version': effective.get('version') or dependency['version'],
                        'dir': directories.get(dependency['path'], ''), 'name': dependency['path'],
                        'sum': effective.get('sum', ''), 'replace': dependency.get('replace'),
                        'required': dependency['version']})

    for module in modules:
        replace = module.get('replace')
        local = bool(replace) and replace['path'].startswith(('.', '/'))
        if local:
            # A module replaced by a directory of this repository (node/proto,
            # node/xport): its licence is the repository's statement for that
            # path, not a guess from a file that is not there.
            # --node may be a copy of node/ somewhere else (the reproducibility
            # test builds from one); a module inside it is node/<...> all the same.
            relative = ''
            if module['dir']:
                inside = os.path.relpath(os.path.realpath(module['dir']), node)
                relative = 'node/' + inside if not inside.startswith('..') else ''
            licence = (mapped_licence(relative) if relative else None) or NOASSERTION
            files, note = [], 'in-tree module; licence from LICENSES/spdx-map.json' if licence != NOASSERTION else 'in-tree module outside the mapped paths'
            module_version = buildinfo.get('version', module['version'])
        else:
            licence, files, note = licence_of_directory(module['dir'])
            module_version = module['version']
        reference = spdx_id('GoModule-' + module['path'] + '-' + module_version)
        comment = note
        if replace and not local:
            comment += f"; go.mod requires {module['required']}, replaced by {replace['path']} {replace['version']}"
        digest = hex_of_h1(module['sum'])
        if digest:
            comment += f'; Go module hash h1 (sha256 of the module file list, hex): {digest}'
        package = {
            'SPDXID': reference, 'name': module['name'], 'versionInfo': module_version,
            'downloadLocation': NOASSERTION if local or module['path'] == 'std' else f"https://proxy.golang.org/{module['path']}/@v/{module_version}.zip",
            'filesAnalyzed': False, 'supplier': NOASSERTION,
            'licenseConcluded': licence, 'licenseDeclared': licence, 'copyrightText': NOASSERTION, 'comment': comment,
        }
        if module['path'] != 'std' and not local:
            package['externalRefs'] = [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl',
                                        'referenceLocator': f"pkg:golang/{module['path']}@{module_version}"}]
        packages.append(package)
        relationships.append({'spdxElementId': agent_ref, 'relationshipType': 'STATIC_LINK', 'relatedSpdxElement': reference})
        notices.append((module['name'], module_version, licence, note))
        if not local:
            texts.extend((module['path'], module_version, path) for path in files)

    # Non-Go components: pinned in firmware/upstream.lock.json. Their licences
    # are per package/file upstream and are not asserted here.
    distro = lock.get('distro', '')
    if distro:
        reference = 'SPDXRef-Distro'
        packages.append({
            'SPDXID': reference, 'name': distro, 'versionInfo': NOASSERTION, 'downloadLocation': NOASSERTION,
            'filesAnalyzed': False, 'supplier': 'Organization: Debian', 'licenseConcluded': NOASSERTION, 'licenseDeclared': NOASSERTION,
            'copyrightText': NOASSERTION, 'primaryPackagePurpose': 'OPERATING-SYSTEM',
            'comment': f"Base system ({lock.get('architecture', '')}). Each Debian package keeps its own licence "
                       '(/usr/share/doc/*/copyright in the image). ' + lock.get('note', '')
                       + ' Root filesystem package set: ' + rootfs_statement + '.',
        })
        relationships.append({'spdxElementId': firmware_ref, 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': reference})
        for package in rootfs_packages:
            deb = spdx_id(f"Deb-{package['name']}-{package['arch']}-{package['version']}")
            entry = {
                'SPDXID': deb, 'name': package['name'], 'versionInfo': package['version'], 'downloadLocation': NOASSERTION,
                'filesAnalyzed': False, 'supplier': 'Organization: Debian',
                # Not read from the package's copyright file, so not asserted.
                'licenseConcluded': NOASSERTION, 'licenseDeclared': NOASSERTION, 'copyrightText': NOASSERTION,
                'comment': f"Debian binary package ({package['arch']}); source package {package.get('source', package['name'])} "
                           f"{package.get('source_version', package['version'])}.",
                'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl',
                                  'referenceLocator': f"pkg:deb/debian/{package['name']}@{package['version']}?arch={package['arch']}"}],
            }
            if package.get('deb_sha256'):
                entry['checksums'] = [{'algorithm': 'SHA256', 'checksumValue': package['deb_sha256']}]
            packages.append(entry)
            relationships.append({'spdxElementId': reference, 'relationshipType': 'CONTAINS', 'relatedSpdxElement': deb})
    if lock.get('kernel_repository'):
        reference = 'SPDXRef-Kernel'
        packages.append({
            'SPDXID': reference, 'name': 'Linux kernel (ufi003-kernel)', 'versionInfo': lock.get('kernel_version', NOASSERTION),
            'downloadLocation': f"git+{lock['kernel_repository']}@{lock.get('kernel_commit', '')}",
            'filesAnalyzed': False, 'supplier': NOASSERTION, 'licenseConcluded': NOASSERTION, 'licenseDeclared': NOASSERTION,
            'copyrightText': NOASSERTION, 'primaryPackagePurpose': 'OPERATING-SYSTEM',
            'comment': f"Release {lock.get('kernel_release', '')}. Not built or redistributed by this repository; see the upstream "
                       'COPYING. The patches in kernel/audio are GPL-2.0-only (LICENSES/README.md).',
        })
        relationships.append({'spdxElementId': firmware_ref, 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': reference})
    if lock.get('reference_builder_repository'):
        reference = 'SPDXRef-ReferenceBuilder'
        packages.append({
            'SPDXID': reference, 'name': 'ufi003-debian (reference builder)', 'versionInfo': lock.get('reference_builder_commit', NOASSERTION),
            'downloadLocation': f"git+{lock['reference_builder_repository']}@{lock.get('reference_builder_commit', '')}",
            'filesAnalyzed': False, 'supplier': NOASSERTION, 'licenseConcluded': NOASSERTION, 'licenseDeclared': NOASSERTION,
            'copyrightText': NOASSERTION, 'comment': 'Reference only; not bundled (NOTICE.md).',
        })
        relationships.append({'spdxElementId': reference, 'relationshipType': 'OTHER', 'relatedSpdxElement': firmware_ref,
                              'comment': 'reference build recipe, not a component of the package'})

    document = {
        'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
        'name': f'nassimhub-ufi003-firmware-{version_label(buildinfo)}',
        'documentNamespace': f'https://spdx.org/spdxdocs/nassimhub-ufi003-firmware-{agent_digest}',
        'creationInfo': {'created': created, 'creators': ['Tool: nassimhub-firmware-scripts-sbom.py']},
        'packages': packages, 'relationships': relationships,
    }
    output = json.dumps(document, indent=2) + '\n'
    if arguments.out:
        pathlib.Path(arguments.out).write_text(output)
    else:
        sys.stdout.write(output)

    if arguments.notices:
        lines = ['# Third-party notices', '',
                 'Components linked into `nassimhub-agent`, read from the binary (`go version -m`). The licence column is',
                 'what the licence file in the module source was recognised as; `NOASSERTION` means it could not be',
                 'determined and was not guessed. Licence texts are in `LICENSES/third-party/`.', '',
                 '| Component | Version | Licence | Basis |', '|---|---|---|---|']
        lines += [f'| {name} | {version} | {licence} | {note} |' for name, version, licence, note in notices]
        lines += ['', 'Not linked into the agent, present in an image built from this package:', '',
                  f"- {distro or 'Debian base system'}: every package keeps its own licence, see `/usr/share/doc/*/copyright` in the image"
                  ' and `DEBIAN-PACKAGES.txt` when the packager could read the package list.',
                  f"- Linux kernel {lock.get('kernel_version', '')} from {lock.get('kernel_repository', '')} "
                  f"(commit {lock.get('kernel_commit', '')}); the boot image is supplied by the packager.",
                  '- Modem firmware, NV and calibration data are not part of this package (NOTICE.md).', '']
        pathlib.Path(arguments.notices).write_text('\n'.join(lines))
    if arguments.licence_dir:
        target = pathlib.Path(arguments.licence_dir)
        for path, version, source in texts:
            name = 'go-standard-library' if path == 'std' else path.replace('/', '_')
            destination = target / f'{name}@{version}'
            destination.mkdir(parents=True, exist_ok=True)
            (destination / source.name).write_bytes(source.read_bytes())

    if arguments.no_policy:
        return 0
    return report_policy(check_policy(document, json.loads(POLICY.read_text())))


def rootfs_package_set(path):
    """(packages, statement) of the rootfs lock: the pinned Debian package set, or why there is none.

    The list is used only when it is the one the lock's own hash covers and a
    snapshot is named; anything less is reported as not included, never as a
    partial list.
    """
    path = pathlib.Path(path)
    if not path.is_file():
        return [], 'not included: no rootfs lock (firmware/rootfs.lock.json)'
    try:
        lock = json.loads(path.read_text())
    except ValueError:
        return [], 'not included: rootfs lock unreadable'
    packages = lock.get('packages') or {}
    versions = packages.get('versions')
    timestamp = (lock.get('snapshot') or {}).get('timestamp')
    if lock.get('status') != 'resolved' or not isinstance(versions, list) or not versions or not timestamp:
        return [], f"not included: rootfs lock unresolved (status: {lock.get('status')})"
    text = ''.join(f"{p['name']}\t{p['version']}\t{p['arch']}\n" for p in sorted(versions, key=lambda p: (p['name'], p['arch'])))
    if hashlib.sha256(text.encode()).hexdigest() != packages.get('manifest_sha256'):
        return [], 'not included: the rootfs lock\'s package list does not match its manifest_sha256'
    return versions, (f"{len(versions)} Debian packages as pinned by firmware/rootfs.lock.json: {lock.get('suite')} at snapshot.debian.org "
                      f"{timestamp}, package-set manifest sha256 {packages['manifest_sha256']}")


def version_label(buildinfo):
    return buildinfo.get('version', 'unknown')


# --- licence policy ---------------------------------------------------------

def check_policy(document, policy):
    """Problems (strings) for the Go modules of an SBOM under a policy."""
    allowed = set(policy.get('allowed', []))
    allowlist = {}
    problems = []
    for entry in policy.get('allowlist', []):
        if not str(entry.get('reason', '')).strip():
            problems.append(f"allowlist entry for {entry.get('module')} {entry.get('version')} has no reason")
            continue
        allowlist[(entry.get('module'), entry.get('version'))] = entry
    for package in document.get('packages', []):
        if not package.get('SPDXID', '').startswith('SPDXRef-GoModule-'):
            continue
        name, version, licence = package['name'], package.get('versionInfo'), package.get('licenseConcluded', NOASSERTION)
        if (name, version) in allowlist:
            continue
        if licence in (NOASSERTION, 'NONE', '', None):
            problems.append(f'{name} {version}: licence missing or not determined (NOASSERTION)')
        else:
            unknown = [part for part in re.split(r'\s+(?:AND|OR)\s+', licence) if part.strip('()') not in allowed]
            if unknown:
                problems.append(f"{name} {version}: licence {licence} is not in the allowed list")
    return problems


def report_policy(problems):
    if problems:
        print('Licence policy FAILED:')
        for problem in problems:
            print('  ' + problem)
        print(f'Either fix the dependency or add a reviewed entry WITH a reason to {POLICY.relative_to(ROOT)}.')
        return 1
    print('Licence policy PASS: every linked Go module has a determined, allowed licence (or a reviewed allowlist entry).')
    return 0


# --- SPDX coverage ----------------------------------------------------------

HEADER = re.compile(r'SPDX-License-Identifier:\s*([^\n*]+?)\s*(?:\*/)?\s*$', re.MULTILINE)


def spdx_coverage(root=ROOT, directories=('scripts', 'kernel', 'node'), mapping=None):
    """Per-directory counts and the list of files with neither a header nor a mapping rule."""
    if mapping is None:
        mapping = json.loads(SPDX_MAP.read_text())
    rules = sorted(mapping['rules'], key=lambda rule: -len(rule['path']))
    summary, uncovered, licences = {}, [], {}
    for directory in directories:
        counts = {'files': 0, 'header': 0, 'mapped': 0, 'uncovered': 0}
        base = pathlib.Path(root) / directory
        for path in sorted(p for p in base.rglob('*') if p.is_file() and '__pycache__' not in p.parts):
            relative = path.relative_to(root).as_posix()
            counts['files'] += 1
            head = path.read_bytes()[:4096].decode('utf-8', errors='replace')
            match = HEADER.search(head)
            if match:
                counts['header'] += 1
                licences[match.group(1)] = licences.get(match.group(1), 0) + 1
                continue
            rule = next((rule for rule in rules if relative.startswith(rule['path'])), None)
            if rule:
                counts['mapped'] += 1
                licences[rule['licence']] = licences.get(rule['licence'], 0) + 1
            else:
                counts['uncovered'] += 1
                uncovered.append(relative)
        summary[directory] = counts
    return summary, uncovered, licences


def coverage_command(arguments):
    mapping = json.loads(SPDX_MAP.read_text())
    summary, uncovered, licences = spdx_coverage(mapping=mapping)
    problems = list(uncovered)
    # A rule is only as good as the licence text it points to.
    for rule in mapping['rules']:
        if not rule.get('basis'):
            problems.append(f"rule {rule['path']} has no basis")
        if not (ROOT / rule.get('text', '')).is_file():
            problems.append(f"rule {rule['path']}: licence text {rule.get('text')} is missing")
    if not arguments.quiet:
        for directory, counts in summary.items():
            print(f"{directory}/: {counts['files']} files, {counts['header']} with an SPDX header, "
                  f"{counts['mapped']} covered by LICENSES/spdx-map.json, {counts['uncovered']} uncovered")
        print('licences: ' + ', '.join(f'{name} x{count}' for name, count in sorted(licences.items())))
    if problems:
        print('SPDX coverage FAILED:')
        for problem in problems:
            print('  ' + problem)
        return 1
    print('SPDX coverage PASS: every file has a header or a mapping rule.')
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    gen = commands.add_parser('generate')
    gen.add_argument('--agent', required=True)
    gen.add_argument('--buildinfo')
    gen.add_argument('--node', default=str(ROOT / 'node'))
    gen.add_argument('--lock', default=str(LOCK))
    gen.add_argument('--rootfs-lock', default=str(ROOTFS_LOCK))
    gen.add_argument('--out')
    gen.add_argument('--notices')
    gen.add_argument('--licence-dir')
    gen.add_argument('--no-policy', action='store_true')
    pol = commands.add_parser('policy')
    pol.add_argument('sbom')
    cov = commands.add_parser('spdx-coverage')
    cov.add_argument('--quiet', action='store_true')
    arguments = parser.parse_args(argv)
    if arguments.command == 'generate':
        return generate(arguments)
    if arguments.command == 'policy':
        return report_policy(check_policy(json.loads(pathlib.Path(arguments.sbom).read_text()), json.loads(POLICY.read_text())))
    return coverage_command(arguments)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
