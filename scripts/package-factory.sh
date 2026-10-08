#!/bin/sh
# Offline developer packaging only. No mounts, chroot, flashing or device writes.
#
#   sudo ROOT_SPEC=LABEL=rootfs sh scripts/package-factory.sh CLEAN_ROOTFS_DIR REVIEWED_BOOT_IMG [Lite|Dev]
#
# Output: dist/factory/<agent version>-<variant>/
#   images/rootfs.img, images/boot.img   as before: raw ext4 rootfs and the reviewed boot image
#   rootfs-overlay/                      exactly the files layered onto the clean rootfs, for review:
#                                        agent, systemd units, default config, overlay scripts and,
#                                        ONLY when provided, /etc/nassimhub/ota-keys.json (public keys)
#   PACKAGE-MANIFEST.json                every file: size, SHA-256, mode; variant; update status
#   SHA256SUMS                           integrity, not authenticity
#   manifest.json, signatures/README.txt as before
#   BUILDINFO.json, sbom.spdx.json       how the agent was built and what is linked into it
#   LICENSE, LICENSES/, NOTICE.md, THIRD-PARTY-NOTICES.md, SOURCE.md, DEBIAN-PACKAGES.txt
#
# Variants (docs/RELEASING.md has the matrix; only what is implemented differs):
#   Lite  the agent, its units and the overlay. Default.
#   Dev   Lite plus the optional voice deployment sources from node/deploy/audio,
#         staged under /usr/share/nassimhub/voice-deploy and NOT installed or enabled.
#
# Environment:
#   ROOT_SPEC      required: the reviewed boot root= value (LABEL=rootfs or PARTUUID=...).
#   NSH_OTA_KEYS   optional: the PUBLIC release key file (`nsh-release keyring`). Installed as
#                  /etc/nassimhub/ota-keys.json root:root 0644. Without it the image trusts no
#                  publisher and the manifest says "updates disabled: no release keys".
#   NSH_SETUP_AP   optional: on|off, default off. `on` adds firmware/setup-ap-overlay/ (one polkit
#                  action and CAP_NET_BIND_SERVICE for the agent, scripts/imagepolicy.py), switches
#                  the packaged copy of agent.conf to provisioning = true / provisioning_ap = auto
#                  and requires dnsmasq (Debian package dnsmasq-base) in the input rootfs. The
#                  manifest then says "setup access point: enabled (not verified on hardware)".
#                  Off, it says "setup access point: not enabled" and none of this is in the image.
#   NSH_ROOTFS_MANIFEST
#                  optional: the ROOTFS-MANIFEST.json scripts/build-rootfs.sh wrote beside
#                  CLEAN_ROOTFS_DIR. The directory is re-hashed against it; then PACKAGE-MANIFEST.json
#                  says `rootfs: built from lock <sha256>` (or, for a --unlocked build, that it is not
#                  a release input), the boot image must be the one that rootfs was built for, and
#                  rootfs.img is made with fixed UUID, hash seed, times and (when the lock records the
#                  partition size) size, so that two runs give the same image. Without it the package
#                  says `rootfs: operator-supplied (unverified provenance)` and the image is made as
#                  before (sized from its contents, not repeatable byte for byte).
#   SOURCE_URL     optional: where the corresponding source of this exact revision is offered.
#   NSH_BUILD_DIR  where build-agent.sh wrote the agent (default <repo>/build).
#   NSH_DIST_DIR   output root (default <repo>/dist).
#
# A private key is never read by this script; a key file that is not a public
# keyring is refused before anything is staged.
set -eu
[ "$#" = 2 ] || [ "$#" = 3 ] || { echo 'usage: package-factory.sh CLEAN_ROOTFS_DIR REVIEWED_BOOT_IMG [Lite|Dev]' >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo 'root required to preserve rootfs ownership' >&2; exit 1; }
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# This script runs as root: leave no root-owned __pycache__ in the source tree.
export PYTHONDONTWRITEBYTECODE=1
root=$(realpath "$1")
boot=$(realpath "$2")
variant=${3:-Lite}
case "$variant" in Lite|Dev) ;; *) echo "unknown variant '$variant' (Lite or Dev)" >&2; exit 2;; esac
[ "$root" != / ] && [ -d "$root/etc" ] && [ -f "$boot" ] || exit 1
case "$root/" in /dev/*|/proc/*|/sys/*|/run/*) echo 'invalid input rootfs' >&2; exit 1;; esac
# The setup access point is opt-in and spelled out: an unset or mistyped value
# must not quietly become "on", nor a mistyped "on" quietly stay off.
setup_ap=${NSH_SETUP_AP:-off}
case "$setup_ap" in on|off) ;; *) echo "NSH_SETUP_AP must be on or off, not '$setup_ap'" >&2; exit 2;; esac
build=${NSH_BUILD_DIR:-$here/build}
[ -f "$build/nassimhub-agent" ] && [ -f "$build/BUILDINFO.json" ] || { echo 'build the agent first: sh scripts/build-agent.sh VERSION' >&2; exit 1; }
# The package is named after the version the agent itself reports. BUILDINFO.json
# must describe this exact binary, and a "dev" agent is refused: it never
# installs or starts an update, and it has no version a release could be
# compared against (the factory agent is the floor for every later update).
version=$(python3 - "$build" <<'PY'
import hashlib, json, pathlib, sys
build = pathlib.Path(sys.argv[1])
info = json.loads((build / 'BUILDINFO.json').read_text())
if info.get('sha256') != hashlib.sha256((build / 'nassimhub-agent').read_bytes()).hexdigest():
    sys.exit('BUILDINFO.json does not describe build/nassimhub-agent; rebuild with scripts/build-agent.sh')
if info.get('version') in (None, '', 'dev'):
    sys.exit('the agent was built without a VERSION ("dev"); a factory package needs a versioned agent')
print(info['version'])
PY
)
keys=${NSH_OTA_KEYS:-}
if [ -n "$keys" ]; then
	[ -f "$keys" ] || { echo "NSH_OTA_KEYS ($keys) is not a file" >&2; exit 1; }
	python3 "$here/scripts/privacy-check.py" --public-keyring "$keys"
fi
python3 "$here/scripts/audit-rootfs.py" "$root"
[ "$setup_ap" = off ] || python3 "$here/scripts/imagepolicy.py" require-dnsmasq "$root"
# Caller must inspect boot cmdline and supply the exact matching root= argument.
: "${ROOT_SPEC:?Set ROOT_SPEC to the reviewed boot root= value (LABEL=rootfs or matching PARTUUID)}"
case "$ROOT_SPEC" in LABEL=rootfs|PARTUUID=*) ;; *) echo 'unreviewed root spec' >&2; exit 1;; esac
python3 - "$boot" "$ROOT_SPEC" "$here/kernel/audio" <<'PY'
import pathlib, sys
sys.path.insert(0, sys.argv[3])
import importlib
m = importlib.import_module('replace-appended-dtb')
image = m.parse(pathlib.Path(sys.argv[1]).read_bytes())
m.split_kernel(image['kernel'])
cmd = (image['fields'][12].split(b'\0')[0] + image['fields'][14].split(b'\0')[0]).decode()
if ('root=' + sys.argv[2]) not in cmd.split():
    raise SystemExit('ROOT_SPEC does not match the boot image command line')
PY
out="${NSH_DIST_DIR:-$here/dist}/factory/$version-$variant"
[ ! -e "$out" ] || { echo "output already exists: $out; choose a clean build directory" >&2; exit 1; }
work=$(mktemp -d)
layer=$(mktemp -d)
meta=$(mktemp -d)
trap 'rm -rf "$work" "$layer" "$meta"' EXIT

# Where the input rootfs comes from. Only a manifest written by build-rootfs.sh
# for exactly this tree (it is re-hashed) and this boot image establishes
# anything; everything else is the operator's word and is recorded as such.
rootfs_manifest=${NSH_ROOTFS_MANIFEST:-}
[ -z "$rootfs_manifest" ] || [ -f "$rootfs_manifest" ] || { echo "NSH_ROOTFS_MANIFEST ($rootfs_manifest) is not a file" >&2; exit 1; }
python3 "$here/scripts/rootfs_tools.py" provenance --manifest "$rootfs_manifest" --root "$root" --boot-img "$boot" > "$meta/provenance.json"

# The layer: everything this project adds to the clean rootfs, assembled on its
# own so that it can be reviewed (it is copied into the package as
# rootfs-overlay/) and so that its ownership is root regardless of who checked
# the repository out.
cp -R "$here/firmware/overlay/." "$layer/"
mkdir -p "$layer/usr/bin" "$layer/etc/nassimhub" "$layer/etc/systemd/system/nassimhub-agent.service.d" "$layer/etc/systemd/system/multi-user.target.wants"
install -m 0755 "$build/nassimhub-agent" "$layer/usr/bin/nassimhub-agent"
install -m 0644 "$here/node/deploy/agent.conf" "$layer/etc/nassimhub/agent.conf"
install -m 0644 "$here/node/deploy/nassimhub-agent.service" "$layer/etc/systemd/system/nassimhub-agent.service"
install -m 0644 "$here/node/deploy/nassimhub-sim-number.service" "$layer/etc/systemd/system/nassimhub-sim-number.service"
install -m 0644 "$here/node/deploy/nassimhub-sim-number.timer" "$layer/etc/systemd/system/nassimhub-sim-number.timer"
mkdir -p "$layer/etc/systemd/system/timers.target.wants"
ln -s ../nassimhub-sim-number.timer "$layer/etc/systemd/system/timers.target.wants/nassimhub-sim-number.timer"
install -m 0644 "$here/node/deploy/nassimhub-agent-resources.conf" "$layer/etc/systemd/system/nassimhub-agent.service.d/resources.conf"
chmod 0755 "$layer/usr/local/libexec/"nassimhub-*
chmod 0600 "$layer/etc/NetworkManager/system-connections/nassimhub-usb.nmconnection"
for unit in nassimhub-agent nassimhub-usb nassimhub-device-firmware; do
 ln -s "../$unit.service" "$layer/etc/systemd/system/multi-user.target.wants/$unit.service"
done
if [ -n "$keys" ]; then
	# Release PUBLIC keys. Root-owned, world-readable, writable by nobody else:
	# the agent verifies updates against keys its own user cannot change
	# (node/agent/ota/keyring.go).
	install -m 0644 "$keys" "$layer/etc/nassimhub/ota-keys.json"
	# Releases are executed from the state partition, so with keys the mount
	# drops noexec. Without keys nothing there is ever executed and the base
	# unit's noexec stays (firmware/ota-overlay).
	cp -R "$here/firmware/ota-overlay/." "$layer/"
fi
if [ "$setup_ap" = on ]; then
	# The image-side prerequisites of the setup access point, and the switch
	# itself: without the two configuration values the agent never starts
	# it, and a manifest saying "enabled" would be false. Only this copy of
	# the configuration changes; node/deploy/agent.conf stays off.
	cp -R "$here/firmware/setup-ap-overlay/." "$layer/"
	python3 "$here/scripts/imagepolicy.py" enable-setup-ap "$layer/etc/nassimhub/agent.conf"
fi
if [ "$variant" = Dev ]; then
	# Sources only, not installed: voice needs a per-device acceptance, a
	# patched boot image and a holder binary this packager does not build.
	mkdir -p "$layer/usr/share/nassimhub/voice-deploy"
	for file in "$here"/node/deploy/audio/*; do
		install -m 0644 "$file" "$layer/usr/share/nassimhub/voice-deploy/"
	done
fi
find "$layer" -type d -exec chmod 0755 {} +
# A ZIP or Windows checkout does not preserve Unix modes. Set image policy
# explicitly, including optional overlays, rather than inheriting host ACLs.
find "$layer" -type f -exec chmod 0644 {} +
chmod 0755 "$layer/usr/bin/nassimhub-agent" "$layer/usr/local/libexec/"nassimhub-*
chmod 0600 "$layer/etc/NetworkManager/system-connections/nassimhub-usb.nmconnection"
chown -R -h root:root "$layer"

cp -a "$root/." "$work/"
cp -a "$layer/." "$work/"
mkdir -p "$work/var/lib/nassimhub"
# The configuration directory must not be writable by the service user.
chown root:root "$work/etc/nassimhub"
chmod 0755 "$work/etc/nassimhub"
printf '%s\n' "${ROOT_SPEC} / ext4 defaults,noatime,errors=remount-ro 0 1" 'tmpfs /tmp tmpfs defaults,nosuid,nodev,mode=1777 0 0' > "$work/etc/fstab"
: > "$work/etc/machine-id"
if [ "$setup_ap" = on ]; then
	python3 "$here/scripts/audit-rootfs.py" --setup-ap "$work"
else
	python3 "$here/scripts/audit-rootfs.py" "$work"
fi

mkdir -p "$out/images" "$out/signatures" "$out/LICENSES"
# image_field NAME: a value of the rootfs manifest, empty when there is none.
image_field() { python3 -c 'import json,sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value.get(key) if isinstance(value, dict) else None
print("" if value is None else value)' "$meta/provenance.json" "$1"; }
image_epoch=$(image_field source_date_epoch)
image_uuid=$(image_field image.uuid)
image_seed=$(image_field image.hash_seed)
image_mib=$(image_field image.size_mib)
if [ -n "$image_epoch" ] && [ -n "$image_uuid" ] && [ -n "$image_seed" ]; then
	# A rootfs from build-rootfs.sh: nothing in the image may depend on when or
	# where it was made. Modification times are clamped in the staged tree;
	# mke2fs takes its own timestamps from E2FSPROGS_FAKE_TIME, and the change
	# and access times it copies from the staging files are set afterwards.
	python3 "$here/scripts/rootfs_tools.py" clamp-mtime "$work" "$image_epoch"
	if [ -n "$image_mib" ]; then
		size_mb=$image_mib
		image_size_from='the rootfs partition size recorded in the rootfs lock'
	else
		# No partition size is known (an --unlocked build): sized from the
		# contents. Repeatable for the same tree, but NOT the partition's size.
		size_mb=$(( $(du -sm --apparent-size "$work" | cut -f1) + 256 ))
		image_size_from='the contents plus 256 MiB (no partition size recorded: not sized for the device)'
	fi
	truncate -s "${size_mb}M" "$out/images/rootfs.img"
	E2FSPROGS_FAKE_TIME=$image_epoch mke2fs -q -t ext4 -L rootfs -U "$image_uuid" \
		-E "hash_seed=$image_seed,lazy_itable_init=0,lazy_journal_init=0" -d "$work" "$out/images/rootfs.img" || {
		echo "the staged tree does not fit a ${size_mb} MiB image ($image_size_from)" >&2; exit 1; }
	python3 "$here/scripts/rootfs_tools.py" image-times "$work" "$image_epoch" > "$meta/image-times"
	E2FSPROGS_FAKE_TIME=$image_epoch debugfs -w -f "$meta/image-times" "$out/images/rootfs.img" > "$meta/debugfs.log" 2>&1
	if grep -v '^debugfs' "$meta/debugfs.log" | grep -q .; then
		grep -v '^debugfs' "$meta/debugfs.log" | head -n 5 >&2
		echo 'the inode times of rootfs.img could not be fixed' >&2
		exit 1
	fi
	image_fixed=yes
else
	size_mb=$(( $(du -sm "$work" | cut -f1) + 256 ))
	image_size_from='the contents plus 256 MiB'
	truncate -s "${size_mb}M" "$out/images/rootfs.img"
	mke2fs -q -t ext4 -L rootfs -d "$work" "$out/images/rootfs.img"
	image_fixed=no
fi
e2fsck -fn "$out/images/rootfs.img"
cp "$boot" "$out/images/boot.img"
cp -a "$layer" "$out/rootfs-overlay"
printf '%s\n' 'No release signature is provided by this developer build. SHA256 is integrity, not authenticity. Release publisher must sign manifest separately; do not put signing private keys into the image.' > "$out/signatures/README.txt"

# Licence texts, notices, SBOM. sbom.py also enforces the licence policy: a
# linked module without a determined, allowed licence stops the package.
cp "$here/LICENSE" "$out/LICENSE"
cp "$here/NOTICE.md" "$out/NOTICE.md"
cp "$here/LICENSES/GPL-2.0-only.txt" "$here/LICENSES/README.md" "$here/LICENSES/spdx-map.json" "$out/LICENSES/"
cp "$build/BUILDINFO.json" "$out/BUILDINFO.json"
# Made by build-agent.sh for exactly this binary (that step has the toolchain;
# this one runs as root and needs none). The licence policy is re-checked here
# so a package cannot be made from an SBOM that was produced with it disabled.
[ -f "$build/sbom/sbom.spdx.json" ] || { echo 'no build/sbom/: rebuild the agent with scripts/build-agent.sh' >&2; exit 1; }
python3 - "$build" <<'PY'
import json, pathlib, sys
build = pathlib.Path(sys.argv[1])
info = json.loads((build / 'BUILDINFO.json').read_text())
document = json.loads((build / 'sbom/sbom.spdx.json').read_text())
agent = next(p for p in document['packages'] if p['SPDXID'] == 'SPDXRef-Agent')
if agent['checksums'][0]['checksumValue'] != info['sha256']:
    sys.exit('build/sbom/sbom.spdx.json describes another agent binary; rebuild with scripts/build-agent.sh')
PY
python3 "$here/scripts/sbom.py" policy "$build/sbom/sbom.spdx.json"
cp "$build/sbom/sbom.spdx.json" "$out/sbom.spdx.json"
cp "$build/sbom/THIRD-PARTY-NOTICES.md" "$out/THIRD-PARTY-NOTICES.md"
[ ! -d "$build/sbom/third-party" ] || cp -R "$build/sbom/third-party" "$out/LICENSES/third-party"

commit=unknown
dirty=unknown
if command -v git >/dev/null 2>&1 && git -C "$here" rev-parse --git-dir >/dev/null 2>&1; then
	commit=$(git -C "$here" rev-parse HEAD 2>/dev/null || echo unknown)
	if [ -z "$(git -C "$here" status --porcelain 2>/dev/null)" ]; then dirty=false; else dirty=true; fi
fi
python3 - "$out" "$ROOT_SPEC" "$version" "$variant" "$here" "$root" "$commit" "$dirty" "${SOURCE_URL:-}" "$setup_ap" \
	"$meta/provenance.json" "$image_fixed" "$size_mb" "$image_size_from" <<'PY'
import hashlib, json, os, pathlib, stat, sys
out, root_spec, version, variant, here, rootfs, commit, dirty, source_url, setup_ap = sys.argv[1:11]
provenance = json.loads(pathlib.Path(sys.argv[11]).read_text())
image_fixed, image_mib, image_size_from = sys.argv[12] == 'yes', int(sys.argv[13]), sys.argv[14]
out = pathlib.Path(out); here = pathlib.Path(here)
sys.path.insert(0, str(here / 'scripts'))
import imagepolicy
lock = json.loads((here / 'firmware/upstream.lock.json').read_text())
info = json.loads((out / 'BUILDINFO.json').read_text())

def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        while b := f.read(1024 * 1024): digest.update(b)
    return digest.hexdigest()

# Debian packages of the input rootfs, for the reader who has to find their
# source. Read from the dpkg database; nothing is executed.
status = pathlib.Path(rootfs) / 'var/lib/dpkg/status'
lines = []
if status.is_file():
    for block in status.read_text(encoding='utf-8', errors='replace').split('\n\n'):
        fields = dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
        if 'Package' in fields and 'installed' in fields.get('Status', ''):
            lines.append(f"{fields['Package']}\t{fields.get('Version', '')}\t{fields.get('Architecture', '')}\t{fields.get('Source', fields['Package'])}")
header = '# Debian packages installed in the input rootfs (package, version, architecture, source package).\n'
if lines:
    (out / 'DEBIAN-PACKAGES.txt').write_text(header + '\n'.join(sorted(lines)) + '\n')
else:
    (out / 'DEBIAN-PACKAGES.txt').write_text(header + '# not available: the input rootfs has no readable var/lib/dpkg/status\n')

keyring = out / 'rootfs-overlay/etc/nassimhub/ota-keys.json'
if keyring.is_file():
    keys = json.loads(keyring.read_text())
    updates = {'release_keys': True, 'status': 'release keys installed',
               'ed25519_keys': len(keys.get('ed25519', {})), 'ml_dsa_keys': len(keys.get('ml_dsa', {})),
               'key_file': '/etc/nassimhub/ota-keys.json', 'state_mount_exec': True}
else:
    updates = {'release_keys': False, 'status': 'updates disabled: no release keys',
               'ed25519_keys': 0, 'ml_dsa_keys': 0, 'key_file': None, 'state_mount_exec': False}

# The setup access point, stated from what is in the overlay and not from the
# switch alone: the two must agree or the package is not made.
overlay = out / 'rootfs-overlay'
fragment = [relative for relative in imagepolicy.SETUP_AP_FILES if (overlay / relative).is_file()]
configured = imagepolicy.conf_enables_setup_ap((overlay / imagepolicy.AGENT_CONF).read_text())
complete = len(fragment) == len(imagepolicy.SETUP_AP_FILES) and configured
if (setup_ap == 'on' and not complete) or (setup_ap == 'off' and (fragment or configured)):
    sys.exit('the overlay does not match NSH_SETUP_AP=' + setup_ap)
if setup_ap == 'on':
    access_point = {
        'enabled': True, 'status': imagepolicy.STATUS_ON, 'verified_on_hardware': False,
        'files': ['/' + relative for relative in imagepolicy.SETUP_AP_FILES],
        'polkit_actions_added': sorted(action for actions in imagepolicy.SETUP_AP_POLKIT.values() for action in actions),
        'capabilities_added': sorted(imagepolicy.SETUP_AP_CAPABILITIES),
        'configuration': {'provisioning': 'true', 'provisioning_ap': 'auto'},
        'required_packages': imagepolicy.required_packages(str(here)),
        'passphrase': 'generated on the device at first use (/var/lib/nassimhub/setup-ap-passphrase); none is in this package',
    }
else:
    access_point = {'enabled': False, 'status': imagepolicy.STATUS_OFF, 'verified_on_hardware': False,
                    'files': [], 'polkit_actions_added': [], 'capabilities_added': [],
                    'configuration': {'provisioning_ap': 'off'}, 'required_packages': []}

# AGPL-3.0 section 6: where the corresponding source is. Stated only as far as
# it is known at packaging time; an unset SOURCE_URL is said to be unset.
source = {'repository_commit': commit, 'working_tree_modified': {'true': True, 'false': False}.get(dirty, 'unknown'),
          'node_tree_sha256': info.get('node_tree_sha256'), 'url': source_url or None}
text = f'''# Corresponding source

This package contains object code covered by the GNU Affero General Public
License version 3 (`LICENSE`): `nassimhub-agent` and the firmware integration
files under `rootfs-overlay/`. Section 6 of that licence requires the
corresponding source to be available to whoever receives this package.

## What the source is

- The NasSimHub UFI003 firmware source tree (directories `node/`, `firmware/`,
  `scripts/`, `kernel/`, `docs/`).
- Revision: git commit `{commit}`, working tree modified at packaging time: `{dirty}`.
- Content hash of `node/` the agent was built from: `{info.get('node_tree_sha256')}`
  (recorded in `BUILDINFO.json`; recomputed by `scripts/build-agent.sh`).
- Agent version `{version}`, built with `{info.get('go_version')}`; rebuild with
  `sh scripts/build-agent.sh {version}` and compare `SHA256SUMS`.

## Where to get it

'''
if source_url:
    text += f'The packager states that the source of this exact revision is offered at:\n\n    {source_url}\n'
else:
    text += ('No source location was supplied when this package was built (`SOURCE_URL` was not set).\n'
             'Whoever conveys this package must accompany it with the complete corresponding source of the\n'
             'revision above, or meet AGPL-3.0 section 6 in another way it permits. This file is a pointer,\n'
             'not the source itself.\n')
if dirty != 'false':
    text += ('\nThe working tree was modified or its state was unknown when this package was built, so the commit\n'
             'alone does not identify the source: the modified files are part of the corresponding source.\n')
text += f'''
## Components this repository does not build

- Kernel and boot image: `images/boot.img` was supplied by the packager. The pinned upstream is
  {lock.get('kernel_repository')} at commit `{lock.get('kernel_commit')}` ({lock.get('kernel_version')});
  the patches this project adds are in `kernel/audio/` (GPL-2.0-only). Whoever distributes the boot
  image is responsible for the kernel's GPL-2.0 source obligations.
- Debian base system ({lock.get('distro')}): packages are listed in `DEBIAN-PACKAGES.txt` when the
  package database could be read; that list is the reference for their sources. Root filesystem
  of this package: {provenance['statement']} (`PACKAGE-MANIFEST.json`, `rootfs`). Only a rootfs
  "built from lock" has its package versions pinned by `firmware/rootfs.lock.json`.
- Go modules linked into the agent: `THIRD-PARTY-NOTICES.md`, `sbom.spdx.json`, `LICENSES/third-party/`.
- No modem firmware, NV or calibration data is part of this package (`NOTICE.md`).
'''
(out / 'SOURCE.md').write_text(text)

images = []
for name in ('boot.img', 'rootfs.img'):
    p = out / 'images' / name
    images.append({'path': 'images/' + name, 'sha256': sha256(p), 'size': p.stat().st_size})
protected = ['modemst1', 'modemst2', 'fsg', 'persist', 'fsc', 'cdt', 'sbl1', 'aboot', 'tz', 'rpm', 'hyp', 'sec']
legacy = {'schema': 1, 'channel': 'developer', 'board': lock['board'], 'distro': lock['distro'], 'kernel': lock['kernel_version'],
          'root_spec': root_spec, 'image_format': 'raw-ext4', 'signed': False, 'images': images,
          'protected_partitions': protected, 'version': version, 'variant': variant}
(out / 'manifest.json').write_text(json.dumps(legacy, indent=2) + '\n')

common = ['nassimhub-agent (factory agent, /usr/bin, never modified by updates)',
          'nassimhub-agent.service + resources drop-in + persistent-state drop-in',
          'default configuration /etc/nassimhub/agent.conf',
          'persistent state mount (NSHSTATE) and state check; first-boot ownership of /var/lib/nassimhub',
          'USB NCM gadget with development-only USB IDs',
          'NetworkManager configuration and polkit rules for the nassimhub user']
if setup_ap == 'on':
    common.append('Wi-Fi setup access point enabled (NSH_SETUP_AP=on): polkit wifi.share.protected and CAP_NET_BIND_SERVICE '
                  'for the agent, provisioning_ap = auto; NOT verified on hardware')
features = {'Lite': common,
            'Dev': common + ['voice deployment sources staged in /usr/share/nassimhub/voice-deploy (not installed, not enabled)']}
# Enabled is not the same as working: with the switch on, say what is missing.
access_point_gap = ('Wi-Fi setup access point: enabled in this package but never verified on hardware; no screen shows '
                    'its passphrase (it is read from /var/lib/nassimhub/setup-ap-passphrase over the USB maintenance link)'
                    if setup_ap == 'on' else
                    'Wi-Fi setup access point in this package: not enabled (opt-in with NSH_SETUP_AP=on; never verified on hardware)')
not_implemented = [
    'voice/VoLTE audio enabled in an image: per-device acceptance only (node/deploy/audio/install-voice.sh)',
    'hold-cs-voice binary: source only, needs an aarch64 C compiler',
    'audio DTB or q6 kernel modules chosen by variant: the boot image is the packager\'s input',
    'SSH server, serial console or debug tooling chosen by variant: the packager installs no Debian packages',
    'size-reduced Lite root filesystem: both variants use the same input rootfs',
    access_point_gap,
    'product USB VID/PID',
    'signature over the factory package: SHA256SUMS is integrity only',
    'system-image OTA (kernel, rootfs, modem): only the agent executable is updatable',
]
files = []
for directory, names, filenames in os.walk(out):
    names.sort()
    for name in sorted(filenames) + [n for n in names if os.path.islink(os.path.join(directory, n))]:
        path = pathlib.Path(directory) / name
        relative = path.relative_to(out).as_posix()
        if relative in ('PACKAGE-MANIFEST.json', 'SHA256SUMS'):
            continue
        st = os.lstat(path)
        entry = {'path': relative, 'mode': format(st.st_mode & 0o7777, '04o')}
        if stat.S_ISLNK(st.st_mode):
            entry.update(type='symlink', target=os.readlink(path))
        else:
            entry.update(type='file', size=st.st_size, sha256=sha256(path))
        files.append(entry)
files.sort(key=lambda entry: entry['path'])
manifest = {
    'schema': 1, 'package': 'nassimhub-ufi003-factory', 'version': version, 'variant': variant, 'channel': 'developer',
    'board': lock['board'], 'distro': lock['distro'], 'kernel': lock['kernel_version'], 'architecture': lock['architecture'],
    'root_spec': root_spec, 'image_format': 'raw-ext4', 'signed': False,
    'agent': {key: info.get(key) for key in ('version', 'sha256', 'size', 'go_version', 'goos', 'goarch', 'go_mod', 'ml_dsa_available', 'node_tree_sha256')},
    'updates': updates, 'setup_access_point': access_point,
    'features': features[variant], 'not_implemented': not_implemented,
    'generic': 'No device identity, pairing state, administrator password, Wi-Fi credential, SSH key, device certificate, '
               'modem NV/EFS/calibration, IMEI/ICCID/phone number, log or SMS is included; all of it is created on the device '
               '(docs/FIRST_BOOT.md). Enforced by scripts/audit-rootfs.py and scripts/privacy-check.py --package.',
    # Exactly one of three wordings (scripts/rootfs_tools.py, provenance):
    # "built from lock <sha256>", "built by build-rootfs.sh WITHOUT a resolved
    # lock ...", or "operator-supplied (unverified provenance)".
    'rootfs': dict(provenance, image={
        'path': 'images/rootfs.img', 'size_mib': image_mib, 'size_from': image_size_from,
        'fixed_uuid_seed_and_times': image_fixed,
        'statement': ('made with fixed UUID, hash seed and timestamps: the same inputs and e2fsprogs version give the same bytes'
                      if image_fixed else 'not repeatable byte for byte (filesystem UUID and timestamps are those of this run)')}),
    'rootfs_post_steps': ['etc/fstab written from ROOT_SPEC', 'etc/machine-id emptied', 'var/lib/nassimhub created empty (mount point)'],
    'source': source, 'protected_partitions': protected, 'not_verified_on_hardware': True, 'files': files,
}
(out / 'PACKAGE-MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
with open(out / 'SHA256SUMS', 'w') as sums:
    for entry in files:
        if entry['type'] == 'file':
            sums.write(f"{entry['sha256']}  {entry['path']}\n")
    sums.write(f"{sha256(out / 'PACKAGE-MANIFEST.json')}  PACKAGE-MANIFEST.json\n")
PY
# Last gate: the finished package must be generic. A failure leaves the
# directory in place for inspection, marked so it cannot be mistaken for a
# deliverable.
if ! python3 "$here/scripts/privacy-check.py" --package "$out"; then
	mv "$out" "$out.REJECTED"
	echo "package rejected and moved to $out.REJECTED" >&2
	exit 1
fi
if [ -n "$keys" ]; then echo 'updates: release public keys installed'; else echo 'updates disabled: no release keys'; fi
if [ "$setup_ap" = on ]; then echo 'setup access point: enabled (not verified on hardware)'; else echo 'setup access point: not enabled'; fi
echo "rootfs: $(image_field statement)"
echo "Developer package created: $out (variant $variant; not flashed, not signed, requires board-specific review; not verified on hardware)"
