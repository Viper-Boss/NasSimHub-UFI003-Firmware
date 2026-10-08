#!/bin/sh
# End-to-end test of scripts/package-factory.sh on SYNTHETIC inputs.
#
# The "rootfs" is a handful of files that satisfy the clean-rootfs audit and
# the "boot image" is a few hundred bytes with a valid Android v0 header: this
# exercises the packager, its manifest and the generic-package gate. It does
# not produce something that boots, and nothing is flashed or verified on
# hardware.
#
# Needs root (file ownership inside the image) and e2fsprogs; without either it
# says SKIPPED and exits 0 so that an unprivileged source check still runs.
set -eu
export PYTHONDONTWRITEBYTECODE=1  # this test runs as root: no root-owned __pycache__ in the source tree
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${NSH_TEST_VERSION:-9.9.1}
fail() { echo "test-package-factory FAILED: $*" >&2; exit 1; }
if [ "$(id -u)" != 0 ] || ! command -v mke2fs >/dev/null 2>&1 || ! command -v debugfs >/dev/null 2>&1; then
	echo 'package-factory test SKIPPED: needs root and e2fsprogs (mke2fs, debugfs)'
	exit 0
fi

outside_repositories() {
	for base in "${NSH_TEST_TMPDIR:-}" "${TMPDIR:-/tmp}" /var/tmp /dev/shm; do
		[ -n "$base" ] && [ -d "$base" ] && [ -w "$base" ] || continue
		probe=$(CDPATH= cd -- "$base" && pwd -P)
		inside=no
		while :; do
			for marker in .git .hg .svn; do [ ! -e "$probe/$marker" ] || inside=yes; done
			[ "$probe" != / ] || break
			probe=$(dirname "$probe")
		done
		[ "$inside" = yes ] || { mktemp -d "$base/nsh-factory-test.XXXXXX"; return 0; }
	done
	return 1
}
work=$(outside_repositories) || fail 'no temporary directory outside a repository; set NSH_TEST_TMPDIR'
trap 'rm -rf "$work"' EXIT

build=${NSH_TEST_BUILD_DIR:-}
if [ -z "$build" ] || [ ! -f "$build/sbom/sbom.spdx.json" ]; then
	build=$work/build
	NSH_BUILD_DIR="$build" sh "$here/scripts/build-agent.sh" "$version" >/dev/null
fi
export NSH_BUILD_DIR="$build" NSH_DIST_DIR="$work/dist" ROOT_SPEC=LABEL=rootfs

# Synthetic clean rootfs and boot image.
root=$work/rootfs
mkdir -p "$root/etc" "$root/usr/bin" "$root/var/lib/dpkg" "$root/var/log"
printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nVERSION_ID="13"\n' > "$root/etc/os-release"
printf 'root:x:0:0:root:/root:/bin/sh\nnassimhub:x:999:999::/nonexistent:/usr/sbin/nologin\n' > "$root/etc/passwd"
printf 'root:!:0:0:99999:7:::\nnassimhub:!:0:0:99999:7:::\n' > "$root/etc/shadow"
chmod 0640 "$root/etc/shadow"
printf 'Package: synthetic-base\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.0-1\n\nPackage: synthetic-removed\nStatus: deinstall ok config-files\nArchitecture: arm64\nVersion: 0.1\n' > "$root/var/lib/dpkg/status"
python3 - "$here/kernel/audio" "$work/boot.img" <<'PY'
import importlib, pathlib, struct, sys
sys.path.insert(0, sys.argv[1])
boot = importlib.import_module('replace-appended-dtb')
dtb = boot.FDT_MAGIC + struct.pack('>I', 40) + b'd' * 32
fields = [boot.MAGIC, 0, 0x80080000, 8, 0x81000000, 0, 0, 0x80000100, 2048, 0, 0, b'UFI003', b'root=LABEL=rootfs', b'', b'']
image = boot.build({'fields': fields, 'page': 2048, 'ramdisk': b'ramdisk!', 'second': b''}, b'\x1f\x8bkernel' + dtb)
pathlib.Path(sys.argv[2]).write_bytes(image)
PY
factory() { sh "$here/scripts/package-factory.sh" "$root" "$work/boot.img" "$@"; }
image_stat() { debugfs -R "stat $2" "$1" 2>/dev/null; }
image_cat() { debugfs -R "cat $2" "$1" 2>/dev/null; }

echo '== 1. Lite, no release keys'
factory Lite > "$work/lite.log" 2>&1 || { cat "$work/lite.log"; fail 'Lite packaging failed'; }
lite=$work/dist/factory/$version-Lite
grep -q 'updates disabled: no release keys' "$work/lite.log" || fail 'the missing keys were not announced'
grep -q '^setup access point: not enabled$' "$work/lite.log" || fail 'the default state of the setup access point was not announced'
grep -q '^rootfs: operator-supplied (unverified provenance)$' "$work/lite.log" || fail 'a rootfs without a build manifest was not announced as operator-supplied'
python3 -c 'import json,sys; rootfs = json.load(open(sys.argv[1]))["rootfs"]; assert rootfs["statement"] == "operator-supplied (unverified provenance)" and rootfs["built_from_lock"] is False and rootfs["image"]["fixed_uuid_seed_and_times"] is False, rootfs' "$work/dist/factory/$version-Lite/PACKAGE-MANIFEST.json" || fail 'PACKAGE-MANIFEST.json does not record the rootfs as operator-supplied'
python3 - "$lite" <<'PY' || exit 1
import json, pathlib, sys
package = pathlib.Path(sys.argv[1])
manifest = json.loads((package / 'PACKAGE-MANIFEST.json').read_text())
paths = {entry['path']: entry for entry in manifest['files']}
assert manifest['variant'] == 'Lite' and manifest['updates'] == {'release_keys': False, 'status': 'updates disabled: no release keys', 'ed25519_keys': 0, 'ml_dsa_keys': 0, 'key_file': None, 'state_mount_exec': False}, manifest['updates']
for required in ('images/rootfs.img', 'images/boot.img', 'rootfs-overlay/usr/bin/nassimhub-agent', 'rootfs-overlay/etc/systemd/system/nassimhub-agent.service',
                 'rootfs-overlay/etc/nassimhub/agent.conf', 'LICENSE', 'LICENSES/GPL-2.0-only.txt', 'NOTICE.md', 'THIRD-PARTY-NOTICES.md', 'SOURCE.md',
                 'sbom.spdx.json', 'BUILDINFO.json', 'DEBIAN-PACKAGES.txt', 'manifest.json', 'signatures/README.txt'):
    assert required in paths, required
assert not any('ota-keys' in path or 'voice-deploy' in path or 'mount.d' in path for path in paths), 'Lite without keys carries keys, the exec drop-in or voice files'
access_point = manifest['setup_access_point']
assert access_point['enabled'] is False and access_point['status'] == 'setup access point: not enabled' and access_point['files'] == [], access_point
assert not any('setup-ap' in path for path in paths), 'the setup access point fragment is in a package that did not ask for it'
assert any('not enabled (opt-in with NSH_SETUP_AP=on' in item for item in manifest['not_implemented'])
assert all(set(entry) >= {'path', 'mode', 'type'} and (entry['type'] == 'symlink' or len(entry['sha256']) == 64 and 'size' in entry) for entry in manifest['files'])
assert paths['rootfs-overlay/usr/bin/nassimhub-agent']['mode'] == '0755' and paths['rootfs-overlay/usr/bin/nassimhub-agent']['sha256'] == manifest['agent']['sha256']
assert 'synthetic-base\t1.0-1' in (package / 'DEBIAN-PACKAGES.txt').read_text() and 'synthetic-removed' not in (package / 'DEBIAN-PACKAGES.txt').read_text()
assert 'SOURCE_URL` was not set' in (package / 'SOURCE.md').read_text()
PY
(cd "$lite" && sha256sum -c SHA256SUMS >/dev/null) || fail 'SHA256SUMS does not check'
python3 "$here/scripts/privacy-check.py" --package "$lite" >/dev/null || fail 'the clean Lite package failed the generic check'
image_stat "$lite/images/rootfs.img" /usr/bin/nassimhub-agent | grep -q 'Mode:  0755' || fail 'the agent is not 0755 in the image'
image_stat "$lite/images/rootfs.img" /etc/nassimhub/ota-keys.json | grep -q 'Type: regular' && fail 'a key file is in the Lite image'
image_stat "$lite/images/rootfs.img" /etc/machine-id | grep -q 'Size: 0' || fail 'machine-id is not empty in the image'
image_cat "$lite/images/rootfs.img" /etc/nassimhub/agent.conf | grep -q '^provisioning_ap = off$' || fail 'the default image does not keep provisioning_ap = off'
image_stat "$lite/images/rootfs.img" /etc/polkit-1/rules.d/48-nassimhub-setup-ap.rules | grep -q 'Type: regular' && fail 'the setup access point polkit rule is in the default image'
image_stat "$lite/images/rootfs.img" /etc/systemd/system/nassimhub-agent.service.d/setup-ap.conf | grep -q 'Type: regular' && fail 'the setup access point drop-in is in the default image'

echo '== 2. Dev, with a PUBLIC release key file'
tool=$work/nsh-release
# shellcheck disable=SC2086 # NSH_GO_FLAGS is a deliberately word-split flag list.
(cd "$here/node/agent" && unset GOOS GOARCH && CGO_ENABLED=0 GOWORK=off GOFLAGS= "${GO:-go}" build ${NSH_GO_FLAGS:-} -trimpath -buildvcs=false -o "$tool" ./cmd/nsh-release)
"$tool" keygen -dir "$work/release-keys" -key-id test-2026 -pq ml-dsa-87 >/dev/null 2>&1 || {
	rm -rf "$work/release-keys"; "$tool" keygen -dir "$work/release-keys" -key-id test-2026 -pq none >/dev/null; }
"$tool" keyring -dir "$work/release-keys" -out "$work/ota-keys.json" >/dev/null
NSH_OTA_KEYS="$work/ota-keys.json" SOURCE_URL=https://source.example.invalid/nassimhub-firmware factory Dev > "$work/dev.log" 2>&1 || { cat "$work/dev.log"; fail 'Dev packaging failed'; }
dev=$work/dist/factory/$version-Dev
python3 - "$dev" <<'PY' || exit 1
import json, pathlib, sys
package = pathlib.Path(sys.argv[1])
manifest = json.loads((package / 'PACKAGE-MANIFEST.json').read_text())
paths = {entry['path']: entry for entry in manifest['files']}
assert manifest['variant'] == 'Dev' and manifest['updates']['release_keys'] is True and manifest['updates']['ed25519_keys'] == 1, manifest['updates']
assert paths['rootfs-overlay/etc/nassimhub/ota-keys.json']['mode'] == '0644'
assert 'rootfs-overlay/etc/systemd/system/var-lib-nassimhub.mount.d/10-ota-exec.conf' in paths
assert 'rootfs-overlay/usr/share/nassimhub/voice-deploy/install-voice.sh' in paths
assert not any(path.endswith(('.enabled', '.verified')) for path in paths)
assert 'https://source.example.invalid/nassimhub-firmware' in (package / 'SOURCE.md').read_text()
PY
(cd "$dev" && sha256sum -c SHA256SUMS >/dev/null) || fail 'SHA256SUMS does not check'
python3 "$here/scripts/privacy-check.py" --package "$dev" >/dev/null || fail 'the clean Dev package failed the generic check'
image_stat "$dev/images/rootfs.img" /etc/nassimhub/ota-keys.json > "$work/keystat"
grep -q 'Mode:  0644' "$work/keystat" && grep -q 'User:     0   Group:     0' "$work/keystat" || fail 'ota-keys.json is not root:root 0644 in the image'
image_stat "$dev/images/rootfs.img" /etc/nassimhub | grep -q 'Mode:  0755' || fail '/etc/nassimhub is not 0755 in the image'
if grep -rl '"seed"' "$dev" >/dev/null 2>&1; then fail 'private key material in the package'; fi

echo '== 3. a private key file is refused as the release key file'
rm -rf "$dev"
if NSH_OTA_KEYS="$work/release-keys/test-2026.ed25519.key" factory Dev > "$work/private.log" 2>&1; then fail 'a private key file was packaged'; fi
grep -q 'not a PUBLIC release keyring' "$work/private.log" || fail 'wrong refusal for a private key file'
[ ! -e "$dev" ] || fail 'output was written although the key file was refused'

echo '== 4. a rootfs carrying a personal authorized_keys is refused'
mkdir -p "$root/root/.ssh"
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticsyntheticsyntheticsynthetic test@example.invalid\n' > "$root/root/.ssh/authorized_keys"
if factory Lite > "$work/dirty.log" 2>&1; then fail 'a rootfs with authorized_keys was packaged'; fi
grep -q 'Clean rootfs audit FAILED' "$work/dirty.log" || fail 'wrong refusal for a dirty rootfs'
rm -rf "$root/root"

echo '== 5. something added to a finished package is caught'
mkdir -p "$lite/images"
printf 'synthetic' > "$lite/images/modemst1.bin"
if python3 "$here/scripts/privacy-check.py" --package "$lite" > "$work/added.log"; then fail 'a calibration image added to the package was not caught'; fi
grep -q 'modem-calibration: images/modemst1.bin' "$work/added.log" || fail 'the added calibration image was not named'

echo '== 6. setup access point: opt-in only, all or nothing'
export NSH_DIST_DIR="$work/dist-ap"
ap=$NSH_DIST_DIR/factory/$version-Lite
if NSH_SETUP_AP=yes factory Lite > "$work/ap-typo.log" 2>&1; then fail 'a mistyped NSH_SETUP_AP was accepted'; fi
grep -q 'NSH_SETUP_AP must be on or off' "$work/ap-typo.log" || fail 'wrong refusal for a mistyped NSH_SETUP_AP'
# The synthetic rootfs has no dnsmasq: NetworkManager could not serve the phone an address.
if NSH_SETUP_AP=on factory Lite > "$work/ap-nodnsmasq.log" 2>&1; then fail 'the setup access point was packaged without dnsmasq in the rootfs'; fi
grep -q 'dnsmasq-base' "$work/ap-nodnsmasq.log" || fail 'the missing dnsmasq was not named'
[ ! -e "$ap" ] || fail 'output was written although dnsmasq is missing'
mkdir -p "$root/usr/sbin"
printf 'synthetic stand-in for the dnsmasq binary\n' > "$root/usr/sbin/dnsmasq"
chmod 0755 "$root/usr/sbin/dnsmasq"
NSH_SETUP_AP=on factory Lite > "$work/ap.log" 2>&1 || { cat "$work/ap.log"; fail 'packaging with NSH_SETUP_AP=on failed'; }
grep -q '^setup access point: enabled (not verified on hardware)$' "$work/ap.log" || fail 'the enabled setup access point was not announced'
python3 - "$ap" <<'PY' || exit 1
import json, pathlib, sys
package = pathlib.Path(sys.argv[1])
manifest = json.loads((package / 'PACKAGE-MANIFEST.json').read_text())
paths = {entry['path']: entry for entry in manifest['files']}
access_point = manifest['setup_access_point']
assert access_point['enabled'] is True and access_point['status'] == 'setup access point: enabled (not verified on hardware)', access_point
assert access_point['verified_on_hardware'] is False
assert access_point['polkit_actions_added'] == ['org.freedesktop.NetworkManager.wifi.share.protected'], access_point
assert access_point['capabilities_added'] == ['CAP_NET_BIND_SERVICE'] and access_point['required_packages'] == ['dnsmasq-base'], access_point
for relative in ('etc/polkit-1/rules.d/48-nassimhub-setup-ap.rules', 'etc/systemd/system/nassimhub-agent.service.d/setup-ap.conf'):
    assert paths['rootfs-overlay/' + relative]['mode'] == '0644', relative
    assert '/' + relative in access_point['files']
conf = (package / 'rootfs-overlay/etc/nassimhub/agent.conf').read_text()
assert '\nprovisioning = true\n' in conf and '\nprovisioning_ap = auto\n' in conf and 'NOT yet verified on hardware' in conf, conf
assert any('NOT verified on hardware' in item for item in manifest['features'])
assert any('never verified on hardware' in item for item in manifest['not_implemented'])
assert manifest['not_verified_on_hardware'] is True
assert not any('setup-ap-passphrase' in path or path.endswith('nassimhub-setup-ap.nmconnection') for path in paths), 'a passphrase or access point profile is in the package'
PY
(cd "$ap" && sha256sum -c SHA256SUMS >/dev/null) || fail 'SHA256SUMS does not check'
python3 "$here/scripts/privacy-check.py" --package "$ap" >/dev/null || fail 'the package with the setup access point failed the generic check'
image_cat "$ap/images/rootfs.img" /etc/nassimhub/agent.conf | grep -q '^provisioning_ap = auto$' || fail 'provisioning_ap = auto is not in the image'
image_stat "$ap/images/rootfs.img" /etc/polkit-1/rules.d/48-nassimhub-setup-ap.rules > "$work/apstat"
grep -q 'Mode:  0644' "$work/apstat" && grep -q 'User:     0   Group:     0' "$work/apstat" || fail 'the setup access point polkit rule is not root:root 0644 in the image'
image_cat "$ap/images/rootfs.img" /etc/systemd/system/nassimhub-agent.service.d/setup-ap.conf | grep -q '^AmbientCapabilities=CAP_NET_BIND_SERVICE$' || fail 'the capability drop-in is not in the image'
cmp -s "$here/node/deploy/agent.conf" "$lite/rootfs-overlay/etc/nassimhub/agent.conf" || fail 'the default package does not ship node/deploy/agent.conf unchanged'
grep -q '^provisioning_ap = off$' "$here/node/deploy/agent.conf" || fail 'the packager changed node/deploy/agent.conf'
# The agent itself must accept the rewritten configuration (under emulation, when available).
emulator=$(command -v qemu-aarch64-static 2>/dev/null || command -v qemu-aarch64 2>/dev/null || :)
if [ -n "$emulator" ]; then
	"$emulator" "$build/nassimhub-agent" -config "$ap/rootfs-overlay/etc/nassimhub/agent.conf" -check-config >/dev/null \
		|| fail 'the agent rejects the configuration written for NSH_SETUP_AP=on'
	echo '   the agent accepts the rewritten configuration (qemu-user)'
else
	echo '   NOT CHECKED: no qemu-user here, the agent was not run against the rewritten configuration'
fi
# Taken out of a finished package, or claimed away in its manifest: caught.
rm "$ap/rootfs-overlay/etc/systemd/system/nassimhub-agent.service.d/setup-ap.conf"
if python3 "$here/scripts/privacy-check.py" --package "$ap" > "$work/ap-half.log"; then fail 'half a setup access point passed the generic check'; fi
grep -q 'setup-ap-incomplete' "$work/ap-half.log" || fail 'the incomplete setup access point was not named'
rm -f "$root/usr/sbin/dnsmasq"

echo "package-factory test PASS (TEST ONLY: synthetic rootfs and boot image - the packages made here are not flashable and are removed with $work; nothing flashed, nothing verified on hardware)"
