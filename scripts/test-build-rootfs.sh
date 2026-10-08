#!/bin/sh
# End-to-end TEST of scripts/build-rootfs.sh and of the rootfs provenance in
# scripts/package-factory.sh, on SYNTHETIC inputs.
#
# The "bootstrap" is a tar of a few dozen hand-written files standing in for
# what mmdebstrap produces (python3 scripts/test_rootfs.py --make-fixtures);
# the "boot image" holds a gzip stream with a version banner; the "modules"
# are 200-byte ELF stubs. This exercises everything build-rootfs.sh does AFTER
# the bootstrap - the part that needs no network - and the image assembly.
# It does NOT bootstrap Debian, and NOTHING it produces is a root filesystem
# that boots or a package that may be flashed.
#
# Needs root (file ownership in the tree and the image) and e2fsprogs; without
# either it says SKIPPED and exits 0.
set -eu
export PYTHONDONTWRITEBYTECODE=1
# shellcheck disable=SC1007 # an empty CDPATH for this one cd
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${NSH_TEST_VERSION:-9.9.1}
fail() { echo "test-build-rootfs FAILED: $*" >&2; [ ! -f "${log:-/nonexistent}" ] || sed 's/^/    | /' "$log" >&2; exit 1; }
if [ "$(id -u)" != 0 ] || ! command -v mke2fs >/dev/null 2>&1 || ! command -v debugfs >/dev/null 2>&1; then
	echo 'build-rootfs test SKIPPED: needs root and e2fsprogs (mke2fs, debugfs)'
	exit 0
fi
outside_repositories() {
	for base in "${NSH_TEST_TMPDIR:-}" "${TMPDIR:-/tmp}" /var/tmp /dev/shm; do
		[ -n "$base" ] && [ -d "$base" ] && [ -w "$base" ] || continue
		# shellcheck disable=SC1007
		probe=$(CDPATH= cd -- "$base" && pwd -P)
		inside=no
		while :; do
			for marker in .git .hg .svn; do [ ! -e "$probe/$marker" ] || inside=yes; done
			[ "$probe" != / ] || break
			probe=$(dirname "$probe")
		done
		[ "$inside" = yes ] || { mktemp -d "$base/nsh-rootfs-test.XXXXXX"; return 0; }
	done
	return 1
}
work=$(outside_repositories) || fail 'no temporary directory outside a repository; set NSH_TEST_TMPDIR'
trap 'rm -rf "$work"' EXIT
log=$work/log
fix=$work/fix
mkdir "$fix"
python3 "$here/scripts/test_rootfs.py" --make-fixtures "$fix"
lock=$here/firmware/rootfs.lock.json
lock_before=$(sha256sum < "$lock")
rootfs() { sh "$here/scripts/build-rootfs.sh" "$@" > "$log" 2>&1; }
field() { python3 -c 'import json,sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value[key]
print(value)' "$1" "$2"; }

echo '== 1. the shipped lock is unresolved: no build without --unlocked'
if rootfs --out "$work/refused" --boot-img "$fix/boot.img" --modules "$fix/modules"; then fail 'a rootfs was built from an unresolved lock'; fi
grep -q 'the lock is not resolved' "$log" || fail 'the refusal does not name the unresolved lock'
grep -q 'package versions are not resolved (versions: null)' "$log" || fail 'the refusal does not say what is missing'
[ ! -e "$work/refused" ] || fail 'an output directory was left behind'
if rootfs --unlocked --out "$work/refused" --boot-img "$fix/boot.img" --modules "$fix/modules" --from-tar "$fix/bootstrap.tar"; then fail '--unlocked built without service ids'; fi
grep -q 'needs --service-uid and --service-gid' "$log" || fail 'the missing service ids were not asked for'
if rootfs --lock --timestamp 20260101T000000Z --boot-img "$fix/boot.img" --modules "$fix/modules" --service-uid 990 --service-gid 990; then fail '--lock ran without the partition size'; fi
grep -q 'needs --image-size-mib' "$log" || fail 'the partition size was not asked for'

echo '== 2. the kernel inputs are checked before anything is built'
if rootfs --unlocked --out "$work/refused" --boot-img "$fix/other-boot.img" --modules "$fix/modules" --from-tar "$fix/bootstrap.tar" --service-uid 990 --service-gid 990; then fail 'another kernel was accepted'; fi
grep -q 'is kernel 6.1.0-synthetic; the verified kernel is' "$log" || fail 'the kernel release mismatch was not reported'
if SOURCE_DATE_EPOCH=1700000000 rootfs --unlocked --out "$work/refused" --boot-img "$fix/boot.img" --modules "$fix/wrong-modules" --from-tar "$fix/bootstrap.tar" --service-uid 990 --service-gid 990; then fail 'modules of another kernel were accepted'; fi
grep -q 'kernel modules do not match kernel release' "$log" || fail 'the vermagic mismatch was not reported'
[ ! -e "$work/refused" ] && [ -d "$work/refused.FAILED" ] || fail 'a failed build was not set aside as .FAILED'
if SOURCE_DATE_EPOCH=1700000000 rootfs --unlocked --out "$work/refused2" --boot-img "$fix/boot.img" --modules "$fix/modules" --firmware-dir "$fix/unit-firmware" --from-tar "$fix/bootstrap.tar" --service-uid 990 --service-gid 990; then fail 'per-device modem data was accepted as firmware'; fi
grep -q 'refused (modem-calibration)' "$log" || fail 'the per-device data was not named as the reason'

echo '== 3. --unlocked from a synthetic bootstrap: built, and stamped as not a release input'
build_one() {
	SOURCE_DATE_EPOCH=1700000000 rootfs --unlocked --out "$1" --boot-img "$fix/boot.img" --modules "$fix/modules" \
		--firmware-dir "$fix/firmware" --from-tar "$fix/bootstrap.tar" --service-uid 990 --service-gid 990 || fail "build $1 failed"
}
build_one "$work/a"
grep -q 'NOT A RELEASE INPUT, NOT REPRODUCIBLE' "$log" || fail 'the output was not announced as a non-release build'
manifest=$work/a/ROOTFS-MANIFEST.json
[ "$(field "$manifest" release_input)" = False ] && [ "$(field "$manifest" reproducible)" = False ] || fail 'the manifest claims a release input'
python3 - "$manifest" "$work/a" "$lock" "$fix" <<'PY' || exit 1
import hashlib, json, os, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
out, lock, fix = pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
root = out / 'rootfs'
reasons = ' | '.join(manifest['non_release_reasons'])
assert 'the lock is not resolved' in reasons and '--from-tar' in reasons, reasons
assert manifest['statement'].startswith('NOT a release input and NOT reproducible'), manifest['statement']
assert manifest['lock'] == {'sha256': hashlib.sha256(lock.read_bytes()).hexdigest(), 'status': json.loads(lock.read_text())['status']}
assert manifest['kernel']['boot_img_sha256'] == hashlib.sha256((fix / 'boot.img').read_bytes()).hexdigest()
assert manifest['kernel']['built_here'] is False
assert manifest['service_user'] == {'name': 'nassimhub', 'uid': 990, 'gid': 990}
assert manifest['firmware']['included'] is True and 'NOT redistributable' in manifest['firmware']['redistribution']
assert [entry['path'] for entry in manifest['firmware']['files']] == ['usr/lib/firmware/synthetic-model/synthetic.mbn']
assert manifest['archive']['sha256'] == hashlib.sha256((out / 'rootfs.tar').read_bytes()).hexdigest()
release = manifest['kernel']['release']
assert (root / 'usr/lib/modules' / release / 'modules.dep').is_file()
assert 'nassimhub:x:990:990::/var/lib/nassimhub:/usr/sbin/nologin' in (root / 'etc/passwd').read_text().splitlines()
assert (root / 'etc/machine-id').read_bytes() == b''
for gone in ('etc/ssh/ssh_host_ed25519_key', 'var/log/dpkg.log', 'var/lib/apt/lists/synthetic_Packages', 'var/cache/apt/archives',
             'etc/resolv.conf', 'var/lib/systemd/random-seed'):
    assert not os.path.lexists(root / gone), gone
packages = (out / 'PACKAGES.tsv').read_text()
assert 'systemd\t1.0-1\tarm64\n' in packages and 'synthetic-removed' not in packages
assert manifest['package_set']['sha256'] == hashlib.sha256(packages.encode()).hexdigest()
for directory, names, files in os.walk(root):
    for name in names + files:
        info = os.lstat(os.path.join(directory, name))
        assert info.st_mtime <= 1700000000, name
        assert (info.st_uid, info.st_gid) == (0, 0), name
PY

echo '== 4. the same inputs give the same tree and the same archive'
sleep 1
build_one "$work/b"
[ "$(field "$work/a/ROOTFS-MANIFEST.json" tree_sha256)" = "$(field "$work/b/ROOTFS-MANIFEST.json" tree_sha256)" ] || fail 'two builds gave different trees'
cmp -s "$work/a/rootfs.tar" "$work/b/rootfs.tar" || fail 'two builds gave different rootfs.tar'
cmp -s "$work/a/ROOTFS-MANIFEST.json" "$work/b/ROOTFS-MANIFEST.json" || fail 'two builds gave different manifests'
[ "$(sha256sum < "$lock")" = "$lock_before" ] || fail 'a build changed firmware/rootfs.lock.json'

echo '== 5. package-factory.sh: provenance of the rootfs, and a repeatable image'
build=${NSH_TEST_BUILD_DIR:-}
if [ -z "$build" ] || [ ! -f "$build/sbom/sbom.spdx.json" ]; then
	build=$work/build
	NSH_BUILD_DIR="$build" sh "$here/scripts/build-agent.sh" "$version" > "$log" 2>&1 || fail 'the agent could not be built'
fi
export NSH_BUILD_DIR="$build" ROOT_SPEC=LABEL=rootfs
# The SBOM made with the agent: the shipped lock is unresolved, so it must not list Debian packages.
grep -q 'Root filesystem package set: not included: rootfs lock unresolved' "$build/sbom/sbom.spdx.json" || fail 'the SBOM does not say that the rootfs package set is not included'
if grep -q 'SPDXRef-Deb-' "$build/sbom/sbom.spdx.json"; then fail 'the SBOM lists Debian packages although the lock is unresolved'; fi
# firmware in the tree: the audit and the package gate must still pass.
factory() { dist=$1; shift; NSH_DIST_DIR="$dist" sh "$here/scripts/package-factory.sh" "$@" > "$log" 2>&1; }
NSH_ROOTFS_MANIFEST=$work/a/ROOTFS-MANIFEST.json factory "$work/dist1" "$work/a/rootfs" "$fix/boot.img" Lite || fail 'packaging the built rootfs failed'
grep -q '^rootfs: built by build-rootfs.sh WITHOUT a resolved lock (non-reproducible, not a release input)$' "$log" || fail 'the non-release rootfs was not announced'
sleep 1
NSH_ROOTFS_MANIFEST=$work/b/ROOTFS-MANIFEST.json factory "$work/dist2" "$work/b/rootfs" "$fix/boot.img" Lite || fail 'packaging the second rootfs failed'
one=$work/dist1/factory/$version-Lite
two=$work/dist2/factory/$version-Lite
cmp -s "$one/images/rootfs.img" "$two/images/rootfs.img" || fail 'two packagings gave different rootfs.img'
e2fsck -fn "$one/images/rootfs.img" > "$log" 2>&1 || fail 'rootfs.img does not pass e2fsck'
[ "$(field "$one/PACKAGE-MANIFEST.json" rootfs.statement)" = 'built by build-rootfs.sh WITHOUT a resolved lock (non-reproducible, not a release input)' ] || fail 'PACKAGE-MANIFEST.json rootfs statement'
[ "$(field "$one/PACKAGE-MANIFEST.json" rootfs.release_input)" = False ] || fail 'PACKAGE-MANIFEST.json claims a release input'
[ "$(field "$one/PACKAGE-MANIFEST.json" rootfs.image.fixed_uuid_seed_and_times)" = True ] || fail 'the image was not made with fixed parameters'
[ "$(field "$one/PACKAGE-MANIFEST.json" rootfs.firmware.included)" = True ] || fail 'the operator-supplied firmware is not recorded in the package manifest'
debugfs -R 'stat /usr/bin/nassimhub-agent' "$one/images/rootfs.img" 2>/dev/null | grep -q 'ctime: 0x6553f100' || fail 'inode times in the image are not fixed'
dumpe2fs -h "$one/images/rootfs.img" 2>/dev/null | grep -qi "UUID: *$(field "$lock" image.uuid)" || fail 'the filesystem UUID is not the fixed one'
debugfs -R "stat /usr/lib/modules/$(field "$work/a/ROOTFS-MANIFEST.json" kernel.release)/modules.dep" "$one/images/rootfs.img" 2>/dev/null | grep -q 'Type: regular' || fail 'the modules are not in the image'

echo '== 6. without a manifest: operator-supplied (unverified provenance)'
factory "$work/dist3" "$work/a/rootfs" "$fix/boot.img" Lite || fail 'packaging without a manifest failed'
grep -q '^rootfs: operator-supplied (unverified provenance)$' "$log" || fail 'the unverified rootfs was not announced'
three=$work/dist3/factory/$version-Lite
[ "$(field "$three/PACKAGE-MANIFEST.json" rootfs.statement)" = 'operator-supplied (unverified provenance)' ] || fail 'PACKAGE-MANIFEST.json does not say operator-supplied'
[ "$(field "$three/PACKAGE-MANIFEST.json" rootfs.built_from_lock)" = False ] || fail 'an operator-supplied rootfs is recorded as built from the lock'
[ "$(field "$three/PACKAGE-MANIFEST.json" rootfs.image.fixed_uuid_seed_and_times)" = False ] || fail 'an unverified rootfs is recorded with a repeatable image'

echo '== 7. a manifest that marks a release input says "built from lock <sha256>" (hand-made manifest: no resolved lock exists here)'
python3 - "$work/a/ROOTFS-MANIFEST.json" "$work/release-manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
manifest.update(release_input=True, reproducible=True, non_release_reasons=[])
manifest['image'] = dict(manifest['image'], size_mib=96)
json.dump(manifest, open(sys.argv[2], 'w'))
PY
NSH_ROOTFS_MANIFEST=$work/release-manifest.json factory "$work/dist4" "$work/a/rootfs" "$fix/boot.img" Dev || fail 'packaging with a release manifest failed'
four=$work/dist4/factory/$version-Dev
want="built from lock $(sha256sum < "$lock" | cut -d' ' -f1)"
grep -q "^rootfs: $want\$" "$log" || fail 'the locked rootfs was not announced'
[ "$(field "$four/PACKAGE-MANIFEST.json" rootfs.statement)" = "$want" ] || fail 'PACKAGE-MANIFEST.json does not say built from lock'
[ "$(field "$four/PACKAGE-MANIFEST.json" rootfs.image.size_mib)" = 96 ] || fail 'the image is not the recorded partition size'
[ "$(stat -c %s "$four/images/rootfs.img")" = $((96 * 1024 * 1024)) ] || fail 'rootfs.img is not 96 MiB'

echo '== 8. a manifest for another tree, another boot image, or a tree too large for the partition is refused'
: > "$work/a/rootfs/usr/bin/added-after-the-build"
if NSH_ROOTFS_MANIFEST=$work/a/ROOTFS-MANIFEST.json factory "$work/dist5" "$work/a/rootfs" "$fix/boot.img" Lite; then fail 'a changed tree was packaged under its old manifest'; fi
grep -q 'is not the tree its ROOTFS-MANIFEST.json describes' "$log" || fail 'the changed tree was not named as the reason'
rm "$work/a/rootfs/usr/bin/added-after-the-build"
python3 - "$fix/other-root.img" "$here" <<'PY'
import pathlib, sys
sys.path.insert(0, sys.argv[2] + '/scripts')
import test_rootfs
pathlib.Path(sys.argv[1]).write_bytes(test_rootfs.boot_image(cmdline=b'root=LABEL=rootfs quiet'))
PY
if NSH_ROOTFS_MANIFEST=$work/a/ROOTFS-MANIFEST.json factory "$work/dist5" "$work/a/rootfs" "$fix/other-root.img" Lite; then fail 'another boot image was accepted for this rootfs'; fi
grep -q 'the boot image is not the one this rootfs was built for' "$log" || fail 'the boot image mismatch was not named'
python3 - "$work/release-manifest.json" "$work/small-manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
manifest['image'] = dict(manifest['image'], size_mib=4)
json.dump(manifest, open(sys.argv[2], 'w'))
PY
if NSH_ROOTFS_MANIFEST=$work/small-manifest.json factory "$work/dist6" "$work/a/rootfs" "$fix/boot.img" Lite; then fail 'a tree larger than the partition was packaged'; fi
grep -q 'does not fit a 4 MiB image' "$log" || fail 'the size problem was not named'

echo 'test-build-rootfs PASS (SYNTHETIC bootstrap, kernel and modules: no Debian system was bootstrapped, nothing here boots, nothing was flashed or verified on hardware)'
