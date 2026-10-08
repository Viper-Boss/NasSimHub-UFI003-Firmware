#!/bin/sh
# Build the Debian 13 (trixie) arm64 base root filesystem for the UFI003 from a
# pinned archive snapshot, repeatably. No device is touched, nothing is flashed.
#
#   Resolve the lock (once per base-system refresh; needs network and mmdebstrap):
#     sudo sh scripts/build-rootfs.sh --lock --timestamp 20260101T000000Z \
#          --boot-img BOOT.IMG --modules MODULES --service-uid N --service-gid N \
#          --image-size-mib N [--setup-ap]
#
#   Build (needs network for the bootstrap, and mmdebstrap):
#     sudo sh scripts/build-rootfs.sh --out DIR --boot-img BOOT.IMG --modules MODULES \
#          [--firmware-dir DIR] [--setup-ap]
#
#   Build WITHOUT a resolved lock (never a release input; the manifest says so):
#     sudo SOURCE_DATE_EPOCH=N sh scripts/build-rootfs.sh --unlocked --out DIR \
#          --boot-img BOOT.IMG --modules MODULES --service-uid N --service-gid N \
#          [--timestamp TS] [--from-tar BOOTSTRAP.tar]
#
# Output (DIR must not exist):
#   rootfs/               the clean base tree: Debian packages, the nassimhub
#                         account, the kernel's modules, nothing per-device
#   rootfs.tar            the same tree as a deterministic archive
#   PACKAGES.tsv          package, version, architecture of everything installed
#   ROOTFS-MANIFEST.json  provenance: lock hash, snapshot, package-set hash,
#                         kernel artefact hashes, tree hash, and whether this is
#                         a release input or not (with the reasons)
#
# What this script does NOT do: it does not add the agent, the overlay or the
# units and does not make the ext4 image. scripts/package-factory.sh does that,
# with the permission normalisation and unit links it already has, from the
# directory written here:
#     sudo ROOT_SPEC=LABEL=rootfs NSH_ROOTFS_MANIFEST=DIR/ROOTFS-MANIFEST.json \
#          sh scripts/package-factory.sh DIR/rootfs BOOT.IMG Lite
# One implementation of "what the project layers on top" instead of two.
#
# The kernel is consumed, not built: --boot-img is the verified Android v0 boot
# image, --modules the matching lib/modules/<release> (directory or tar). The
# release string is read from the kernel itself and every module's vermagic must
# match it. Firmware is copied only from --firmware-dir, never downloaded.
#
# Options:
#   --lock-file FILE     default firmware/rootfs.lock.json
#   --setup-ap           also install dnsmasq-base (firmware/debian-packages.json)
#   --from-tar FILE      use an existing bootstrap archive instead of running
#                        mmdebstrap; only with --unlocked (its contents cannot
#                        be tied to the snapshot)
#
# Needs root: file ownership in the tree must be the image's, and mmdebstrap's
# root mode is the one this script was written for. Not run in the container
# this was written in (no network, no mmdebstrap); see docs/ROOTFS-BUILD.md for
# what was and was not exercised.
set -eu
# shellcheck disable=SC1007 # an empty CDPATH for this one cd
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONDONTWRITEBYTECODE=1
die() { echo "build-rootfs.sh: $*" >&2; exit 1; }
tools() { python3 "$here/scripts/rootfs_tools.py" "$@"; }
lock_field() { python3 -c 'import json,sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value.get(key) if isinstance(value, dict) else None
print("" if value is None else value)' "$lock" "$1"; }

mode=build
lock=$here/firmware/rootfs.lock.json
out= boot= modules= firmware= timestamp= uid= gid= size= from_tar=
unlocked=no
setup_ap=
while [ "$#" -gt 0 ]; do
	case $1 in
	--lock) mode=lock; shift;;
	--unlocked) unlocked=yes; shift;;
	--setup-ap) setup_ap=--setup-ap; shift;;
	--out|--boot-img|--modules|--firmware-dir|--timestamp|--service-uid|--service-gid|--image-size-mib|--from-tar|--lock-file)
		[ "$#" -ge 2 ] || die "$1 needs a value"
		case $1 in
		--out) out=$2;; --boot-img) boot=$2;; --modules) modules=$2;; --firmware-dir) firmware=$2;;
		--timestamp) timestamp=$2;; --service-uid) uid=$2;; --service-gid) gid=$2;; --image-size-mib) size=$2;;
		--from-tar) from_tar=$2;; --lock-file) lock=$2;;
		esac
		shift 2
		;;
	-h|--help) sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
	*) die "unknown argument $1 (see --help)";;
	esac
done
for number in "$uid" "$gid" "$size"; do
	case $number in *[!0-9]*) die 'uid, gid and size must be numbers';; esac
done
[ -f "$lock" ] || die "lock file $lock not found"
[ "$(id -u)" = 0 ] || die 'root required (file ownership in the tree; mmdebstrap root mode)'
[ -n "$boot" ] && [ -f "$boot" ] || die '--boot-img FILE is required: the verified boot image this rootfs is for'
[ -n "$modules" ] && [ -e "$modules" ] || die '--modules DIR_OR_TAR is required: lib/modules/<release> of that same kernel'

suite=$(lock_field suite)
arch=$(lock_field architecture)
variant=$(lock_field variant)
keyring=$(lock_field snapshot.keyring)
locked_release=$(lock_field kernel.release)
[ "$suite" = trixie ] && [ "$arch" = arm64 ] || die 'this script builds Debian 13 (trixie) arm64 and nothing else'

# The kernel inputs, identified before anything is built.
kernel_release=$(tools kernel-release "$boot") || die 'the kernel release could not be read from --boot-img'
[ "$kernel_release" = "$locked_release" ] || die "--boot-img is kernel $kernel_release; the verified kernel is $locked_release (firmware/upstream.lock.json)"
boot_sha=$(sha256sum < "$boot" | cut -d' ' -f1)
if [ -d "$modules" ]; then
	# A directory has no single hash; its tree hash stands in for one.
	modules_sha=$(tools tree-hash "$modules" | cut -d' ' -f1)
else
	modules_sha=$(sha256sum < "$modules" | cut -d' ' -f1)
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# archive_of TEMPLATE TIMESTAMP: the snapshot URL for a timestamp.
archive_of() { printf '%s\n' "$1" | sed "s/{timestamp}/$2/"; }

# bootstrap TIMESTAMP EPOCH OUTPUT.tar: the one step that needs the network.
# mmdebstrap is given the two pinned archives and nothing else; with
# SOURCE_DATE_EPOCH set it writes a tar whose order, owners and times do not
# depend on the build host. A snapshot's Release file is past its Valid-Until
# by design, hence the apt option.
bootstrap() {
	command -v mmdebstrap >/dev/null 2>&1 || die 'mmdebstrap not found. On a Debian/Ubuntu build host: apt install mmdebstrap qemu-user-static binfmt-support debian-archive-keyring gpgv e2fsprogs'
	include=$(tools lock-include "$lock" $setup_ap) || exit 1
	if [ -n "$1" ]; then
		main_archive=$(archive_of "$(lock_field snapshot.archive)" "$1")
		security_archive=$(archive_of "$(lock_field snapshot.security_archive)" "$1")
	else
		# --unlocked without a timestamp: today's archive, whatever it holds.
		main_archive=http://deb.debian.org/debian/
		security_archive=http://security.debian.org/debian-security/
	fi
	echo "bootstrap: $suite/$arch variant=$variant include=$include"
	echo "bootstrap: $main_archive and $security_archive"
	SOURCE_DATE_EPOCH=$2 mmdebstrap --variant="$variant" --architectures="$arch" --include="$include" \
		--keyring="$keyring" --aptopt='Acquire::Check-Valid-Until "false"' \
		"$suite" "$3" \
		"deb $main_archive $suite main" \
		"deb $security_archive $suite-security main"
}
# status_of TAR OUTPUT: var/lib/dpkg/status out of a bootstrap archive.
status_of() {
	python3 - "$1" "$2" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    for member in archive:
        if member.name.lstrip('./') == 'var/lib/dpkg/status' and member.isreg():
            with open(sys.argv[2], 'wb') as out:
                out.write(archive.extractfile(member).read())
            sys.exit(0)
sys.exit('the bootstrap archive has no var/lib/dpkg/status')
PY
}

if [ "$mode" = lock ]; then
	[ -n "$timestamp" ] || die '--lock needs --timestamp (a snapshot.debian.org timestamp, e.g. 20260101T000000Z)'
	if [ -z "$uid" ] || [ -z "$gid" ]; then die '--lock needs --service-uid and --service-gid: `id -u nassimhub` / `id -g nassimhub` on a verified device'; fi
	[ -n "$size" ] || die '--lock needs --image-size-mib: the size of the rootfs partition on the stick (not documented in this repository)'
	[ -z "$from_tar" ] || die '--lock always bootstraps from the snapshot itself'
	epoch=$(python3 -c 'import calendar,sys,time; print(calendar.timegm(time.strptime(sys.argv[1], "%Y%m%dT%H%M%SZ")))' "$timestamp") || die 'unreadable --timestamp'
	bootstrap "$timestamp" "$epoch" "$work/base.tar"
	status_of "$work/base.tar" "$work/status"
	set --
	index=0
	for pair in "$(archive_of "$(lock_field snapshot.archive)" "$timestamp")|$suite" \
		"$(archive_of "$(lock_field snapshot.security_archive)" "$timestamp")|$suite-security"; do
		index=$((index + 1))
		python3 "$here/scripts/rootfs_fetch_index.py" --base "${pair%|*}" --suite "${pair#*|}" --arch "$arch" --keyring "$keyring" \
			--out-packages "$work/Packages.$index" --out-release "$work/InRelease.$index"
		# "all" packages are listed in the architecture's index too.
		set -- "$@" --index "$work/Packages.$index" --release-file "$work/InRelease.$index"
	done
	# shellcheck disable=SC2086 # $setup_ap is one flag or nothing
	tools lock-resolve --lock "$lock" --status "$work/status" --timestamp "$timestamp" --out "$work/lock.json" "$@" \
		--kernel-release "$kernel_release" --boot-img-sha256 "$boot_sha" --modules-sha256 "$modules_sha" \
		--uid "$uid" --gid "$gid" --image-mib "$size" $setup_ap
	cp "$work/lock.json" "$lock"
	tools lock-check --release "$lock"
	echo "The lock is resolved: review the diff of $lock (package list and versions), commit it, then build."
	exit 0
fi

# --- build -------------------------------------------------------------------

[ -n "$out" ] || die '--out DIR is required'
[ ! -e "$out" ] || die "output already exists: $out"
release_input=yes
reasons=
note() { reasons="$reasons$1
"; release_input=no; }
if tools lock-check --release "$lock" > "$work/lock-check" 2>&1; then
	[ "$unlocked" = no ] || note '--unlocked was given although the lock is resolved'
else
	if [ "$unlocked" = no ]; then
		cat "$work/lock-check" >&2
		die "the lock is not resolved, so this would not be a reproducible build. Resolve it (--lock, on a networked build host), or pass --unlocked to build something that is stamped as NOT a release input."
	fi
	note "the lock is not resolved: $(sed -n '2,$p' "$work/lock-check" | sed 's/^ *//' | tr '\n' ';' | sed 's/;$//; s/;/; /g')"
fi
if [ "$release_input" = yes ]; then
	for given in "$timestamp" "$uid" "$gid" "$from_tar"; do
		[ -z "$given" ] || die 'with a resolved lock the timestamp, the service ids and the bootstrap come from the lock; --timestamp, --service-uid, --service-gid and --from-tar are only for --unlocked'
	done
	timestamp=$(lock_field snapshot.timestamp)
	epoch=$(lock_field source_date_epoch)
	uid=$(lock_field service_user.uid)
	gid=$(lock_field service_user.gid)
	[ "$boot_sha" = "$(lock_field kernel.boot_img_sha256)" ] || die '--boot-img is not the boot image the lock records (SHA-256 differs)'
	[ "$modules_sha" = "$(lock_field kernel.modules_sha256)" ] || die '--modules is not the modules input the lock records (SHA-256 differs)'
else
	[ -n "$uid" ] || uid=$(lock_field service_user.uid)
	[ -n "$gid" ] || gid=$(lock_field service_user.gid)
	if [ -z "$uid" ] || [ -z "$gid" ]; then die '--unlocked needs --service-uid and --service-gid (the lock has none)'; fi
	if [ -n "$timestamp" ]; then
		epoch=$(python3 -c 'import calendar,sys,time; print(calendar.timegm(time.strptime(sys.argv[1], "%Y%m%dT%H%M%SZ")))' "$timestamp") || die 'unreadable --timestamp'
	else
		epoch=${SOURCE_DATE_EPOCH:-}
		case $epoch in ''|*[!0-9]*) die '--unlocked needs --timestamp or SOURCE_DATE_EPOCH';; esac
		[ -n "$from_tar" ] || note 'bootstrapped from the live Debian archive, not from a snapshot'
	fi
fi

if [ -n "$from_tar" ]; then
	[ -f "$from_tar" ] || die "--from-tar $from_tar is not a file"
	note 'the bootstrap archive was supplied by the operator (--from-tar): its contents are not tied to the archive snapshot'
	cp "$from_tar" "$work/base.tar"
	bootstrap_by='operator-supplied archive (--from-tar)'
else
	bootstrap "$timestamp" "$epoch" "$work/base.tar"
	bootstrap_by=$(mmdebstrap --version 2>/dev/null | head -n 1 || echo mmdebstrap)
fi

mkdir -p "$out/rootfs"
# shellcheck disable=SC1007
out=$(CDPATH= cd -- "$out" && pwd)
failed() { rm -rf "$work"; mv "$out" "$out.FAILED" 2>/dev/null || :; echo "build-rootfs.sh: FAILED; what was built so far is in $out.FAILED for inspection, not for use" >&2; }
trap 'status=$?; [ "$status" = 0 ] || failed; rm -rf "$work"; exit "$status"' EXIT
# Device nodes are not part of the image: /dev is a devtmpfs at boot.
tar -xpf "$work/base.tar" --numeric-owner --xattrs --xattrs-include='*' --exclude='./dev/*' --exclude='dev/*' -C "$out/rootfs"

status_of "$work/base.tar" "$work/status"
if [ "$release_input" = yes ]; then
	tools verify-packages --lock "$lock" --root "$out/rootfs"
fi
python3 - "$here/scripts" "$work/status" "$out/PACKAGES.tsv" > "$work/package-set" <<'PY'
import pathlib, sys
sys.path.insert(0, sys.argv[1])
import rootfs_tools
packages = rootfs_tools.installed_packages(pathlib.Path(sys.argv[2]).read_text(encoding='utf-8'))
text, digest = rootfs_tools.package_manifest(packages)
pathlib.Path(sys.argv[3]).write_text(text)
print(digest, len(packages))
PY
read -r package_sha package_count < "$work/package-set"

tools finalize --root "$out/rootfs" --lock "$lock" --epoch "$epoch" --uid "$uid" --gid "$gid"
tools modules --root "$out/rootfs" --modules "$modules" --kernel-release "$kernel_release"
if [ -n "$firmware" ]; then
	tools firmware --root "$out/rootfs" --dir "$firmware" --out "$work/firmware.json"
else
	echo '[]' > "$work/firmware.json"
	echo 'firmware: none supplied (--firmware-dir); the image carries no modem or Wi-Fi firmware'
fi
tools clamp-mtime "$out/rootfs" "$epoch"
# The same gate the packager applies to its input: nothing per-device.
python3 "$here/scripts/audit-rootfs.py" "$out/rootfs"

read -r tree_sha tree_count <<EOF
$(tools tree-hash "$out/rootfs")
EOF
# The archive: sorted, numeric owners, no access or change times, modification
# times clamped. Two runs over the same tree give the same bytes.
tar --sort=name --format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
	--numeric-owner --mtime="@$epoch" --clamp-mtime --xattrs --xattrs-include='security.capability' \
	-C "$out/rootfs" -cf "$out/rootfs.tar" .
tar_sha=$(sha256sum < "$out/rootfs.tar" | cut -d' ' -f1)

printf '%s' "$reasons" > "$work/reasons"
python3 - "$out" "$lock" "$release_input" "$work/reasons" "$timestamp" "$epoch" "$package_sha" "$package_count" "$bootstrap_by" \
	"$kernel_release" "$boot_sha" "$modules_sha" "$work/firmware.json" "$uid" "$gid" "$tree_sha" "$tree_count" "$tar_sha" "${setup_ap:-}" <<'PY'
import hashlib, json, os, pathlib, sys
(out, lock_path, release_input, reasons, timestamp, epoch, package_sha, package_count, bootstrap, kernel_release, boot_sha,
 modules_sha, firmware, uid, gid, tree_sha, tree_count, tar_sha, setup_ap) = sys.argv[1:20]
lock = json.loads(pathlib.Path(lock_path).read_text())
files = json.loads(pathlib.Path(firmware).read_text())
release = release_input == 'yes'
manifest = {
    'schema': 1, 'kind': 'nassimhub-ufi003-rootfs-base',
    'release_input': release,
    'reproducible': release,
    'non_release_reasons': [line for line in pathlib.Path(reasons).read_text().splitlines() if line],
    'statement': ('built from a resolved lock: a rebuild from the same lock and inputs must give the same tree and archive'
                  if release else
                  'NOT a release input and NOT reproducible: built without a resolved lock (see non_release_reasons)'),
    'distro': 'Debian 13 trixie', 'architecture': lock['architecture'], 'variant': lock['variant'],
    'lock': {'sha256': hashlib.sha256(pathlib.Path(lock_path).read_bytes()).hexdigest(), 'status': lock.get('status')},
    'snapshot': {'timestamp': timestamp or None},
    'source_date_epoch': int(epoch),
    'bootstrap': bootstrap,
    'package_set': {'sha256': package_sha, 'count': int(package_count), 'file': 'PACKAGES.tsv',
                    'setup_access_point_packages': bool(setup_ap)},
    'service_user': {'name': lock['service_user']['name'], 'uid': int(uid), 'gid': int(gid)},
    'kernel': {'release': kernel_release, 'boot_img_sha256': boot_sha, 'modules_sha256': modules_sha,
               'vermagic': 'every installed module matches the release read from the boot image',
               'built_here': False},
    'firmware': {'included': bool(files), 'files': files,
                 'redistribution': ('operator-supplied vendor firmware: NOT redistributable by this project; do not publish this '
                                    'rootfs or an image made from it') if files else 'none included'},
    'image': lock.get('image', {}),
    'tree_sha256': tree_sha, 'tree_entries': int(tree_count),
    'archive': {'path': 'rootfs.tar', 'sha256': tar_sha, 'size': os.path.getsize(os.path.join(out, 'rootfs.tar'))},
    'contains': 'Debian packages, the service account, kernel modules' + (', operator-supplied firmware' if files else '')
                + '. NOT yet in this tree: the agent, the overlay and the units (scripts/package-factory.sh adds them).',
    'not_verified_on_hardware': True,
}
pathlib.Path(out, 'ROOTFS-MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY

echo "rootfs tree:    $out/rootfs ($tree_count entries, tree sha256 $tree_sha)"
echo "rootfs archive: $out/rootfs.tar (sha256 $tar_sha)"
echo "packages:       $package_count (manifest sha256 $package_sha)"
if [ "$release_input" = yes ]; then
	echo "provenance:     built from lock $(sha256sum < "$lock" | cut -d' ' -f1) (snapshot $timestamp)"
else
	echo 'provenance:     NOT A RELEASE INPUT, NOT REPRODUCIBLE:'
	printf '%s' "$reasons" | sed 's/^/                  - /'
fi
echo 'Not booted, not flashed, not verified on hardware. Next:'
echo "  sudo ROOT_SPEC=LABEL=rootfs NSH_ROOTFS_MANIFEST=$out/ROOTFS-MANIFEST.json sh scripts/package-factory.sh $out/rootfs $boot Lite"
