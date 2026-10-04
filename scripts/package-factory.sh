#!/bin/sh
# Offline developer packaging only. No mounts, chroot, flashing or device writes.
set -eu
[ "$#" = 2 ] || { echo 'usage: package-factory.sh CLEAN_ROOTFS_DIR REVIEWED_BOOT_IMG' >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo 'root required to preserve rootfs ownership' >&2; exit 1; }
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
root=$(realpath "$1")
boot=$(realpath "$2")
[ "$root" != / ] && [ -d "$root/etc" ] && [ -f "$boot" ] || exit 1
case "$root/" in /dev/*|/proc/*|/sys/*|/run/*) echo 'invalid input rootfs' >&2; exit 1;; esac
[ -f "$here/build/nassimhub-agent" ] || { echo 'build the agent first' >&2; exit 1; }
python3 "$here/scripts/audit-rootfs.py" "$root"
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
out="$here/dist/factory"
[ ! -e "$out" ] || { echo 'output already exists; choose a clean build directory' >&2; exit 1; }
mkdir -p "$out/images" "$out/signatures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -a "$root/." "$work/"
cp -a "$here/firmware/overlay/." "$work/"
install -m 0755 "$here/build/nassimhub-agent" "$work/usr/bin/nassimhub-agent"
mkdir -p "$work/etc/nassimhub" "$work/etc/systemd/system" "$work/etc/systemd/system/multi-user.target.wants" "$work/var/lib/nassimhub"
install -m 0644 "$here/node/deploy/agent.conf" "$work/etc/nassimhub/agent.conf"
install -m 0644 "$here/node/deploy/nassimhub-agent.service" "$work/etc/systemd/system/nassimhub-agent.service"
install -m 0644 "$here/node/deploy/nassimhub-agent-resources.conf" "$work/etc/systemd/system/nassimhub-agent.service.d/resources.conf"
chmod 0755 "$work/usr/local/libexec/"nassimhub-*
chmod 0600 "$work/etc/NetworkManager/system-connections/nassimhub-usb.nmconnection"
chown root:root "$work/etc/NetworkManager/system-connections/nassimhub-usb.nmconnection"
for unit in nassimhub-agent nassimhub-usb; do
 ln -s "../$unit.service" "$work/etc/systemd/system/multi-user.target.wants/$unit.service"
done
printf '%s\n' "${ROOT_SPEC} / ext4 defaults,noatime,errors=remount-ro 0 1" 'tmpfs /tmp tmpfs defaults,nosuid,nodev,mode=1777 0 0' > "$work/etc/fstab"
: > "$work/etc/machine-id"
python3 "$here/scripts/audit-rootfs.py" "$work"
size_mb=$(( $(du -sm "$work" | cut -f1) + 256 ))
truncate -s "${size_mb}M" "$out/images/rootfs.img"
mke2fs -q -t ext4 -L rootfs -d "$work" "$out/images/rootfs.img"
e2fsck -fn "$out/images/rootfs.img"
cp "$boot" "$out/images/boot.img"
printf '%s\n' 'No release signature is provided by this developer build. SHA256 is integrity, not authenticity. Release publisher must sign manifest separately; do not put signing private keys into the image.' > "$out/signatures/README.txt"
python3 - "$out" "$ROOT_SPEC" <<'PY'
import hashlib, json, pathlib, sys
out=pathlib.Path(sys.argv[1]); files=[]
for name in ('boot.img','rootfs.img'):
    p=out/'images'/name
    digest=hashlib.sha256()
    with p.open('rb') as f:
        while b:=f.read(1024*1024): digest.update(b)
    files.append({'path':'images/'+name,'sha256':digest.hexdigest(),'size':p.stat().st_size})
manifest={'schema':1,'channel':'developer','board':'UFI003_MB_V02','distro':'Debian 13 trixie','kernel':'6.12.49-msm8916-g93a71ee9468d','root_spec':sys.argv[2],'image_format':'raw-ext4','signed':False,'images':files,'protected_partitions':['modemst1','modemst2','fsg','persist','fsc','cdt','sbl1','aboot','tz','rpm','hyp','sec']}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
(cd "$out"; sha256sum images/boot.img images/rootfs.img manifest.json > SHA256SUMS)
echo "Developer package created: $out (not flashed, not signed, requires board-specific review)"
