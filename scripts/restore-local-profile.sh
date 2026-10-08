#!/bin/sh
# Rescue-side, SAME-DEVICE restore into a mounted OFFLINE rootfs only.
# Do not use the resulting private rootfs as a redistributable image.
set -eu
export LC_ALL=C
[ "$#" = 1 ] || { echo 'usage: restore-local-profile.sh OFFLINE_ROOTFS_MOUNT' >&2; exit 2; }
[ "$(id -u)" = 0 ]
root=$(realpath "$1")
[ "$root" != / ] && [ -d "$root/etc/nassimhub" ]
[ "$(findmnt -n -o TARGET --target "$root")" = "$root" ]
[ "$(findmnt -n -o FSTYPE --target "$root")" = ext4 ]
[ "$(findmnt -n -o LABEL --target "$root")" = rootfs ]
# An alias/bind mount of the running root must never satisfy the offline check.
[ "$(findmnt -n -o MAJ:MIN --target "$root")" != "$(findmnt -n -o MAJ:MIN --target /)" ]
/usr/local/libexec/nassimhub-state-check
base=/var/lib/nassimhub/.private-system
test -d "$base" && test ! -L "$base"
test "$(stat -c '%u:%a' "$base")" = 0:700
for manifest in SHA256SUMS MODES; do
 test -f "$base/$manifest" && test ! -L "$base/$manifest"
 test "$(stat -c '%u:%a' "$base/$manifest")" = 0:600
done
awk '
 NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ { exit 1 }
 $2 !~ /^(etc\/nassimhub\/(agent[.]conf|local-volte[.]enabled|voice-audio[.]verified)|etc\/systemd\/system\/nassimhub-agent[.]service[.]d\/voice[.]conf|etc\/systemd\/system\/rmtfs[.]service[.]d\/80-nassimhub-local-volte[.]conf|etc\/systemd\/system\/nassimhub-(ims|radio)-status[.](service|timer)|etc\/polkit-1\/rules.d\/51-nassimhub-modemmanager-voice[.]rules|usr\/lib\/nassimhub\/(hold-cs-voice|query-ims-status|query-radio-status)|usr\/local\/libexec\/nassimhub\/rmtfs-local-volte|etc\/NetworkManager\/system-connections\/[A-Za-z0-9_-]+[.]nmconnection|var\/lib\/alsa\/asound[.]state)$/ { exit 1 }
 seen[$2]++ { exit 1 }
 END { if (!seen["etc/nassimhub/agent.conf"] || !seen["etc/nassimhub/voice-audio.verified"] || !seen["etc/systemd/system/nassimhub-ims-status.timer"] || !seen["etc/systemd/system/nassimhub-radio-status.timer"]) exit 1 }
' "$base/SHA256SUMS"
list=$(mktemp)
trap 'rm -f "$list"' EXIT
while read -r hash relative; do
 path=$(realpath "$base/$relative")
 [ "$path" = "$base/$relative" ]
 test -f "$path" && test ! -L "$path"
 test "$(stat -c '%u:%a' "$path")" = 0:600
 destination=$(realpath -m "$root/$relative")
 case "$destination" in "$root"/*) ;; *) exit 1;; esac
 mode=$(awk -v file="$relative" '$2==file {print $1}' "$base/MODES")
 case "$mode" in 600|640|644|700|750|755) ;; *) exit 1;; esac
 printf '%s %s\n' "$mode" "$relative" >> "$list"
done < "$base/SHA256SUMS"
(cd "$base" && sha256sum --status -c SHA256SUMS)
# All sources have been verified before the first write. Interrupted restores
# may be rerun before boot. No command reloads or restarts the running system.
while read -r mode relative; do
 mkdir -p "$root/$(dirname "$relative")"
 install -m "$mode" "$base/$relative" "$root/$relative.nsh-restore"
 mv "$root/$relative.nsh-restore" "$root/$relative"
 cmp -s "$base/$relative" "$root/$relative"
done < "$list"
mkdir -p "$root/etc/systemd/system/timers.target.wants"
for timer in nassimhub-ims-status nassimhub-radio-status; do
 test -f "$root/etc/systemd/system/$timer.timer"
 ln -sf "../$timer.timer" "$root/etc/systemd/system/timers.target.wants/$timer.timer"
done
echo 'Same-device settings restored into offline rootfs; hardware acceptance still required.'
