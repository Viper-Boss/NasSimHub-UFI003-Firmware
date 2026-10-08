#!/bin/sh
# Install the separate root helper; leaves user SSH disabled on first install.
# Run as root: sh install-system-admin.sh HELPER_BINARY DEPLOY_DIRECTORY
set -eu
[ "$(id -u)" = 0 ] || { echo 'root required' >&2; exit 1; }
[ "$#" = 2 ] || { echo 'usage: install-system-admin.sh HELPER_BINARY DEPLOY_DIRECTORY' >&2; exit 2; }
helper=$1
units=$2
[ -f "$helper" ] && [ ! -L "$helper" ]
for f in /usr/sbin/useradd /usr/sbin/usermod /usr/sbin/userdel /usr/sbin/chpasswd /usr/bin/gpasswd /usr/sbin/sshd /usr/bin/ssh-keygen /usr/bin/sudo; do
 [ -x "$f" ] || { echo "missing dependency: $f (install passwd, openssh-server, openssh-client and sudo)" >&2; exit 1; }
done
getent passwd nassimhub >/dev/null
for unit in nassimhub-system-admin.service nassimhub-user-ssh.service; do
 [ -f "$units/$unit" ] && [ ! -L "$units/$unit" ]
done
# Never modify the maintenance SSH service, root password or authorized keys.
install -d -m 0755 /usr/lib/nassimhub
install -m 0755 "$helper" /usr/lib/nassimhub/nassimhub-system-admin.new
mv /usr/lib/nassimhub/nassimhub-system-admin.new /usr/lib/nassimhub/nassimhub-system-admin
for unit in nassimhub-system-admin.service nassimhub-user-ssh.service; do
 install -m 0644 "$units/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now nassimhub-system-admin.service
systemctl restart nassimhub-system-admin.service
systemctl is-active --quiet nassimhub-system-admin.service
printf '%s\n' 'System administration installed. User SSH remains at its existing setting; first installation is disabled.'
