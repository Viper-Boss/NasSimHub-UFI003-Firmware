#!/bin/sh
set -eu
# Usage: sudo sh install-voice.sh /path/to/agent-arm64 /path/to/holder-arm64
[ "$(id -u)" = 0 ] || { echo 'root required' >&2; exit 1; }
[ "$#" = 2 ] || { echo 'usage: install-voice.sh AGENT HOLDER' >&2; exit 1; }
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test "$(uname -m)" = aarch64
grep -q nassimhub-ufi003 /proc/asound/cards
test -f /etc/nassimhub/local-volte.enabled
"$1" -config /etc/nassimhub/agent.conf -voice-media -check-config
backup=/var/backups/nassimhub-voice-$(date +%Y%m%d-%H%M%S)
mkdir -p "$backup"
cp -a /usr/bin/nassimhub-agent "$backup/agent"
cp -a /etc/nassimhub/agent.conf "$backup/agent.conf"
cp -a /etc/systemd/system/nassimhub-agent.service.d "$backup/service.d"
echo "backup: $backup"
systemctl stop nassimhub-agent
mkdir -p /usr/lib/nassimhub /etc/systemd/system/nassimhub-agent.service.d
install -m 0755 "$1" /usr/bin/nassimhub-agent
install -m 0755 "$2" /usr/lib/nassimhub/hold-cs-voice
install -m 0755 "$here/query-ims-status" /usr/lib/nassimhub/query-ims-status
install -m 0644 "$here/nassimhub-ims-status.service" /etc/systemd/system/nassimhub-ims-status.service
install -m 0644 "$here/nassimhub-ims-status.timer" /etc/systemd/system/nassimhub-ims-status.timer
install -m 0644 "$here/51-nassimhub-modemmanager-voice.rules" /etc/polkit-1/rules.d/51-nassimhub-modemmanager-voice.rules
install -m 0644 "$here/nassimhub-agent-voice.conf" /etc/systemd/system/nassimhub-agent.service.d/voice.conf
chown root:nassimhub /etc/nassimhub/local-volte.enabled
chmod 0640 /etc/nassimhub/local-volte.enabled
systemctl daemon-reload
install -m 0755 "$here/query-radio-status" /usr/lib/nassimhub/query-radio-status
install -m 0644 "$here/nassimhub-radio-status.service" /etc/systemd/system/nassimhub-radio-status.service
install -m 0644 "$here/nassimhub-radio-status.timer" /etc/systemd/system/nassimhub-radio-status.timer
systemctl daemon-reload
systemctl enable --now nassimhub-ims-status.timer nassimhub-radio-status.timer
systemctl restart nassimhub-agent
systemctl is-active nassimhub-agent
# Identity, pairing records, NV and boot are never changed by this installer.
