# Initial source publication validation

Hardware baseline was read from the running device: Debian 13.1 / Linux 6.12.49-msm8916-g93a71ee9468d.
Mixed WPA2/WPA3 hotspot discovery selected WPA2; the production unprivileged backend connected successfully, saved its credential and reactivated using the saved profile. USB remained available. No password, address of the private Wi-Fi LAN or device identity is included here.

Kernel audio changes were previously compiled and tested on the target board. Actual 16 kHz PCM downlink and uplink were tested on one carrier/SIM combination. This is not a blanket carrier compatibility claim.

The sanitized publication tree passed all agent/proto/xport go test and go vet checks, including the mixed-mode Wi-Fi regression. A new static Linux arm64 Agent was built from that tree and its default configuration validated. Boot-tool structure/roundtrip and dirty-rootfs rejection tests passed. Source privacy review found no private phone numbers, LAN details, per-device identity, passwords, tokens or private keys in the staged files. Build host paths are excluded from the Agent by trimpath.

The published tree contains no prebuilt factory firmware; boot and rootfs packaging require independently reviewed clean inputs. The offline packager is a developer skeleton, not a fully boot-tested factory recipe. Full browser calls and update/recovery acceptance remain in the roadmap.

# Factory/OTA packaging round (reproducible build, generic package, agent updates)

## What was checked, and where

Everything in this section was run **offline in a build container, on synthetic inputs and with throw-away keys**. None of it is a device result.

| Check | Command | What a pass means |
|---|---|---|
| Reproducible agent build | `sh scripts/test-reproducible-build.sh` | Two builds of the same source (different checkout path, empty build cache) are byte-identical; no build-host path in the binary; the version reported under qemu-user emulation is the requested one |
| OTA packaging | `sh scripts/test-package-ota.sh` | Unsigned manifest without keys; key directory inside a repository refused; signed (dual-signed on Go >= 1.27) manifest verifies against the public key file; a tampered artifact, a tampered manifest, an untrusted key, a classical-only signature under `-require-pq` and a private key offered as the public key file are all refused |
| Factory packaging | `sh scripts/test-package-factory.sh` (root, e2fsprogs) | Lite and Dev packages from a synthetic rootfs and boot header; manifest, checksums, key file ownership and mode inside the image; private key file and dirty rootfs refused |
| Generic-package rules | `python3 scripts/test_tools.py` | Each offender type is planted in a package or rootfs and caught; a clean one passes |
| SBOM and licences | `python3 scripts/sbom.py spdx-coverage`, `sbom.py generate` (run by `build-agent.sh`) | Every linked Go module has a recognised, allowed licence; every file in `scripts/`, `kernel/`, `node/` has an SPDX header or a mapping rule |
| Image policy (polkit grants, capabilities, setup access point switch, telemetry visibility) | `python3 scripts/test_tools.py` (class `ImagePolicyTests`) | See the part B section below |
| Overlay unit and polkit rule syntax and decisions | `sh scripts/test-setup-ap-overlay.sh` | See the part B section below |
| All of the above plus `go test`/`go vet` | `sh scripts/check.sh` | — |

Not covered by any of this: booting a factory image, the exec permission of the state partition, a real update, restart, confirmation or rollback under systemd on the stick, flash wear and memory limits, and key rotation in the field.

## Hardware checklist — 未在真机验证 / not yet verified on hardware

Run on one UFI003_MB_V02 that is already working (identity, pairing, SMS) with a private backup of its boot and system configuration. Record the result of every step; do not record phone numbers, IMEI/ICCID, SMS bodies, keys or passwords. **No step uses the ~5 s power-button hold (9008/EDL) and no step writes modemst1, modemst2, fsg, fsc or persist. If a step seems to need either, stop and report instead.**

Preparation (build host): build two agents from the same tree, `sh scripts/build-agent.sh 1.15.1` (factory) and, in a separate `NSH_BUILD_DIR`, `1.15.2` (update); create throw-away TEST release keys outside every repository with `nsh-release keygen`; export `ota-keys.json`; build the factory package with `NSH_OTA_KEYS`; package and sign the update with `scripts/package-ota.sh 1.15.2 stable agent-1.15.2`.

| # | Step on the device | Expected result | If it fails / how to get back |
|---|---|---|---|
| 1 | Flash/boot the image built WITH `NSH_OTA_KEYS`. `findmnt -no OPTIONS /var/lib/nassimhub` | Options contain `rw,nosuid,nodev` and NOT `noexec` | Drop-in not applied: check `systemctl cat var-lib-nassimhub.mount`. Back: boot the previous image |
| 2 | `stat -c '%U:%G %a' /etc/nassimhub/ota-keys.json /etc/nassimhub /usr/bin/nassimhub-agent`; `sudo -u nassimhub test -w /etc/nassimhub/ota-keys.json; echo $?` | `root:root 644`, `root:root 755`, `root:root 755`; the write test prints `1` | Fix ownership in the image recipe; do not chmod on the device and call it verified |
| 3 | `systemctl show nassimhub-agent -p Restart -p NRestarts`; `journalctl -u nassimhub-agent -b \| grep -i update` | `Restart=always`; a line `updates available: 1 release key(s), ... running the system agent 1.15.1` | A line `updates unavailable: <reason>` names what is wrong |
| 4 | `ls -l /var/lib/nassimhub` after first boot | `device.json` 0600, `device-cert.pem`, `transport-key.json`, `admin-bootstrap.txt` 0600, `admin-tls-*.pem`, and `pq-identity.json` 0600 when the agent was built with Go >= 1.27; all owned by `nassimhub`. Device id identical after a reboot | Do not delete identity files to "retry"; report |
| 5 | Boot an image built WITHOUT keys (or move the key file away as root and restart) | Log: `updates unavailable: no release keys are installed on this device...`; NAS shows the update as unsupported with that reason; mount still `noexec` | Restore the key file / previous image |
| 6 | Happy path: import `manifest.signed.json` and `nassimhub-agent` into the NAS, push, apply | Service restarts once; `readlink /var/lib/nassimhub/agent-releases/current` is `agent-1.15.2`; the NAS shows 1.15.2 and confirms; `sha256sum /usr/bin/nassimhub-agent` is still the factory hash from `BUILDINFO.json`; same device id, pairing intact; SMS still works | `updates = false` in `/etc/nassimhub/agent.conf` + restart runs the factory agent |
| 7 | Unconfirmed update: apply, then make the NAS unreachable (unplug USB/Wi-Fi) before it confirms | Within 10 min (+ up to 30 s) the agent logs the rollback and restarts; `current` is gone or points at the previous release; version back to 1.15.1 | As 6 |
| 8 | Second restart before confirmation: apply, then `systemctl restart nassimhub-agent` before confirming | Start-up log `rolling back the update to 1.15.2`; the update status reports `the new version started and then stopped before it could be confirmed`; the factory/previous agent runs | As 6 |
| 9 | Power loss: apply and cut power immediately; repeat a few times at different moments | Device always comes back with an agent answering the NAS, on the old or the new version, never neither; no manual repair | As 6. A device with no running agent is a blocking failure |
| 10 | Corrupted release: as `nassimhub`, append a byte to `agent-releases/agent-1.15.2/nassimhub-agent`, restart | Log: `release agent-1.15.2 is deselected: ... does not match its signed manifest`; factory agent runs | Remove the release directory; re-push |
| 11 | Untrusted or damaged release: push a release signed with another throw-away key; push one whose signed manifest was edited | Refused at offer; state unchanged; nothing staged | — |
| 12 | Signature policy: set `ota_signature_policy = required`, push a classical-only release, then a dual-signed one | First refused (no valid post-quantum signature), second accepted | Set the policy back to `preferred` |
| 13 | Version rules: push the release that is already running; push an older one | Both refused (`already running` / `older than the running ...`) | — |
| 14 | Factory floor: with release 1.15.2 installed, boot a system image whose factory agent is 1.15.3 | Release not run: `older than the system's own agent`; 1.15.3 runs | Previous image |
| 15 | Resource limits during push/apply: `systemctl show nassimhub-agent -p MemoryPeak -p NRestarts`; `journalctl -k \| grep -i oom`; `df /var/lib/nassimhub` | No OOM kill under `MemoryMax=96M`; restart count below `StartLimitBurst=5` in 120 s; free space left after two releases | Report the numbers; do not raise limits on the device and call it verified |
| 16 | Voice-enabled device only: with the voice drop-in installed, update and confirm | The chained release still runs with `-voice-media` (`systemctl status` shows the release binary and argument); a call still has audio | As 6 |
| 17 | Key rotation: build an image whose key file holds old + new keys, flash, push a release signed with the new key | Accepted; a device still on the old image refuses it | Previous image |
| 18 | Dev variant only: `ls /usr/share/nassimhub/voice-deploy`; `ls /etc/nassimhub` | Sources present; no `*.enabled`/`*.verified` marker; voice not active | — |

Overall rollback for this round: boot the previous boot/rootfs images; the NSHSTATE partition is left as it is, so identity and pairing survive. To discard only the update state, stop the agent and remove `/var/lib/nassimhub/agent-releases`, `ota-staging`, `ota-state.json` and `ota.lock` — never `device.json`, `pq-identity.json`, `pairing.json` or the admin files.

# Part B: setup access point prerequisites and telemetry sources

## What was checked, and where

Offline, in a build container, on the repository's own files and on synthetic trees. **None of it is a device result.** No access point was started, no phone joined anything, no sysfs file of a UFI003 was read.

| Check | Command | What a pass means | What it does not mean |
|---|---|---|---|
| Unit syntax | `sh scripts/test-setup-ap-overlay.sh` (part 1; needs `systemd-analyze`, otherwise prints SKIPPED) | `systemd-analyze verify` (systemd 255 on the build host) reports no unknown key and no unparsable value in the agent unit with its drop-ins, without and with `firmware/setup-ap-overlay/`; a deliberately broken drop-in is reported | That systemd 257 on Debian 13 or the stick's kernel honours every line, `SocketBindDeny=` in particular |
| polkit rule decisions | same script, part 2 (needs `node`, otherwise prints SKIPPED) | Each rule file, run in a JavaScript engine against a stand-in `polkit` object, answers YES for user `nassimhub` and exactly the documented actions and gives no decision for other users and other actions (including `wifi.share.open`, a prefix and a longer form of a granted name); a rule widened to `wifi.share.*` is caught | That polkitd's own engine (duktape) or NetworkManager behave the same; that the documented actions are sufficient for the access point |
| Documented grants are enforced | `python3 scripts/test_tools.py` | `audit-rootfs.py` fails a tree where a rule for the agent user grants an undocumented action, targets another user, has an unrecognised shape or is an undocumented file; where the agent unit has any capability other than (with the switch) `CAP_NET_BIND_SERVICE`, an unexpected drop-in, or runs as root; where a sysctl file lowers `ip_unprivileged_port_start`; where the fragment is present without `--setup-ap` or incomplete with it | — |
| The fragment changes nothing else | `test_fragment_changes_the_capability_and_nothing_else` | The effective unit settings with and without the fragment differ in `CapabilityBoundingSet`, `AmbientCapabilities`, `SocketBindDeny` only | — |
| Packager switch | `sh scripts/test-package-factory.sh` step 6 | Default package: no fragment, `provisioning_ap = off` in the image, manifest `setup access point: not enabled`. `NSH_SETUP_AP=on`: refused without `/usr/sbin/dnsmasq`; with it, both files root:root 0644 in the image, configuration rewritten and accepted by the agent's own `-check-config` (under qemu-user), manifest `setup access point: enabled (not verified on hardware)`; half a fragment in a finished package is caught | That an image built this way starts an access point |
| Telemetry visibility | `test_unit_hardening_hides_no_telemetry_source` | No directive in the packaged unit hides a path the agent samples (table below); the base unit alone would (`ProtectProc=invisible`), the packaged drop-in lifts it | That the files exist on the board or hold sensible values |

## Telemetry sources against the unit hardening

The agent samples as user `nassimhub` inside the unit's sandbox (`node/agent/internal/systemstats/collector.go`, `radio.go`). Effective settings are the base unit `node/deploy/nassimhub-agent.service` plus the drop-ins the image ships (`resources.conf`, `persistent.conf`, and `setup-ap.conf` when enabled). Verdicts are from reading the unit files and systemd's documented semantics, **not from a device**.

| Source the agent reads | Directive that could matter | Verdict |
|---|---|---|
| `/sys/class/thermal/thermal_zone*/{temp,type}` | `ProtectKernelTunables=yes` makes `/sys` read-only; `ProtectSystem=strict` likewise | Not hidden: read-only is enough, the files are world-readable |
| `/sys/devices/system/cpu/{present,online}`, `cpuN/cpufreq/{scaling_cur_freq,cpuinfo_min_freq,cpuinfo_max_freq}` | same | Not hidden. (`cpuinfo_cur_freq` is root-only on Linux; the agent does not read it) |
| `/sys/block/mmcblk0/device/{life_time,pre_eol_info}` | `PrivateDevices=yes` | Not hidden: `PrivateDevices` replaces `/dev`, not `/sys`; these are sysfs attributes, not device nodes |
| `/proc/net/dev` | `ProtectProc=`, `ProcSubset=`, `PrivateNetwork=` | Not hidden: `ProcSubset` is not set (default `all`); `PrivateNetwork` is not set, so the file lists the host's interfaces; `ProtectProc` only concerns `/proc/<pid>` |
| `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/cpuinfo`, `/proc/uptime`, `/proc/sys/kernel/random/boot_id` | `ProcSubset=`, `ProtectKernelTunables=yes` (`/proc/sys` read-only) | Not hidden |
| `/proc/<pid>/status` of every process (process count, memory) | `ProtectProc=invisible` in the base unit | **Would be hidden** for processes of other users. Already lifted, narrowly, by `node/deploy/nassimhub-agent-resources.conf` (`ProtectProc=default`), which the packager installs as `resources.conf`. No change proposed; the checklist confirms the drop-in is in effect |
| `/run/nassimhub-ims/radio.metrics` | `ProtectSystem=strict` (read-only `/run`), `PrivateTmp=yes` | Not hidden: `/run` stays visible and readable; the directory and file are 0755/0644 (`query-radio-status`, `umask 022`) |
| `statfs` of `/` and `/var/lib/nassimhub` | `SystemCallFilter=@system-service` | Allowed (`@system-service` includes `@file-system`) |

No directive blocks a source, so **no hardening change is proposed**. One finding that is not about hardening: `/run/nassimhub-ims/radio.metrics` is written by `nassimhub-radio-status.timer`, which only `node/deploy/audio/install-voice.sh` installs, per device. A factory image (Lite or Dev) does not have it, so on such a device band, EARFCN, PCI, TAC and cell id are reported as unknown. Shipping that timer in the image is a decision for the Node owner (it issues two QMI queries every 15 s) and was not made here.

## Hardware checklist A — setup access point prerequisites — 未在真机验证 / not yet verified on hardware

Use an image built with `NSH_SETUP_AP=on` (its `PACKAGE-MANIFEST.json` says `setup access point: enabled (not verified on hardware)`) on a stick whose USB link works. **The way back for every step is the USB link** (`https://10.55.0.2:7581`, the root maintenance shell on 10.55.0.2), which nothing here touches. To turn the access point off at any time: set `provisioning_ap = off` in `/etc/nassimhub/agent.conf`, `systemctl restart nassimhub-agent`, and if it is up `nmcli connection down id nassimhub-setup-ap`. **No step uses the ~5 s power-button hold (9008/EDL); no step writes modemst1, modemst2, fsg, fsc or persist.** Do not copy the access point passphrase, a router password or a device id into the record.

Run as root on the device unless stated. `pid=$(systemctl show -p MainPID --value nassimhub-agent)`.

| # | Command | Expected | If not / how to get back |
|---|---|---|---|
| A1 | `grep -E '^provisioning(_ap)? ' /etc/nassimhub/agent.conf` | `provisioning = true`, `provisioning_ap = auto` | Image was built without the switch: use A14 instead |
| A2 | `stat -c '%U:%G %a %n' /etc/polkit-1/rules.d/48-nassimhub-setup-ap.rules /etc/systemd/system/nassimhub-agent.service.d/setup-ap.conf` | both `root:root 644` | Rebuild the image; do not create the files by hand and call it verified |
| A3 | `command -v pkaction && pkaction --action-id org.freedesktop.NetworkManager.wifi.share.protected` | The action id is printed (polkitd is installed and NetworkManager's policy is registered) | No polkitd: none of the overlay's polkit rules work, including the ones Wi-Fi joining needs. Record and stop |
| A4 | `runuser -u nassimhub -- nmcli -t general permissions` | `…wifi.share.protected:yes`, `…network-control:yes`, `…settings.modify.system:yes`, `…wifi.scan:yes`. `…wifi.share.open` is **not** `yes`; `…enable-disable-network`, `…enable-disable-wifi`, `…settings.modify.hostname`, `…settings.modify.global-dns` are **not** `yes` | `share.protected` not `yes`: the rule is not applied (`journalctl -u polkit -b` for a rule syntax error). Anything else `yes` that the table in RELEASING.md §11.2 does not list: record it as a finding, another rule on the image grants it |
| A5 | `systemctl show nassimhub-agent -p User -p NoNewPrivileges -p CapabilityBoundingSet -p AmbientCapabilities -p SocketBindDeny` | `User=nassimhub`, `NoNewPrivileges=yes`, both capability lines exactly `cap_net_bind_service`, three `SocketBindDeny` rules (tcp 1-79, tcp 81-1023, udp 1-1023) | Drop-in not applied: `systemctl cat nassimhub-agent` |
| A6 | `grep '^Cap' /proc/$pid/status` | `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb` all `0000000000000400` (bit 10, CAP_NET_BIND_SERVICE) and nothing else | Any other bit set is a blocking finding |
| A7 | `journalctl -b \| grep -i -E 'bpf\|socket.*bind'`; then, if `python3` is on the image: `systemd-run --wait --pipe -p User=nassimhub -p AmbientCapabilities=CAP_NET_BIND_SERVICE -p CapabilityBoundingSet=CAP_NET_BIND_SERVICE -p SocketBindDeny=tcp:1-79 -p SocketBindDeny=tcp:81-1023 python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",81)); print("bound 81")'` | No BPF warning in the journal, and the bind fails with a permission error: the deny rules are enforced. If it prints `bound 81`, or the journal says socket binding restrictions are unsupported, the kernel lacks cgroup BPF | Not a blocker for the access point. Record which case it is: without enforcement the agent may bind any port below 1024 (KNOWN_ISSUES 21) |
| A8 | `command -v dnsmasq; dpkg -s dnsmasq-base \| grep '^Status'; systemctl is-enabled dnsmasq 2>&1` | `/usr/sbin/dnsmasq`; `install ok installed`; the last command says the unit does not exist (the full `dnsmasq` service must not be installed) | Missing: the image recipe lacks `dnsmasq-base` |
| A9 | `iw list \| sed -n '/Supported interface modes/,/Band 1/p'` | The list contains `AP` | Without `AP` the radio cannot be an access point at all; expect `AP_FAILED`. Record it; A10-A13 do not apply |
| A10 | With no saved Wi-Fi network (forget it in the console over USB), wait up to 90 s. `nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device`; `ip -br addr show wlan0`; `ss -ltnp \| grep ':80 '`; `journalctl -u nassimhub-agent -b \| grep -E 'provisioning\|cannot listen'` | `wlan0:wifi:connected:nassimhub-setup-ap`; `192.168.4.1/24` on wlan0; a listener on `192.168.4.1:80` owned by `nassimhub-agent`; state transitions ending in `AP_READY`; **no** line `the access point is up but the setup page cannot listen` | `AP_FAILED`: copy `provisioning_reason` (it never contains the passphrase) and the NetworkManager lines of `journalctl -u NetworkManager -b`; the agent retries with backoff, USB keeps working. `cannot listen`: A5/A6 were not as expected |
| A11 | From a phone: join the access point (passphrase read over USB from `/var/lib/nassimhub/setup-ap-passphrase`), open `http://192.168.4.1/`. On the device: `pgrep -a dnsmasq` | Phone reports WPA2, gets a `192.168.4.x` address, the setup page opens; a `dnsmasq` started by NetworkManager for wlan0 is running | Phone joins but gets no address: dnsmasq/NetworkManager shared mode (record `journalctl -u NetworkManager -b`). Then continue with the Node repository's `scripts/field-wifi-acceptance.md` from its step 2 |
| A12 | After the device has joined a network through the page: `ss -ltn \| grep ':80 '`; `nmcli -t -f NAME,DEVICE connection show --active` | No listener on port 80; `nassimhub-setup-ap` not active | A listener that stays is a finding for the Node owner |
| A13 | With an agent update installed (checklist of the previous section, step 6): repeat A6 on the new main PID, and A10 after forgetting the network | Same capability bits in the chained release; the page still listens | The ambient capability did not survive the exec: report; `updates = false` runs the factory agent |
| A14 | Control, on an image built WITHOUT the switch: A2, A4, A5, A6 | Files absent; `wifi.share.protected` not `yes`; both capability lines empty and all `Cap*` values `0000000000000000`; Wi-Fi status shows `provisioning_state` absent or `DISABLED`; no `nassimhub-setup-ap` profile ever created | Anything else means the default image is not the default |

Rollback for this checklist: `provisioning_ap = off` + `systemctl restart nassimhub-agent` stops every access point command; `nmcli connection delete id nassimhub-setup-ap` removes the profile NetworkManager stored; flashing an image built without `NSH_SETUP_AP` removes the two files. Identity, pairing and the saved Wi-Fi network are not touched by any of these. The passphrase file stays on the state partition; removing it only makes the device generate a new one.

## Hardware checklist B — telemetry sources — 未在真机验证 / not yet verified on hardware

Read-only. The point is to read each source **the way the agent does**: as `nassimhub`, inside the service's mount namespace, so the unit's sandbox applies. On the device as root:

~~~sh
pid=$(systemctl show -p MainPID --value nassimhub-agent)
in_unit() { nsenter -t "$pid" -m -- runuser -u nassimhub -- "$@"; }
~~~

| # | Command | Expected | If not |
|---|---|---|---|
| B1 | `systemctl show nassimhub-agent -p ProtectProc -p ProcSubset -p PrivateNetwork -p PrivateDevices -p ProtectKernelTunables` | `ProtectProc=default`, `ProcSubset=all`, `PrivateNetwork=no`, `PrivateDevices=yes`, `ProtectKernelTunables=yes` | `ProtectProc=invisible`: `resources.conf` is missing from the image |
| B2 | `in_unit sh -c 'for z in /sys/class/thermal/thermal_zone*; do echo "$z $(cat $z/type) $(cat $z/temp)"; done'` | One line per zone, temperature in millidegrees. A zone that errors or reports a value outside -40000..150000 is skipped by the agent, not shown as 0 °C | `Permission denied` on a file root can read: record `ls -l` of it and the directive list from B1; do not relax the unit on the device |
| B3 | `in_unit sh -c 'cd /sys/devices/system/cpu; cat present online; cat cpu0/cpufreq/scaling_cur_freq cpu0/cpufreq/cpuinfo_min_freq cpu0/cpufreq/cpuinfo_max_freq'` | CPU lists and three frequencies in kHz | No `cpufreq` directory: the kernel has no cpufreq driver for this board; the fields stay unknown, which is correct |
| B4 | `cat /sys/block/mmcblk0/device/type; in_unit cat /sys/block/mmcblk0/device/life_time /sys/block/mmcblk0/device/pre_eol_info` | `MMC`; two hex bytes (for example `0x01 0x01`) and one (`0x01`) | `No such file`: the eMMC is older than 5.0 or is not `mmcblk0`; the agent reports no eMMC health. Record `ls /sys/block` |
| B5 | `in_unit sh -c 'cat /proc/net/dev'` and, as root, `cat /proc/net/dev` | Identical interface lists (wlan0, the USB interface, the modem's) | A list with only `lo` means a private network namespace: report |
| B6 | `in_unit sh -c 'ls -d /proc/[0-9]* \| wc -l'` and, as root, `ls -d /proc/[0-9]* \| wc -l` | The same number, give or take the processes of the commands themselves | A much smaller number in the unit: `ProtectProc` is not `default` |
| B7 | `systemctl list-timers nassimhub-radio-status.timer; in_unit sh -c 'ls -l /run/nassimhub-ims; cat /run/nassimhub-ims/radio.metrics'` | On a device WITH the voice deployment: `band=`, `earfcn=`, `pci=`, `tac=`, `cell_id=` lines, file younger than 90 s. On a plain factory image: no timer and no file, and the agent reports the cell as unknown (KNOWN_ISSUES 17) | File present but older than 90 s: the timer is failing (`systemctl status nassimhub-radio-status.service`); the agent correctly stops presenting it |
| B8 | In the management console (USB) and on the NAS, look at the device's resource figures | The values of B2-B7 within a sampling interval; every source that was missing above is shown as unknown, never as 0 or as a stale value; no bandwidth is shown for the serving cell | A figure where the source is missing is a blocking finding for the Node/NAS owners |
| B9 | With `NSH_SETUP_AP=on` image: repeat B2-B6 | Same results: the fragment adds a capability, not a sandbox change | Report |

Nothing in checklist B changes the device, so there is nothing to roll back.

# r128: voice installer, rootfs build, release-key statement

## What was checked, and where

Offline only, in a container without a UFI003, without network and without `mmdebstrap`:

- `sh scripts/test-install-voice.sh`: `node/deploy/audio/install-voice.sh` against a directory tree with stand-ins for `systemctl`, `chown`, `id`, `uname` and a shell script as "agent". 23 groups: fresh system, re-run, every single step failing (34 steps keeping the agent, 45 replacing it) with a full restore each time, read-only target, TERM/HUP during the renames, wrong hash, `dev`/unparsable/older candidate, pending update, stored release present. The Node repository's `test/voiceinstall` holds the installer's version reader to `proto.ParseVersion`.
- `python3 scripts/test_rootfs.py`, `sh scripts/test-build-rootfs.sh`: everything `scripts/build-rootfs.sh` does after the bootstrap, and the packager's rootfs provenance and repeatable image, on SYNTHETIC inputs (docs/ROOTFS-BUILD.md section 6 lists what ran and what did not). No Debian system was bootstrapped; nothing produced boots.
- `sh scripts/test-publish-keys.sh`: `release-keys.json` from throw-away keys.

None of the following was done: running the installer on a stick, a real bootstrap from snapshot.debian.org, booting a rootfs built by this recipe, flashing anything.

## Hardware checklist C — voice installer — 未在真机验证 / not yet verified on hardware

On a device that already passed the per-device voice acceptance (docs/INSTALL.md). Never set `NSH_ROOT` or `NSH_INSTALL_VOICE_SANDBOX` on a device. Record every output.

| # | Step | Expected | If not |
|---|---|---|---|
| C1 | `sha256sum /usr/bin/nassimhub-agent; /usr/bin/nassimhub-agent -version; readlink /var/lib/nassimhub/agent-releases/current; cat /var/lib/nassimhub/ota-state.json` | Recorded as the "before" state | — |
| C2 | `sudo sh install-voice.sh /path/agent /path/holder` (the old two-file form) | Refused with the explanation of the new form; `systemctl is-active nassimhub-agent` still `active`; C1 values unchanged | The agent was stopped or replaced: blocking, report |
| C3 | `sudo sh install-voice.sh /path/holder-arm64` | `system agent kept: /usr/bin/nassimhub-agent <version>`; "after the restart, expected to serve: ..." names the factory agent or the selected release; ends with `installed: voice holder, units, polkit rule and timers` and an `observed:` line | Any failure must end with `the previous state was restored`; check C1 values and that the agent is active. `THE RESTORE IS INCOMPLETE` is blocking: restore from the named backup directory by hand |
| C4 | Repeat C1 | The agent's SHA-256 and version are those of C1; `agent-releases/`, `ota-state.json`, `device.json`, `pairing.json` unchanged (`ls -l --time-style=full-iso`) | Blocking |
| C5 | `systemctl list-timers 'nassimhub-*'`; `ls -l /usr/lib/nassimhub /etc/systemd/system/nassimhub-agent.service.d /etc/polkit-1/rules.d/51-*`; `stat -c '%U:%G %a' /etc/nassimhub/local-volte.enabled` | Both timers listed; holder and probes 0755, units and rule 0644; marker `root:nassimhub 640` | Report |
| C6 | One call and one SMS as before the change | Work as before | The voice path was not meant to change: report with `journalctl -u nassimhub-agent -b` |
| C7 | Does the `observed:` line of C3 name the executable that `systemctl status nassimhub-agent` shows? | Yes (`/usr/bin/nassimhub-agent`, or `.../agent-releases/<id>/nassimhub-agent` when a release is selected) | `observed: not available here`: `readlink /proc/<MainPID>/exe` did not work under this systemd; record it |
| C8 | Only if a replacement is really wanted: build `sh scripts/build-agent.sh <version not lower than C1>`, `sha256sum` it on the build host, then `sudo sh install-voice.sh --replace-agent FILE --expect-sha256 <hex> /path/holder-arm64` | `system agent: <old> -> <new> (sha256 ...)`; afterwards `sha256sum /usr/bin/nassimhub-agent` equals `<hex>`; the previous agent is in `/var/backups/nassimhub-voice-<time>/agent` | A refusal names its reason (hash, `dev`, older, pending update, newer than the selected release); none of them changes anything |
| C9 | With a wrong `--expect-sha256` | Refused, `nothing was changed`; agent never stopped (`systemctl show -p ActiveEnterTimestamp nassimhub-agent` unchanged) | Blocking |
| C10 | The 3-second second look (`NSH_VOICE_SETTLE_SECONDS`): is 3 s long enough for an agent that fails at start to be seen as failed on the stick? | Decide from `systemd-analyze` / the journal of a deliberately broken drop-in on a test device | Raise the default if not |

Rollback for this checklist: a failed run restores itself. To undo a successful one: restore `agent`, `agent.conf`, `service.d` from `/var/backups/nassimhub-voice-<time>/`, remove the nine installed files if they did not exist before, `systemctl daemon-reload`, restart the agent. Never touch `/var/lib/nassimhub`.

## Hardware checklist D — rootfs built from the lock — 未在真机验证 / not yet verified on hardware

The steps are in docs/ROOTFS-BUILD.md: section 4 step 0 (facts to read off a verified device), steps 1-5 (networked build host), section 7 (first boot). Record here, per run: the lock's SHA-256, the snapshot timestamp, `rootfs.tar` and `rootfs.img` SHA-256 of two builds (equal or not, and the `tree-list` diff if not), the `mmdebstrap`/`mke2fs` versions, and the first-boot results. Until two real builds are byte-identical the build is "repeatable by design, not demonstrated".

## Hardware checklist E — release key file of an image

| # | Step | Expected |
|---|---|---|
| E1 | On the device or on the unpacked package: `sha256sum /etc/nassimhub/ota-keys.json` | Equals `keyring.sha256` of the published `release-keys.json` for that image generation |
| E2 | `sh scripts/publish-keys.sh --check release-keys.json ota-keys.json --sha256 <value from the signed tag / announcement>` | `Release key check PASS`; a `RETIRED ... but still trusted` line means the image predates a retirement and should be replaced |
| E3 | On the NAS: the file `MODEMDECK_NASSIMHUB_OTA_KEYS` points to | Same check passes |
