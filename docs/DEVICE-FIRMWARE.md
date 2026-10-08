# Device-owned firmware during a system replacement

The generic Factory image contains the loading code, not proprietary modem
or WCNSS payloads, Wi-Fi calibration, modem NV, passwords or device identities.
The owner must preserve their own device files before replacing its rootfs.

`nassimhub-device-firmware.service` waits for NSHSTATE and runs before rmtfs,
ModemManager, NetworkManager and the Agent. Its loader accepts only the modem,
WCNSS and three prima configuration/calibration filenames from a root-owned
0700 `.private-firmware` directory. Each file and SHA256SUMS must be root-owned
0600, with no symlink components. All names, hashes and existing destination
contents are checked before installing files. Differing existing firmware is
refused; the loader never stops a running radio or writes NV partitions.

`--check` validates the preserved bundle without installing or restarting
anything. Missing owner firmware is reported as unprovisioned, not provisioned
with someone else's calibration. Files installed into `/usr/lib/firmware`
remain private to that device and must not be included in a redistributed
rootfs snapshot.

## Verification boundary

The loader has isolated execution tests for successful/idempotent loading,
corruption, path escape, duplicates, symlinks, writable bundles, conflicting
installed firmware and absent bundles. Its check mode has also validated the
preserved bundle on the development device without restarting the radio.

Kernel remoteproc autoload may run before NSHSTATE is mounted. The separate
`nassimhub-radio-resume.service` runs after the verified firmware loader and
rmtfs. It checks the installed payload hashes and starts only the known modem
and WCNSS processors if their state is `offline`. It never stops a running
processor or restarts a crashed one. Its five isolated tests cover those
boundaries. In r138, an owner-restored Debian 13 candidate booted on one
UFI003 and recovered both processors; USB, Wi-Fi and the voice card survived
a normal reboot. This is evidence for that device, not all UFI003 variants.

The development device's verified voice holder, Agent settings, rmtfs profile
selection, ALSA state (if present), voice authorization, status probes and Wi-Fi
connection settings are separately preserved in its root-only private state.
The rescue-side `scripts/restore-local-profile.sh OFFLINE_ROOTFS_MOUNT`
restores a verified root-only `.private-system` bundle into a mounted ext4
rootfs labelled `rootfs`. It rejects the running root device, paths outside the
mounted root, unapproved filenames, bad hashes and unsupported modes before
writing. It enables the restored IMS/radio timers without touching running
services. Interrupted restores must be completed before booting that rootfs.
The helper has isolated positive and corruption/mode rejection checks. An
owner-restored r138 candidate has also completed a real outgoing call with
non-silent downlink PCM. Incoming calls and browser duplex audio on the new
image still require acceptance.
An upgrade must restore and validate these settings locally before declaring
VoLTE, DTMF or Wi-Fi accepted. No generic voice enable marker is shipped.
