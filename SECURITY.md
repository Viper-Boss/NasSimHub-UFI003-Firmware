# Security

Do not upload partition dumps, SIM/IMEI/IMSI/ICCID identifiers, phone numbers, SMS bodies, call recordings, private keys, pairing databases, passwords, tokens or populated NetworkManager profiles. Public issue logs must be redacted before posting.

Report vulnerabilities through GitHub private vulnerability reporting when enabled. Do not post exploit details or credentials in public issues. No default shared password or maintenance SSH key is shipped.

Device identity and management secrets are generated per device and kept on persistent storage. A certificate warning is not a substitute for checking ownership. Keep management interfaces on trusted networks; Internet exposure and carrier-wide VoLTE interoperability have not been validated.

## Release signing keys and updates

Agent updates are accepted only when their manifest is signed by a key in the device's release key file, `/etc/nassimhub/ota-keys.json`. That file holds PUBLIC keys only, is root-owned (0644) and is not writable by the agent's service user, so a fault in the agent cannot add a key and then install something signed with it (`node/agent/ota/keyring.go`). A device without that file trusts no publisher and reports updates as unavailable.

The release PRIVATE keys never exist in this repository, in `build/` or `dist/`, or in any image. `nsh-release keygen` refuses to create a key inside a version-controlled tree, and `scripts/package-ota.sh` refuses a key directory inside one; packaging scripts reject a private key file offered as the public key file. If you find private key material in a published package or image, report it privately as a vulnerability. There is no remote revocation: a compromised release key is retired only by flashing a system image that ships a key file without it (docs/RELEASING.md). Key custody, the published key statement (`release-keys.json`, unsigned), rotation, the limits of revocation and the compromise playbook are in docs/KEY-MANAGEMENT.md; how a security fix reaches a device is in docs/SECURITY-UPDATES.md. No support window has been set.

An update can replace the agent executable and nothing else. It cannot write a boot image, device tree, modem partition or root filesystem (`node/agent/ota/ota.go`). The agent in the system image is never modified and is what the device falls back to; a release is re-verified against the release keys at every start. ML-DSA dual signatures require a Go 1.27 or newer toolchain on both the signing host and the agent build; whether a device demands them is the `ota_signature_policy` setting.

Factory packages are checked to be generic (no device identity, pairing state, administrator password or hash, Wi-Fi credentials, SSH host keys or authorized_keys, device certificates or keys, modem NV/EFS/calibration, IMEI/ICCID/phone numbers, logs, SMS) by `scripts/audit-rootfs.py` and `scripts/privacy-check.py --package`. These checks are pattern-based and do not replace review; their limits are listed in `scripts/genericrules.py`. A factory package is not signed: `SHA256SUMS` is integrity, not authenticity.

What the image lets the unprivileged agent user do beyond its own files is held to a documented list in `scripts/imagepolicy.py` and enforced when a factory package is built: the polkit actions granted to `nassimhub` (three NetworkManager actions and ModemManager messaging), no capability at all, and no system-wide lowering of the privileged-port boundary. The Wi-Fi setup access point is opt-in at packaging time (`NSH_SETUP_AP=on`, default off) and then adds exactly one polkit action (`wifi.share.protected`, never `wifi.share.open`) and one capability (`CAP_NET_BIND_SERVICE`, with the other ports below 1024 denied where the kernel supports it); see docs/RELEASING.md section 11. It is not yet verified on hardware.

The update, rollback and key-file behaviour described here is covered by offline tests only and is not yet verified on hardware (未在真机验证); see docs/VALIDATION.md. Holding the power button for about five seconds enters Qualcomm 9008/EDL; no NasSimHub function is or may be bound to it, and no project script writes modemst1, modemst2, fsg, fsc or persist.
