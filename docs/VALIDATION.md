# Initial source publication validation

Hardware baseline was read from the running device: Debian 13.1 / Linux 6.12.49-msm8916-g93a71ee9468d.
Mixed WPA2/WPA3 hotspot discovery selected WPA2; the production unprivileged backend connected successfully, saved its credential and reactivated using the saved profile. USB remained available. No password, address of the private Wi-Fi LAN or device identity is included here.

Kernel audio changes were previously compiled and tested on the target board. Actual 16 kHz PCM downlink and uplink were tested on one carrier/SIM combination. This is not a blanket carrier compatibility claim.

The sanitized publication tree passed all agent/proto/xport go test and go vet checks, including the mixed-mode Wi-Fi regression. A new static Linux arm64 Agent was built from that tree and its default configuration validated. Boot-tool structure/roundtrip and dirty-rootfs rejection tests passed. Source privacy review found no private phone numbers, LAN details, per-device identity, passwords, tokens or private keys in the staged files. Build host paths are excluded from the Agent by trimpath.

The published tree contains no prebuilt factory firmware; boot and rootfs packaging require independently reviewed clean inputs. The offline packager is a developer skeleton, not a fully boot-tested factory recipe. Full browser calls and update/recovery acceptance remain in the roadmap.
