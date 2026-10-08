# Automatic SIM subscriber number

The modem's `OwnNumbers` property remains the preferred source. On the tested
UFI003 profile, QMI DMS Get MSISDN returned an empty string even though the
active USIM's EF_MSISDN contained the correct number. The legacy SIM directory
was empty. The fallback therefore reads the active USIM application first,
then the legacy SIM directory, using QMI UIM read-only file operations.

The factory overlay installs `nassimhub-sim-number.timer` and its root oneshot
service. Every 30 seconds it confirms the current SIM identity. A successful
number is reused for up to 30 minutes for that exact ICCID, so status polling
does not repeatedly read the raw modem. Cold reads are deferred during calls.
SIM identity is checked again after reading, to discard results if the card
changes mid-query. Missing, locked, empty or malformed records remain unknown.

The unprivileged Agent reads a fresh root-owned cache from
`/run/nassimhub-sim-number/status.json`, accessible only to root and the Agent
group. The cache resides on tmpfs, is written atomically, and is matched against
the SIM which ModemManager currently reports. Neither phone numbers nor SIM
identifiers are printed to the service log or included in release artifacts.

Supported records use the standard ADN number trailer (length, TON/NPI and
BCD digits). Extension records and unsupported numbering types are rejected
rather than truncated. The helper never writes SIM/NV, verifies PINs, changes
provisioning, enables the modem, or resets it. If the card contains no number,
NAS can retain a one-time manual display number associated with that SIM.

For an already installed system, an Agent-only OTA cannot create the systemd
units. Install the two units alongside the updated Agent and enable the timer;
factory overlays include them automatically. Keep the prior Agent and units
available for rollback. Existing boot/rootfs images are not regenerated merely
by modifying these sources.
