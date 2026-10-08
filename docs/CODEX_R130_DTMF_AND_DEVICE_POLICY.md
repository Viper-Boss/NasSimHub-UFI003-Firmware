# r130: device policy status and optional Node DTMF

This change has source and offline tests. It does not certify a modem, carrier,
browser layout, audio path or deployed image.

## Device policy display

The SIM-node and security pages share one component and their existing theme.
They display `trust.device`, not a prediction based on NAS trust alone. Missing
or offline reports remain unknown. Restart, expiration, missing installation,
monitor mode, mismatch and damaged state have distinct messages in all nine
supported locales. Hardware and local-gate evidence belongs to each subject;
the page must not substitute the aggregate evidence of another device.

## Optional DTMF protocol (minor 1.5)

`POST /v1/calls/{id}/dtmf` accepts `request_id` and `digits`, under the existing
paired bearer authentication and local trust gate. `capabilities.dtmf` is an
additive boolean; absence means unsupported. Existing backend interfaces and
pairing remain compatible. NAS routes Node tones to the selected Node, never
to a host modem. Its existing command journal still handles repeated commands.

The MSM8916 implementation sends ModemManager `Call.SendDtmf` only to an active
call. Valid digits are `0-9 A-D * #`, one to 32 characters. `voice_dtmf` defaults
to false and requires `voice_media`; ordinary images do not advertise support.
The dedicated ledger records opaque request IDs before dispatch, syncs file and
directory, and refuses uncertain attempts after restart. It contains no digit
sequence. Ledger failure prevents dispatch. A repeated ID is never resent, even
if its digits differ. It is bounded to 10,000 attempts and then fails closed;
no automatic deletion weakens restart protection. Administrator maintenance
must account for the NAS command journal and retained request IDs before any
ledger rotation. This is a deliberate release limitation, not an automatic
unlimited-history implementation.

## Hardware acceptance before enabling

Back up the existing Agent and configuration; leave boot, rootfs and NV alone.
Verify normal calls and SMS first. On the same paired device, temporarily set
`voice_dtmf = true` and restart the candidate Agent with rollback ready. Connect
to a carrier IVR and send one non-sensitive menu digit. Confirm its audible
result, not merely an HTTP receipt. Check unsupported modem response, end-call
race, duplicate request, and two-device ownership. Restore false if unsupported.
Never replay an ambiguous attempt automatically. Do not test with banking PINs.

Real browser checks at laptop and narrow widths remain required. The full
factory-image lock and real P2P payload transports are separate pending work.
