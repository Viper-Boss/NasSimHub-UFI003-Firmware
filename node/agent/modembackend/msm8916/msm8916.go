// Package msm8916 contains the Qualcomm MSM8916 / UFI003 modem backend.
// It can observe status through an already-active ModemManager service, but
// it cannot start the modem or claim unverified SMS, data or voice support.
// No code in this package writes modem firmware or device-unique NV data.
package msm8916

import (
	"context"
	"sync"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/modembackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// unimplemented is the single reason string every stub method carries, so a
// caller reading a log can tell a stub from a genuine hardware failure.
const unimplemented = "msm8916 backend is an interface stub; hardware bring-up is a later stage"

// Options configures the backend. The fields exist so the eventual
// implementation has somewhere to put its configuration without changing the
// constructor's shape, and so the command line that will drive real hardware
// can be written and tested now.
type Options struct {
	// ModemManagerBus is the D-Bus address to use once ModemManager is
	// available on the device. Empty means the system bus.
	ModemManagerBus string
	// QMIDevice is the QRTR/QMI node, for example /dev/wwan0qmi0. It is
	// recorded, never opened, in this stage.
	QMIDevice string
	// AudioCard is the ALSA card that will carry call audio once q6voice is
	// running. Recorded, never opened, in this stage.
	AudioCard string
	// Now is injectable for tests.
	Now func() time.Time
	// ReadOnly enables ModemManager status queries. It never starts, enables,
	// resets or configures the modem; unavailable services remain offline.
	ReadOnly        bool
	SMSWrite        bool
	VoiceWrite      bool
	VoiceAudioReady func(context.Context) bool
	SMSStateDir     string
	SMSBus          SMSBus
	// IMSProfilePath is a device-local marker for a separately verified modem profile.
	// Empty uses the production path. A generic firmware image must not ship it.
	IMSProfilePath string
	// RunQMI is injectable for IMS registration tests.
	RunQMI func(context.Context) (string, error)
	// Run is injectable for tests. The production runner executes mmcli only.
	Run func(context.Context, ...string) (string, error)
	// RunBusctl reads individual D-Bus call properties. The target mmcli 1.22
	// crashes when querying an existing call object, so call details bypass it.
	RunBusctl func(context.Context, ...string) (string, error)
}

// Backend is a status-only observer until radio functions pass hardware tests.
type Backend struct {
	options       Options
	now           func() time.Time
	run           func(context.Context, ...string) (string, error)
	runBusctl     func(context.Context, ...string) (string, error)
	smsMu         sync.Mutex
	voiceMu       sync.Mutex
	imsMu         sync.Mutex
	imsAt         time.Time
	imsState      proto.Tristate
	imsVoiceState proto.Tristate
}

// New builds the stub. It performs no device access of any kind, so it is safe
// to construct on any host, including one with no modem attached at all.
func New(options Options) *Backend {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	run := options.Run
	if run == nil {
		run = runMMCLI
	}
	runBusctl := options.RunBusctl
	if runBusctl == nil {
		runBusctl = runBusctlReadOnly
	}
	return &Backend{options: options, now: now, run: run, runBusctl: runBusctl}
}

func (b *Backend) Name() string {
	if b.options.ReadOnly {
		return "msm8916-modemmanager-observer"
	}
	return "msm8916-stub"
}

func (b *Backend) Close() error { return nil }

// Capabilities reports an honestly empty capability set.
//
// Every radio capability is false and VoLTE is unknown. A Node running this
// backend is discoverable, pairable and observable, and can do nothing else -
// which is the correct description of an MSM8916 whose modem stack has not
// been brought up.
func (b *Backend) Capabilities(ctx context.Context) (proto.Capabilities, error) {
	smsReady := b.options.SMSWrite && b.options.ReadOnly && b.readOnlyStatus(ctx).SIM.State == proto.SIMReady
	volte := b.imsRegistration(ctx)
	voiceReady := b.options.ReadOnly && b.options.VoiceWrite && b.options.VoiceAudioReady != nil && b.options.VoiceAudioReady(ctx) && b.imsVoiceReady(ctx)
	return proto.Capabilities{
		SMS:              smsReady,
		MobileData:       false,
		VoiceControl:     voiceReady,
		VoiceAudio:       voiceReady,
		VoLTE:            volte,
		WiFiProvisioning: false,
		Logs:             true,
		OTA:              false,
	}, nil
}

// GetStatus reports the observed modem state or an offline fallback.
//
// This is the one method that must never error: Core polls it to decide whether
// a Node is reachable, and a Node whose radio is not up is still a Node whose
// pairing, version and connection type the NAS needs to display.
func (b *Backend) GetStatus(ctx context.Context) (proto.ModemStatus, error) {
	if b.options.ReadOnly {
		return b.readOnlyStatus(ctx), nil
	}
	observed := b.now().UTC()
	return proto.ModemStatus{
		State:  proto.ModemOffline,
		Reason: unimplemented,
		SIM:    proto.SIMInfo{State: proto.SIMUnknown, ObservedAt: observed},
		Network: proto.NetworkStatus{
			Registration:     proto.RegUnknown,
			AccessTechnology: proto.AccessUnknown,
			ObservedAt:       observed,
		},
		Signal:     proto.Signal{Known: false, ObservedAt: observed},
		ObservedAt: observed,
	}, nil
}

func (b *Backend) GetSIMInfo(ctx context.Context) (proto.SIMInfo, error) {
	if b.options.ReadOnly {
		return b.readOnlyStatus(ctx).SIM, nil
	}
	return proto.SIMInfo{State: proto.SIMUnknown, ObservedAt: b.now().UTC()}, nil
}

func (b *Backend) GetNetwork(ctx context.Context) (proto.NetworkStatus, error) {
	if b.options.ReadOnly {
		return b.readOnlyStatus(ctx).Network, nil
	}
	return proto.NetworkStatus{
		Registration:     proto.RegUnknown,
		AccessTechnology: proto.AccessUnknown,
		ObservedAt:       b.now().UTC(),
	}, nil
}

func (b *Backend) GetSignal(ctx context.Context) (proto.Signal, error) {
	if b.options.ReadOnly {
		return b.readOnlyStatus(ctx).Signal, nil
	}
	return proto.Signal{Known: false, ObservedAt: b.now().UTC()}, nil
}

func (b *Backend) ListSMS(ctx context.Context) ([]proto.SMS, error) {
	if b.options.ReadOnly {
		return b.listReadOnlySMS(ctx)
	}
	return nil, proto.NotSupported("list_sms", unimplemented)
}

func (b *Backend) SendSMS(ctx context.Context, request proto.SendSMSRequest) (proto.SendSMSResponse, error) {
	if !b.options.SMSWrite {
		return proto.SendSMSResponse{}, proto.NotSupported("send_sms", unimplemented)
	}
	return b.sendRealSMS(ctx, request)
}

func (b *Backend) DeleteSMS(ctx context.Context, id string) error {
	if !b.options.SMSWrite {
		return proto.NotSupported("delete_sms", unimplemented)
	}
	return b.deleteRealSMS(ctx, id)
}

func (b *Backend) ListCalls(ctx context.Context) ([]proto.Call, error) {
	if b.options.ReadOnly {
		if b.options.Run == nil && b.options.RunBusctl == nil {
			return b.listCallsDBus(ctx)
		}
		return b.listReadOnlyCalls(ctx)
	}
	return nil, proto.NotSupported("list_calls", unimplemented)
}

func (b *Backend) Dial(ctx context.Context, request proto.DialRequest) (proto.CallReceipt, error) {
	return b.dialVoice(ctx, request)
}

func (b *Backend) Answer(ctx context.Context, callID string) (proto.CallReceipt, error) {
	return b.answerVoice(ctx, callID)
}

func (b *Backend) Hangup(ctx context.Context, callID string) (proto.CallReceipt, error) {
	return b.hangupVoice(ctx, callID)
}

// GetVoiceCapability distinguishes IMS registration from a usable call audio path.
// The installed device-local profile permits a live IMS check, but the normal
// dial affordance stays disabled until capture and playback are verified.
func (b *Backend) GetVoiceCapability(ctx context.Context) (modembackend.VoiceCapability, error) {
	capabilities, err := b.Capabilities(ctx)
	if err == nil && capabilities.VoiceAudio {
		return modembackend.VoiceCapability{Control: true, Audio: true, VoLTE: capabilities.VoLTE, Source: "q6voice", Reason: "device-local duplex audio acceptance and live controls verified"}, nil
	}
	volte := b.imsRegistration(ctx)
	if volte == proto.TriYes {
		return modembackend.VoiceCapability{
			Control: false,
			Audio:   false,
			VoLTE:   volte,
			Reason:  "IMS is registered and modem-side outbound call signaling was verified; bidirectional host audio is unavailable",
			Source:  "qmi-imsa",
		}, nil
	}
	if b.options.ReadOnly {
		list, err := b.run(ctx, "-K", "-L")
		if err == nil {
			if path := listedModemPath(list); path != "" {
				if _, err := b.run(ctx, "-K", "-m", path, "--voice-status"); err == nil {
					return modembackend.VoiceCapability{
						Control: false,
						Audio:   false,
						VoLTE:   proto.TriUnknown,
						Reason:  "ModemManager call state is readable; IMS registration and bidirectional audio are not verified",
						Source:  "modemmanager",
					}, nil
				}
			}
		}
	}
	return modembackend.VoiceCapability{
		Control: false,
		Audio:   false,
		VoLTE:   proto.TriUnknown,
		Reason:  unimplemented,
		Source:  "stub",
	}, nil
}

var _ modembackend.Backend = (*Backend)(nil)
