package msm8916

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/godbus/dbus/v5"
	"github.com/human-agent65535/nassimhub-node/proto"
)

var dtmfDigits = regexp.MustCompile(`^[0-9A-D*#]{1,32}$`)

// ConfigureDTMF is called once, before the HTTP server starts. It cannot enable
// voice control by itself. Generic images keep this false until hardware-tested.
func (b *Backend) ConfigureDTMF(enabled bool, stateDir string) {
	b.options.VoiceDTMF = enabled
	if stateDir != "" {
		b.options.SMSStateDir = stateDir
	}
}

// No tones, phone numbers or hashes of PIN digits are persisted. The durable
// attempt ledger records only request IDs. Repeated IDs are refused even after
// a restart: a timeout might have occurred after the network accepted a tone.
func (b *Backend) SendDTMF(ctx context.Context, id string, request proto.DTMFRequest) (proto.CallReceipt, error) {
	const op = "dtmf"
	if err := b.voiceEnabled(op); err != nil {
		return proto.CallReceipt{}, err
	}
	if !b.options.VoiceDTMF {
		return proto.CallReceipt{}, proto.NotSupported(op, "DTMF has not been enabled for this modem profile")
	}
	if !requestKey.MatchString(request.RequestID) || !dtmfDigits.MatchString(request.Digits) {
		return proto.CallReceipt{}, proto.InvalidArgument(op, "invalid call id, request_id or DTMF sequence")
	}
	path, service, err := b.resolveCallID(ctx, op, id)
	if err != nil {
		return proto.CallReceipt{}, err
	}
	b.voiceMu.Lock()
	defer b.voiceMu.Unlock()
	var selected proto.Call
	var send func() error
	if b.options.DTMFCommand != nil {
		calls, err := b.ListCalls(ctx)
		if err != nil {
			return proto.CallReceipt{}, err
		}
		for _, call := range calls {
			if call.ID == id {
				selected = call
			}
		}
		send = func() error { return b.options.DTMFCommand(ctx, path, request.Digits) }
	} else {
		conn, err := activeBus(ctx)
		if err != nil {
			return proto.CallReceipt{}, proto.Unavailable(op, "ModemManager is unavailable", err)
		}
		object := conn.Object(service, dbus.ObjectPath(path))
		var props map[string]dbus.Variant
		if err = object.CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", dbus.FlagNoAutoStart, callInterface).Store(&props); err != nil {
			return proto.CallReceipt{}, proto.Unavailable(op, "cannot read selected call", err)
		}
		selected, err = commandCallFromProperties(path, props)
		if err != nil {
			return proto.CallReceipt{}, proto.Unavailable(op, "invalid selected call", err)
		}
		send = func() error {
			return object.CallWithContext(ctx, callInterface+".SendDtmf", dbus.FlagNoAutoStart, request.Digits).Err
		}
	}
	if selected.ID == "" {
		return proto.CallReceipt{}, proto.NotFound(op, "call does not exist")
	}
	if selected.State != proto.CallActive {
		return proto.CallReceipt{}, proto.FailedPrecondition(op, "DTMF requires an active call")
	}
	ledger := filepath.Join(filepath.Dir(b.smsStatePath()), "dtmf-requests.json")
	data, err := os.ReadFile(ledger)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return proto.CallReceipt{}, proto.Unavailable(op, "cannot read DTMF attempt ledger", err)
	}
	attempts := map[string]bool{}
	if len(data) > 1<<20 || (len(data) > 0 && json.Unmarshal(data, &attempts) != nil) || attempts == nil {
		return proto.CallReceipt{}, proto.FailedPrecondition(op, "DTMF attempt ledger is invalid")
	}
	if attempts[request.RequestID] {
		return proto.CallReceipt{}, proto.Unavailable(op, "DTMF request was already attempted; result uncertain, do not retry", nil)
	}
	if len(attempts) >= 10000 {
		return proto.CallReceipt{}, proto.FailedPrecondition(op, "DTMF attempt ledger is full; administrator maintenance required")
	}
	if err := ctx.Err(); err != nil {
		return proto.CallReceipt{}, proto.Unavailable(op, "DTMF request cancelled before dispatch", err)
	}
	attempts[request.RequestID] = true
	// Commit before dispatch, with file and directory fsync. A failed commit
	// never reaches the modem; a committed uncertain attempt is never replayed.
	encoded, _ := json.Marshal(attempts)
	if err = saveDTMFLedger(ledger, encoded); err != nil {
		return proto.CallReceipt{}, proto.Unavailable(op, "cannot commit DTMF attempt before dispatch", err)
	}
	if err = send(); err != nil {
		var remote dbus.Error
		if errors.As(err, &remote) && remote.Name == "org.freedesktop.ModemManager1.Error.Core.Unsupported" {
			return proto.CallReceipt{}, proto.NotSupported(op, "the modem rejected DTMF as unsupported")
		}
		return proto.CallReceipt{}, proto.Unavailable(op, "DTMF result uncertain; do not retry", err)
	}
	return proto.CallReceipt{RequestID: request.RequestID, CallID: id, State: proto.CallActive}, nil
}

func saveDTMFLedger(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".dtmf-attempts-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
