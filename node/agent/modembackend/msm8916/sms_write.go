package msm8916

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/human-agent65535/nassimhub-node/proto"
)

const smsService = "org.freedesktop.ModemManager1"
const messagingInterface = "org.freedesktop.ModemManager1.Modem.Messaging"
const smsInterface = "org.freedesktop.ModemManager1.Sms"

var phoneNumber = regexp.MustCompile(`^\+?[0-9]{3,20}$`)
var requestKey = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// SMSBus keeps the modem calls injectable. The production implementation sends
// message text inside D-Bus, never in process arguments or logs.
type SMSBus interface {
	Create(context.Context, string, string, string) (string, error)
	Send(context.Context, string) error
	Delete(context.Context, string, string) error
}

type systemSMSBus struct{}

func activeBus(ctx context.Context) (*dbus.Conn, error) {
	check, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(check, "systemctl", "is-active", "--quiet", "ModemManager.service").Run(); err != nil {
		return nil, errors.New("ModemManager is inactive")
	}
	return dbus.SystemBus()
}
func (systemSMSBus) Create(ctx context.Context, modem, number, text string) (string, error) {
	conn, err := activeBus(ctx)
	if err != nil {
		return "", err
	}
	props := map[string]dbus.Variant{"number": dbus.MakeVariant(number), "text": dbus.MakeVariant(text)}
	var path dbus.ObjectPath
	call := conn.Object(smsService, dbus.ObjectPath(modem)).CallWithContext(ctx, messagingInterface+".Create", dbus.FlagNoAutoStart, props)
	if call.Err != nil {
		return "", errors.New("ModemManager SMS creation failed")
	}
	if err = call.Store(&path); err != nil || !validSMSPath(string(path)) {
		return "", errors.New("ModemManager returned invalid SMS path")
	}
	return string(path), nil
}
func (systemSMSBus) Send(ctx context.Context, path string) error {
	conn, err := activeBus(ctx)
	if err != nil {
		return err
	}
	if err = conn.Object(smsService, dbus.ObjectPath(path)).CallWithContext(ctx, smsInterface+".Send", dbus.FlagNoAutoStart).Err; err != nil {
		return errors.New("ModemManager SMS submission failed")
	}
	return nil
}
func (systemSMSBus) Delete(ctx context.Context, modem, path string) error {
	conn, err := activeBus(ctx)
	if err != nil {
		return err
	}
	if err = conn.Object(smsService, dbus.ObjectPath(modem)).CallWithContext(ctx, messagingInterface+".Delete", dbus.FlagNoAutoStart, dbus.ObjectPath(path)).Err; err != nil {
		return errors.New("ModemManager SMS deletion failed")
	}
	return nil
}

type smsAttempt struct {
	Fingerprint string         `json:"fingerprint"`
	MessageID   string         `json:"message_id"`
	State       proto.SMSState `json:"state"`
}

func (b *Backend) smsStatePath() string {
	if b.options.SMSStateDir != "" {
		return filepath.Join(b.options.SMSStateDir, "sms-requests.json")
	}
	return "/var/lib/nassimhub/sms-requests.json"
}
func loadSMSAttempts(path string) (map[string]smsAttempt, error) {
	records := map[string]smsAttempt{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return records, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("SMS request state exceeds limit")
	}
	if err = json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}
func saveSMSAttempts(path string, records map[string]smsAttempt) error {
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("SMS request state exceeds limit")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sms-requests-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err == nil {
		defer d.Close()
		return d.Sync()
	}
	return err
}
func (b *Backend) smsBus() SMSBus {
	if b.options.SMSBus != nil {
		return b.options.SMSBus
	}
	return systemSMSBus{}
}
func (b *Backend) sendRealSMS(ctx context.Context, req proto.SendSMSRequest) (proto.SendSMSResponse, error) {
	const op = "send_sms"
	if !requestKey.MatchString(req.RequestID) {
		return proto.SendSMSResponse{}, proto.InvalidArgument(op, "invalid request_id")
	}
	if !phoneNumber.MatchString(req.To) {
		return proto.SendSMSResponse{}, proto.InvalidArgument(op, "invalid recipient")
	}
	if strings.TrimSpace(req.Text) == "" || len(req.Text) > 4096 {
		return proto.SendSMSResponse{}, proto.InvalidArgument(op, "invalid text length")
	}
	b.smsMu.Lock()
	defer b.smsMu.Unlock()
	records, err := loadSMSAttempts(b.smsStatePath())
	if err != nil {
		return proto.SendSMSResponse{}, proto.Unavailable(op, "SMS request state is unreadable", err)
	}
	status := b.readOnlyStatus(ctx)
	if status.SIM.State != proto.SIMReady || status.SIM.ICCID == "" {
		return proto.SendSMSResponse{}, proto.FailedPrecondition(op, "SIM identity is unavailable")
	}
	digest := sha256.Sum256([]byte(status.SIM.ICCID + "\x00" + req.To + "\x00" + req.Text))
	fingerprint := hex.EncodeToString(digest[:])
	if previous, ok := records[req.RequestID]; ok {
		if previous.Fingerprint != fingerprint {
			return proto.SendSMSResponse{}, proto.InvalidArgument(op, "request_id was used with different content")
		}
		return proto.SendSMSResponse{RequestID: req.RequestID, MessageID: previous.MessageID, State: previous.State}, nil
	}
	list, err := b.run(ctx, "-K", "-L")
	if err != nil {
		return proto.SendSMSResponse{}, proto.Unavailable(op, "modem list is unavailable", err)
	}
	modem := listedModemPath(list)
	if modem == "" {
		return proto.SendSMSResponse{}, proto.Unavailable(op, "no modem is available", nil)
	}
	path, err := b.smsBus().Create(ctx, modem, req.To, req.Text)
	if err != nil {
		return proto.SendSMSResponse{}, proto.Unavailable(op, "SMS creation failed", err)
	}
	if !validSMSPath(path) {
		return proto.SendSMSResponse{}, proto.Unavailable(op, "SMS path is invalid", nil)
	}
	id := "mm-" + strings.TrimPrefix(path, smsPathPrefix)
	records[req.RequestID] = smsAttempt{fingerprint, id, proto.SMSSending}
	if err = saveSMSAttempts(b.smsStatePath(), records); err != nil {
		return proto.SendSMSResponse{}, proto.Unavailable(op, "SMS request state could not be committed; message was not sent", err)
	}
	// Persist before transmission: a crash or timeout can never cause an automatic double send.
	if err = b.smsBus().Send(ctx, path); err != nil {
		return proto.SendSMSResponse{}, proto.Unavailable(op, "SMS send result is uncertain; retry with the same request_id to inspect the receipt", err)
	}
	records[req.RequestID] = smsAttempt{fingerprint, id, proto.SMSSent}
	if err = saveSMSAttempts(b.smsStatePath(), records); err != nil {
		return proto.SendSMSResponse{RequestID: req.RequestID, MessageID: id, State: proto.SMSSending}, nil
	}
	return proto.SendSMSResponse{RequestID: req.RequestID, MessageID: id, State: proto.SMSSent}, nil
}

// deleteRealSMS removes a visible SMS and its exact SIM/device storage twin.
// The twin goes first, so a partial failure leaves the visible ID available for retry.
func (b *Backend) deleteRealSMS(ctx context.Context, id string) error {
	const op = "delete_sms"
	if !strings.HasPrefix(id, "mm-") || !validSMSPath(smsPathPrefix+strings.TrimPrefix(id, "mm-")) {
		return proto.InvalidArgument(op, "invalid message id")
	}
	list, err := b.run(ctx, "-K", "-L")
	if err != nil {
		return proto.Unavailable(op, "modem list is unavailable", err)
	}
	modem := listedModemPath(list)
	if modem == "" {
		return proto.Unavailable(op, "no modem is available", nil)
	}
	listing, err := b.run(ctx, "-K", "-m", modem, "--messaging-list-sms")
	if err != nil {
		return proto.Unavailable(op, "SMS list is unavailable", err)
	}
	fields := parseKeyValues(listing)
	count, err := smsListCount(fields)
	if err != nil {
		return proto.Unavailable(op, "invalid SMS listing", nil)
	}
	targetPath := smsPathPrefix + strings.TrimPrefix(id, "mm-")
	paths := make([]string, 0, count)
	found := false
	for index := 1; index <= count; index++ {
		path := fields["modem.messaging.sms.value["+strconv.Itoa(index)+"]"]
		if !validSMSPath(path) {
			return proto.Unavailable(op, "invalid SMS path", nil)
		}
		paths = append(paths, path)
		if path == targetPath {
			found = true
		}
	}
	if !found {
		return proto.NotFound(op, "message does not exist")
	}
	raw, err := b.run(ctx, "-K", "-s", targetPath)
	if err != nil {
		return proto.Unavailable(op, "cannot inspect SMS", err)
	}
	target := parseKeyValues(raw)
	storage := printableValue(target["sms.properties.storage"])
	timestamp := target["sms.properties.timestamp"]
	pduType := target["sms.properties.pdu-type"]
	// A missing timestamp cannot distinguish repeated messages with the same text.
	if timestamp != "" && pduType != "" && (storage == "sm" || storage == "me") {
		opposite := "sm"
		if storage == "sm" {
			opposite = "me"
		}
		for _, path := range paths {
			if path == targetPath {
				continue
			}
			raw, err := b.run(ctx, "-K", "-s", path)
			if err != nil {
				return proto.Unavailable(op, "cannot inspect SMS twin", err)
			}
			candidate := parseKeyValues(raw)
			if printableValue(candidate["sms.properties.storage"]) != opposite ||
				candidate["sms.properties.timestamp"] != timestamp ||
				candidate["sms.properties.pdu-type"] != pduType ||
				candidate["sms.content.number"] != target["sms.content.number"] ||
				candidate["sms.content.text"] != target["sms.content.text"] {
				continue
			}
			if err := b.smsBus().Delete(ctx, modem, path); err != nil {
				return proto.Unavailable(op, "SMS twin deletion failed", err)
			}
			break // never delete more than the one cross-storage counterpart
		}
	}
	if err := b.smsBus().Delete(ctx, modem, targetPath); err != nil {
		return proto.Unavailable(op, "SMS deletion failed", err)
	}
	return nil
}
