package msm8916

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
	"github.com/human-agent65535/nassimhub-node/proto/mmclitext"
)

const smsPathPrefix = "/org/freedesktop/ModemManager1/SMS/"

// listReadOnlySMS never sends, stores or deletes a message. ModemManager may
// expose the same received PDU from both SIM (sm) and modem (me) storage; one
// logical message is returned for that exact cross-storage pair.
func (b *Backend) listReadOnlySMS(ctx context.Context) ([]proto.SMS, error) {
	list, err := b.run(ctx, "-K", "-L")
	if err != nil {
		return nil, proto.Unavailable("list_sms", "ModemManager is unavailable", err)
	}
	modemPath := listedModemPath(list)
	if modemPath == "" {
		return nil, proto.Unavailable("list_sms", "no modem is available", nil)
	}
	listed, err := b.run(ctx, "-K", "-m", modemPath, "--messaging-list-sms")
	if err != nil {
		return nil, proto.Unavailable("list_sms", "cannot list modem messages", err)
	}
	fields := parseKeyValues(listed)
	count, err := strconv.Atoi(fields["modem.messaging.sms.length"])
	if err != nil || count < 0 || count > 128 {
		return nil, proto.Unavailable("list_sms", "invalid or excessive SMS listing", nil)
	}
	if count == 0 {
		return []proto.SMS{}, nil
	}
	status := b.readOnlyStatus(ctx)
	if status.SIM.State != proto.SIMReady || status.SIM.ICCID == "" {
		return nil, proto.FailedPrecondition("list_sms", "SIM identity is unavailable")
	}
	messages := make([]proto.SMS, 0, count)
	firstStorage := make(map[smsDuplicateKey]string, count)
	for index := 1; index <= count; index++ {
		path := fields["modem.messaging.sms.value["+strconv.Itoa(index)+"]"]
		if !validSMSPath(path) {
			return nil, proto.Unavailable("list_sms", "invalid SMS path", nil)
		}
		raw, err := b.run(ctx, "-K", "-s", path)
		if err != nil {
			return nil, proto.Unavailable("list_sms", "cannot read SMS", err)
		}
		properties := parseKeyValues(raw)
		message, ok := smsFromProperties(path, status.SIM.ICCID, properties)
		if !ok {
			continue // Delivery reports and unknown PDU types are not SMS bodies.
		}
		storage := printableValue(properties["sms.properties.storage"])
		key := smsDuplicateKey{
			peer: message.Peer, text: message.Text,
			timestamp: properties["sms.properties.timestamp"],
			pduType:   properties["sms.properties.pdu-type"],
		}
		prior, seen := firstStorage[key]
		if seen &&
			((prior == "sm" && storage == "me") || (prior == "me" && storage == "sm")) {
			continue
		}
		if !seen {
			firstStorage[key] = storage
		}
		messages = append(messages, message)
	}
	return messages, nil
}

type smsDuplicateKey struct {
	peer, text, timestamp, pduType string
}

func validSMSPath(path string) bool {
	if !strings.HasPrefix(path, smsPathPrefix) {
		return false
	}
	_, err := strconv.ParseUint(strings.TrimPrefix(path, smsPathPrefix), 10, 32)
	return err == nil
}

func smsFromProperties(path, simID string, fields map[string]string) (proto.SMS, bool) {
	pduType := strings.ToLower(fields["sms.properties.pdu-type"])
	message := proto.SMS{
		ID:    "mm-" + strings.TrimPrefix(path, smsPathPrefix),
		SIMID: simID,
		Peer:  printableValue(fields["sms.content.number"]),
		Text:  smsText(fields["sms.content.text"]),
	}
	switch pduType {
	case "deliver":
		message.Direction = proto.DirectionIncoming
	case "submit":
		message.Direction = proto.DirectionOutgoing
	default:
		return proto.SMS{}, false
	}
	switch strings.ToLower(fields["sms.properties.state"]) {
	case "received":
		message.State = proto.SMSReceived
	case "sent":
		message.State = proto.SMSSent
	case "sending", "stored":
		message.State = proto.SMSSending
	case "failed":
		message.State = proto.SMSFailed
	default:
		return proto.SMS{}, false
	}
	if timestamp := printableValue(fields["sms.properties.timestamp"]); timestamp != "" {
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05-07"} {
			if parsed, err := time.Parse(layout, timestamp); err == nil {
				message.Timestamp = parsed.UTC()
				break
			}
		}
	}
	return message, true
}

// SMS text in mmcli -K is GLib-escaped UTF-8, not literal user content.
func smsText(raw string) string {
	value := printableValue(raw)
	decoded, ok := mmclitext.Decode(value)
	if !ok {
		return value
	}
	return decoded
}
