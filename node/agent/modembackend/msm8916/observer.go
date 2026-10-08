package msm8916

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// runMMCLI never activates a masked modem service. Checking systemd first is
// important: contacting the D-Bus name directly could otherwise start it.
func runMMCLI(ctx context.Context, arguments ...string) (string, error) {
	check, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(check, "systemctl", "is-active", "--quiet", "ModemManager.service").Run(); err != nil {
		return "", errors.New("ModemManager is not active")
	}
	query, stop := context.WithTimeout(ctx, 4*time.Second)
	defer stop()
	output, err := exec.CommandContext(query, "mmcli", arguments...).Output()
	if err != nil || len(output) > 64*1024 {
		return "", errors.New("ModemManager query failed")
	}
	return string(output), nil
}

// mmcli's key-value mode has stable field names and avoids parsing localized
// human-readable headings. Unknown fields are ignored, not guessed.
func parseKeyValues(output string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return fields
}

func listedModemPath(output string) string {
	fields := parseKeyValues(output)
	for index := 1; index <= 8; index++ {
		path := fields["modem-list.value["+strconv.Itoa(index)+"]"]
		const prefix = "/org/freedesktop/ModemManager1/Modem/"
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		if _, err := strconv.ParseUint(strings.TrimPrefix(path, prefix), 10, 32); err == nil {
			return path
		}
	}
	return ""
}

func accessTechnologies(fields map[string]string) string {
	if value := fields["modem.generic.access-technologies"]; value != "" {
		return value
	}
	var values []string
	for index := 1; index <= 8; index++ {
		if value := fields["modem.generic.access-technologies.value["+strconv.Itoa(index)+"]"]; value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, " ")
}

func (b *Backend) readOnlyStatus(ctx context.Context) proto.ModemStatus {
	observed := b.now().UTC()
	status := proto.ModemStatus{
		State:      proto.ModemOffline,
		Reason:     "ModemManager is inactive or no modem is visible",
		SIM:        proto.SIMInfo{State: proto.SIMUnknown, ObservedAt: observed},
		Network:    proto.NetworkStatus{Registration: proto.RegUnknown, AccessTechnology: proto.AccessUnknown, ObservedAt: observed},
		Signal:     proto.Signal{ObservedAt: observed},
		ObservedAt: observed,
	}
	list, err := b.run(ctx, "-K", "-L")
	if err != nil {
		return status
	}
	path := listedModemPath(list)
	if path == "" {
		return status
	}
	output, err := b.run(ctx, "-K", "-m", path)
	if err != nil {
		return status
	}
	fields := parseKeyValues(output)
	state := strings.ToLower(fields["modem.generic.state"])
	switch state {
	case "registered", "connected", "enabled", "searching":
		status.State, status.Reason = proto.ModemReady, ""
	case "failed":
		status.State, status.Reason = proto.ModemFailed, "ModemManager reports a failed modem"
	case "initializing", "enabling", "disabling":
		status.State, status.Reason = proto.ModemRestarting, "ModemManager is initializing"
	case "":
		return status
	default:
		status.Reason = "modem is " + state
	}
	status.Network.Registration = parseRegistration(fields["modem.3gpp.registration-state"])
	status.Network.AccessTechnology = parseAccess(accessTechnologies(fields))
	status.Network.OperatorName = printableValue(fields["modem.3gpp.operator-name"])
	status.Network.OperatorCode = printableValue(fields["modem.3gpp.operator-code"])
	status.SIM.PhoneNumber = printableValue(fields["modem.generic.own-numbers.value[1]"])
	status.Network.Roaming = status.Network.Registration == proto.RegRoaming
	if quality, err := strconv.Atoi(fields["modem.generic.signal-quality.value"]); err == nil && quality >= 0 && quality <= 100 {
		status.Signal.Known = true
		status.Signal.Bars = (quality + 19) / 20
	}
	if signalOutput, signalErr := b.run(ctx, "-K", "-m", path, "--signal-get"); signalErr == nil {
		sampled := parseKeyValues(signalOutput)
		for _, field := range []struct {
			key    string
			target **float64
		}{{"rsrp", &status.Signal.RSRP}, {"rsrq", &status.Signal.RSRQ}, {"rssi", &status.Signal.DBM}, {"snr", &status.Signal.SNR}} {
			if value, err := strconv.ParseFloat(sampled["modem.signal.lte."+field.key], 64); err == nil {
				*field.target = &value
			}
		}
	}
	simPath := printableValue(fields["modem.generic.sim"])
	unlock := strings.ToLower(fields["modem.generic.unlock-required"])
	switch {
	case unlock == "sim-puk":
		status.SIM.State = proto.SIMPUKLocked
	case unlock == "sim-pin":
		status.SIM.State = proto.SIMPINLocked
	case simPath == "":
		status.SIM.State = proto.SIMMissing
	default:
		// A SIM path alone does not prove the card is usable. The SIM query
		// fills identifiers only when the modem reports a ready state.
		status.SIM.State = proto.SIMUnknown
		if state == "registered" || state == "connected" || state == "enabled" {
			status.SIM.State = proto.SIMReady
		}
		if sim, err := b.run(ctx, "-K", "-i", simPath); err == nil {
			simFields := parseKeyValues(sim)
			status.SIM.ICCID = printableValue(simFields["sim.properties.iccid"])
			status.SIM.IMSI = printableValue(simFields["sim.properties.imsi"])
			status.SIM.OperatorName = printableValue(simFields["sim.properties.operator-name"])
			status.SIM.OperatorCode = printableValue(simFields["sim.properties.operator-code"])
		}
	}
	if status.SIM.PhoneNumber == "" && status.SIM.State == proto.SIMReady && status.SIM.ICCID != "" && b.options.ReadOwnNumber != nil {
		if number, err := b.options.ReadOwnNumber(status.SIM.ICCID); err == nil {
			status.SIM.PhoneNumber = number
		}
	}
	return status
}

func printableValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "--" || value == "unknown" || value == "none" {
		return ""
	}
	return value
}

func parseRegistration(value string) proto.RegistrationState {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "home":
		return proto.RegRegistered
	case "roaming":
		return proto.RegRoaming
	case "searching":
		return proto.RegSearching
	case "denied":
		return proto.RegDenied
	case "idle":
		return proto.RegUnregistered
	default:
		return proto.RegUnknown
	}
}

func parseAccess(value string) proto.AccessTechnology {
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "lte"):
		return proto.AccessLTE
	case strings.Contains(value, "umts"), strings.Contains(value, "hspa"):
		return proto.AccessUMTS
	case strings.Contains(value, "gsm"), strings.Contains(value, "edge"):
		return proto.AccessGSM
	default:
		return proto.AccessUnknown
	}
}
