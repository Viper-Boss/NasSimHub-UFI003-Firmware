// Package diag builds a diagnostics bundle a user can send to someone who is
// trying to help them.
//
// The design rule is an allowlist, not a denylist, and the difference is the
// whole point. A denylist asks "does this look sensitive?" of every field that
// happens to be in scope, and it is wrong the moment a new field is added
// upstream: someone adds phone_number to a struct, the bundle starts carrying
// it, and nobody notices until a support ticket has a subscriber's number in
// it. An allowlist asks "is this field one of the ones we decided to include?"
// and a newly added field is absent by default.
//
// So nothing here serialises an upstream struct wholesale. Every value in a
// Bundle is copied across by name, and the redaction below is a second line of
// defence for the few string fields - error text, log lines - whose CONTENT is
// not under this package's control.
//
// What is allowed, and why each is safe:
//
//	device_id          derived from a public key; already published unauthenticated
//	boot_id            random per boot; identifies a run, not a person
//	agent/protocol     software versions
//	connection type    usb or wifi
//	capabilities       what the hardware can do
//	modem state        ready / offline / restarting, and the reason
//	network state      registration, access technology, roaming, operator NAME
//	resource usage     memory, goroutines, file descriptors, uptime
//	recent errors      sanitised log lines at warn and above
//
// What is refused, and why refusing it is not negotiable: SMS bodies and
// verification codes (the message content is the user's), full phone numbers,
// IMSI and ICCID (they identify the subscriber, not the device), bearer tokens
// and the private key (they are credentials), Wi-Fi passwords, and SIM PIN or
// PUK. None of these is needed to diagnose a fault, and every one of them is
// permanent once it has been pasted into a chat window.
package diag

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/logbuf"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend"
	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// PairingReader is the slice of the pairing store this package needs.
type PairingReader interface {
	State() proto.PairingState
	NonceCacheSize() int
	SessionCount() int
}

// LogReader is the slice of the log buffer this package needs.
type LogReader interface {
	Page(limit int, minimum proto.LogLevel) proto.LogPage
}

// Identity is the device's stable identity, passed in rather than read, so this
// package never touches the private key.
type Identity struct {
	DeviceID  string
	Platform  proto.Platform
	Model     string
	BootID    string
	StartedAt time.Time
}

// Options is everything Collect needs.
type Options struct {
	Identity     Identity
	AgentVersion string
	BuildDate    string
	Modem        modembackend.Backend
	Network      netbackend.Backend
	Pairing      PairingReader
	Logs         LogReader
	Connection   proto.ConnectionType
	ListenPorts  []int
	TLS          bool
	Now          func() time.Time
	// Transport is the link report, supplied by whatever is carrying the
	// connection. It is passed in rather than discovered because this package
	// deliberately knows nothing about transports - that is what keeps the
	// allowlist a complete description of the bundle.
	Transport proto.TransportSection
}

// Collect builds a bundle.
//
// It never fails the whole bundle because one source failed: a device with a
// dead modem is exactly the device someone is trying to diagnose, and returning
// an error instead of a bundle would withhold the information at the moment it
// is needed. Failures become notes.
func Collect(ctx context.Context, options Options) proto.DiagnosticsBundle {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	at := now().UTC()

	bundle := proto.DiagnosticsBundle{
		FormatVersion: proto.DiagnosticsFormatVersion,
		GeneratedAt:   at,
		Device: proto.DeviceSection{
			DeviceID:  options.Identity.DeviceID,
			Platform:  options.Identity.Platform,
			Model:     options.Identity.Model,
			BootID:    options.Identity.BootID,
			StartedAt: options.Identity.StartedAt,
		},
		Software: proto.SoftwareSection{
			AgentVersion:   options.AgentVersion,
			BuildDate:      options.BuildDate,
			ProtocolMajor:  proto.ProtocolMajor,
			ProtocolMinor:  proto.ProtocolMinor,
			MinCoreVersion: proto.MinCoreVersion,
			GoVersion:      runtime.Version(),
			OS:             runtime.GOOS,
			Arch:           runtime.GOARCH,
		},
		Transport: options.Transport,
		Link: proto.LinkSection{
			Connection:  options.Connection,
			ListenPorts: options.ListenPorts,
			TLS:         options.TLS,
		},
	}

	if options.Pairing != nil {
		state := options.Pairing.State()
		bundle.Device.PairingState = state
		bundle.Device.Paired = state == proto.PairingPaired
		bundle.Runtime.NonceCacheSize = options.Pairing.NonceCacheSize()
		bundle.Runtime.ActiveSessions = options.Pairing.SessionCount()
	}

	// The scrubber is filled by the collectors as they read the hardware, so
	// the log section - collected last, on purpose - can be cleaned of this
	// device's own identifiers as well as of anything that merely looks like
	// one.
	known := &scrubber{}
	collectModem(ctx, options, &bundle, known)
	collectWiFi(ctx, options, &bundle, known)
	collectRuntime(options, at, &bundle)
	collectErrors(options, &bundle, known)

	return bundle
}

func collectModem(ctx context.Context, options Options, bundle *proto.DiagnosticsBundle, known *scrubber) {
	if options.Modem == nil {
		bundle.Notes = append(bundle.Notes, "no modem backend was configured")
		return
	}
	bundle.Modem.Backend = options.Modem.Name()

	status, err := options.Modem.GetStatus(ctx)
	if err != nil {
		bundle.Notes = append(bundle.Notes, "modem status unavailable: "+sanitize(err.Error()))
	} else {
		bundle.Modem.State = status.State
		bundle.Modem.Reason = sanitize(status.Reason)
		bundle.Modem.ObservedAt = status.ObservedAt
		// Field by field, by name. The SIM struct carries ICCID, IMSI and the
		// phone number; only the state and presence cross into the bundle.
		known.add(status.SIM.ICCID, status.SIM.IMSI, status.SIM.PhoneNumber)
		bundle.Modem.SIMState = status.SIM.State
		bundle.Modem.SIMPresent = status.SIM.State != proto.SIMMissing && status.SIM.State != ""
		bundle.Network = proto.NetworkSection{
			Registration:     status.Network.Registration,
			AccessTechnology: status.Network.AccessTechnology,
			OperatorName:     status.Network.OperatorName,
			Roaming:          status.Network.Roaming,
			DataConnected:    status.Network.DataConnected,
			SignalBars:       status.Signal.Bars,
			SignalKnown:      status.Signal.Known,
			SignalDBM:        status.Signal.DBM,
			ObservedAt:       status.Network.ObservedAt,
		}
	}

	if capabilities, err := options.Modem.Capabilities(ctx); err == nil {
		bundle.Modem.Capabilities = capabilities
	} else {
		bundle.Notes = append(bundle.Notes, "capabilities unavailable: "+sanitize(err.Error()))
	}
	if voice, err := options.Modem.GetVoiceCapability(ctx); err == nil {
		bundle.Modem.VoiceControl = tristate(voice.Control)
		bundle.Modem.VoiceAudio = tristate(voice.Audio)
		bundle.Modem.VoLTE = voice.VoLTE
		bundle.Modem.VoiceReason = sanitize(voice.Reason)
	}
}

func collectWiFi(ctx context.Context, options Options, bundle *proto.DiagnosticsBundle, known *scrubber) {
	if options.Network == nil {
		bundle.Notes = append(bundle.Notes, "no network backend was configured")
		return
	}
	status, err := options.Network.Status(ctx)
	if err != nil {
		bundle.Notes = append(bundle.Notes, "wifi status unavailable: "+sanitize(err.Error()))
		return
	}
	known.add(status.SSID, status.SavedSSID, status.APSSID)
	bundle.WiFi = proto.WiFiSection{
		State: status.State,
		// The SSID itself is not copied - only whether there is one.
		HasSSID:  strings.TrimSpace(status.SSID) != "",
		APActive: status.State == proto.WiFiProvisioningAP,
		Failure:  sanitize(status.FailureReason),
	}
}

func collectRuntime(options Options, at time.Time, bundle *proto.DiagnosticsBundle) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)

	uptime := time.Duration(0)
	if !options.Identity.StartedAt.IsZero() {
		uptime = at.Sub(options.Identity.StartedAt)
	}
	bundle.Runtime.Uptime = uptime.Round(time.Second).String()
	bundle.Runtime.UptimeSeconds = int64(uptime / time.Second)
	bundle.Runtime.Goroutines = runtime.NumGoroutine()
	bundle.Runtime.HeapAllocBytes = memory.HeapAlloc
	bundle.Runtime.HeapObjects = memory.HeapObjects
	bundle.Runtime.SysBytes = memory.Sys
	bundle.Runtime.NumGC = memory.NumGC
	bundle.Runtime.OpenFileHandles = openFileHandles()
}

func collectErrors(options Options, bundle *proto.DiagnosticsBundle, known *scrubber) {
	if options.Logs == nil {
		return
	}
	page := options.Logs.Page(proto.DiagnosticsMaxLogLines, proto.LogWarn)
	records := make([]proto.ErrorRecord, 0, len(page.Records))
	for _, record := range page.Records {
		records = append(records, proto.ErrorRecord{
			At:    record.Time,
			Level: record.Level,
			// The source is a subsystem name chosen in code, so it is safe as
			// it stands; the message is arbitrary text and is sanitised again
			// even though logbuf already redacted it on the way in. Redacting
			// twice is cheap; missing it once is not.
			Source:  record.Source,
			Message: known.clean(record.Message),
		})
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].At.Before(records[j].At) })
	bundle.Errors = records
}

// scrubber removes values this device knows about itself.
//
// The pattern-based redaction in logbuf is a guess about shape: it recognises
// things that LOOK like an ICCID or a phone number. That leaves a gap for
// values with no recognisable shape at all - an SSID is an arbitrary string,
// and no regular expression can tell "Wang-Family-5G" from a hostname.
//
// But the agent is not guessing. It has just read its own SSID, its own ICCID
// and its own number from the hardware, so it can remove those exact values
// wherever they appear, including from log lines written by code that should
// have known better. Shape-matching and known-value scrubbing cover different
// halves of the problem and neither replaces the other.
type scrubber struct {
	values []string
}

// add registers a value to remove. Very short values are ignored: scrubbing a
// two-character SSID out of every message would corrupt the text without
// protecting anything a reader could not guess anyway.
func (s *scrubber) add(values ...string) {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if len(trimmed) < 4 {
			continue
		}
		s.values = append(s.values, trimmed)
	}
}

func (s *scrubber) clean(message string) string {
	if message == "" {
		return ""
	}
	cleaned := logbuf.Redact(message)
	for _, value := range s.values {
		if value == "" {
			continue
		}
		cleaned = replaceFold(cleaned, value, logbuf.Redacted)
	}
	return cleaned
}

// replaceFold is a case-insensitive strings.ReplaceAll. SSIDs and operator
// names are compared by humans, not byte-for-byte, and a log line that
// lowercased the value must not slip through.
func replaceFold(haystack, needle, replacement string) string {
	if needle == "" {
		return haystack
	}
	var builder strings.Builder
	lowerHaystack := strings.ToLower(haystack)
	lowerNeedle := strings.ToLower(needle)
	for {
		index := strings.Index(lowerHaystack, lowerNeedle)
		if index < 0 {
			builder.WriteString(haystack)
			return builder.String()
		}
		builder.WriteString(haystack[:index])
		builder.WriteString(replacement)
		haystack = haystack[index+len(needle):]
		lowerHaystack = lowerHaystack[index+len(lowerNeedle):]
	}
}

// sanitize is the shape-based layer on its own, for text collected before the
// device's own values are known.
func sanitize(message string) string {
	if message == "" {
		return ""
	}
	return logbuf.Redact(message)
}

func tristate(value bool) proto.Tristate {
	if value {
		return proto.TriYes
	}
	return proto.TriNo
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

// FileName is the suggested name for a saved bundle.
func FileName(deviceID string, at time.Time) string {
	return fmt.Sprintf("nassimhub-%s-%s.tar.gz", strings.ToLower(deviceID), at.UTC().Format("20060102-150405"))
}

// WriteArchive writes the bundle as a gzipped tar containing the JSON document
// and a plain-text summary.
//
// Two representations of the same data: the JSON is what a tool reads, the text
// is what a person reads when they open the archive to check what they are
// about to send. That second one matters - a bundle a user cannot inspect is a
// bundle they are right not to trust.
func WriteArchive(w io.Writer, bundle proto.DiagnosticsBundle) error {
	compressor := gzip.NewWriter(w)
	archive := tar.NewWriter(compressor)

	document, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("encode diagnostics: %w", err)
	}
	if err := writeEntry(archive, "diagnostics.json", document, bundle.GeneratedAt); err != nil {
		return err
	}
	if err := writeEntry(archive, "summary.txt", []byte(Summary(bundle)), bundle.GeneratedAt); err != nil {
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	return compressor.Close()
}

func writeEntry(archive *tar.Writer, name string, content []byte, at time.Time) error {
	header := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(content)),
		ModTime: at,
		Format:  tar.FormatPAX,
	}
	if err := archive.WriteHeader(header); err != nil {
		return fmt.Errorf("write %s header: %w", name, err)
	}
	if _, err := archive.Write(content); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// Summary renders the bundle for a human.
func Summary(bundle proto.DiagnosticsBundle) string {
	var builder strings.Builder
	line := func(format string, arguments ...any) {
		fmt.Fprintf(&builder, format+"\n", arguments...)
	}
	line("NasSimHub Node diagnostics")
	line("generated  %s", bundle.GeneratedAt.Format(time.RFC3339))
	line("")
	line("device     %s (%s %s)", bundle.Device.DeviceID, bundle.Device.Platform, bundle.Device.Model)
	line("boot       %s, up %s", bundle.Device.BootID, bundle.Runtime.Uptime)
	line("paired     %t", bundle.Device.Paired)
	line("agent      %s (protocol %d.%d, needs core %s+)",
		bundle.Software.AgentVersion, bundle.Software.ProtocolMajor,
		bundle.Software.ProtocolMinor, bundle.Software.MinCoreVersion)
	line("link       %s, tls %t", bundle.Link.Connection, bundle.Link.TLS)
	line("")
	line("modem      %s via %s", bundle.Modem.State, bundle.Modem.Backend)
	if bundle.Modem.Reason != "" {
		line("           reason: %s", bundle.Modem.Reason)
	}
	line("sim        %s (present %t)", bundle.Modem.SIMState, bundle.Modem.SIMPresent)
	line("network    %s on %s, operator %s, roaming %t",
		bundle.Network.Registration, bundle.Network.AccessTechnology,
		orNone(bundle.Network.OperatorName), bundle.Network.Roaming)
	line("signal     %d bars (known %t)", bundle.Network.SignalBars, bundle.Network.SignalKnown)
	line("wifi       %s (configured %t)", bundle.WiFi.State, bundle.WiFi.HasSSID)
	line("")
	line("transport  %s (resolved %s), advice %s",
		orNone(string(bundle.Transport.Mode)), orNone(string(bundle.Transport.Resolved)),
		orNone(string(bundle.Transport.Advice)))
	if bundle.Transport.Measured {
		line("link       rtt %s, jitter %s, loss %.2f%%, retransmits %d",
			orNone(bundle.Transport.RTT), orNone(bundle.Transport.Jitter),
			bundle.Transport.PacketLoss*100, bundle.Transport.Retransmits)
		if bundle.Transport.FECMode != "" && bundle.Transport.FECMode != "off" {
			line("fec        %s, %d recovered, %.1f%% overhead",
				bundle.Transport.FECMode, bundle.Transport.FECRecovered,
				bundle.Transport.FECOverhead*100)
		}
	} else {
		line("link       not measured by this transport")
	}
	line("encryption %s, pq %s%s",
		orNone(bundle.Transport.Security.TLSVersion),
		orNone(string(bundle.Transport.Security.PQActive)),
		pqDetail(bundle.Transport.Security))
	line("")
	line("goroutines %d", bundle.Runtime.Goroutines)
	line("heap       %d bytes in %d objects", bundle.Runtime.HeapAllocBytes, bundle.Runtime.HeapObjects)
	line("sessions   %d, nonces %d", bundle.Runtime.ActiveSessions, bundle.Runtime.NonceCacheSize)
	if bundle.Runtime.OpenFileHandles > 0 {
		line("handles    %d", bundle.Runtime.OpenFileHandles)
	}
	line("")
	line("recent problems (%d)", len(bundle.Errors))
	for _, record := range bundle.Errors {
		line("  %s  %-5s %-12s %s",
			record.At.Format(time.RFC3339), record.Level, record.Source, record.Message)
	}
	for _, note := range bundle.Notes {
		line("note: %s", note)
	}
	line("")
	line("This bundle contains no message content, phone numbers, IMSI, ICCID,")
	line("Wi-Fi passwords, tokens or keys. It is safe to attach to a support request.")
	return builder.String()
}

// pqDetail renders the post-quantum group and the reason for an unknown, so a
// reader of a bundle is not left guessing what "unknown" means.
func pqDetail(security proto.SecurityCapability) string {
	switch {
	case security.PQGroup != "":
		return " (" + security.PQGroup + ")"
	case security.PQActive == proto.TriUnknown && !security.Observable:
		return " (this build cannot read back the negotiated group)"
	case security.Fallback():
		return " (FELL BACK to classical)"
	default:
		return ""
	}
}

func orNone(value string) string {
	if value == "" {
		return "(none)"
	}
	return value
}

// openFileHandles counts the process's open descriptors.
//
// It reads /proc, so it answers only on Linux - which is where the agent runs.
// Anywhere else it returns 0 and the field is omitted, rather than reporting a
// wrong number that someone would later try to explain.
func openFileHandles() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	// One of the entries is the directory handle ReadDir itself opened.
	if len(entries) > 0 {
		return len(entries) - 1
	}
	return 0
}
