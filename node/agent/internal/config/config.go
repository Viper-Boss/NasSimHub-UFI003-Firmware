// Package config reads the agent's configuration file.
//
// The format is deliberately the dullest thing that works: one `key = value`
// per line, `#` starts a comment, blank lines are ignored, no sections, no
// includes, no types beyond string, integer, duration and boolean. It is
// hand-edited over SSH on a device with 256 MB of RAM and possibly no editor
// worth the name, and every feature a format grows is another way for that
// edit to fail at three in the morning.
//
// Two decisions are worth stating because they are what make the file safe to
// ship:
//
//   - An unknown key is an ERROR, not a warning. A typo in a configuration file
//     is the quietest possible failure: the operator writes `listen_addr`,
//     restarts, sees the service running, and does not find out the value was
//     ignored until something does not work weeks later. Refusing to start with
//     the line number is louder and kinder.
//   - The file never contains a password, a key or a token. Nothing here reads
//     one, so a file that grows one would be storing a secret no code uses -
//     and the device identity key is generated on the device and lives in the
//     state directory, not in configuration.
//
// Precedence is: built-in default, then the file, then command-line flags. A
// flag beats the file so that an operator debugging a device can override one
// setting for one run without editing anything.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/proto"
)

// Config is the agent's settings.
//
// Every field here is something an operator might genuinely need to change on a
// deployed device. A setting nobody would change does not belong in a file.
type Config struct {
	StateDir      string
	LogDir        string
	Listen        string
	ModemBackend  string
	Platform      string
	Model         string
	MockScenario  string
	QMIDevice     string
	AudioCard     string
	VoiceMedia    bool
	VoiceDTMF     bool
	Plaintext     bool
	Announce      bool
	LocalAdmin    bool
	AdminListen   string
	Provisioning  bool
	SessionTTL    time.Duration
	UpdateURL     string
	UpdateChannel string
	// Updates enables the agent update mechanism. Off means the agent in the
	// system image always runs and nothing can be installed.
	Updates bool
	// OTAKeys is the file holding the release PUBLIC keys this device trusts.
	// A missing file means no publisher is trusted and updates are reported
	// as unavailable.
	OTAKeys string

	// ProvisioningAP is whether the device may turn its one Wi-Fi radio into
	// the setup access point: auto or off. See deploy/nassimhub-agent.conf.
	ProvisioningAP string

	// Security and transport. These are the settings an operator changes when
	// something is wrong with the link or the policy, which is why they are in
	// the file rather than compiled in.
	// SecurityLevel is the outward-facing setting: STANDARD, PQ or
	// PQ_EXTREME. When set it DECIDES the profile and policy below, which
	// remain readable so an operator who wrote them before levels existed
	// finds their configuration still valid.
	SecurityLevel string
	PQProfile     string
	PQPolicy      string
	// PQIdentityPolicy is how much post-quantum identity to demand of the
	// peer: optional, preferred or required. It is separate from the key
	// agreement policy because identity and confidentiality are different
	// questions - a device can have post-quantum confidentiality today and
	// post-quantum identity only when ML-DSA arrives.
	PQIdentityPolicy string
	// PQIdentity is whether the device holds its own post-quantum identity
	// key. On by default: on a build without ML-DSA it changes nothing, and
	// on a build with it the key is additional to the Ed25519 identity and
	// never affects device_id. Turning it off does not delete a stored key.
	PQIdentity bool
	// OTASignaturePolicy is whether an update must carry both signatures.
	OTASignaturePolicy string
	TransportMode      string
	KCPProfile         string
	KCPFEC             string
}

// Default is the configuration a device with no file uses.
func Default() Config {
	return Config{
		StateDir:      "/var/lib/nassimhub",
		LogDir:        "/var/log/nassimhub",
		Listen:        "0.0.0.0:7580",
		ModemBackend:  "msm8916",
		Platform:      "msm8916",
		Model:         "UFI003",
		MockScenario:  "mobile",
		Plaintext:     false,
		Announce:      true,
		Provisioning:  true,
		LocalAdmin:    true,
		AdminListen:   "0.0.0.0:7581",
		SessionTTL:    0,
		UpdateChannel: "stable",
		Updates:       true,
		OTAKeys:       "/etc/nassimhub/ota-keys.json",
		// auto: a device with no network it can reach offers a way in over
		// Wi-Fi. Whether this radio can be an access point is only known on
		// the hardware; a failure is reported and USB is unaffected.
		// Off until the access point has been seen working on the hardware:
		// an agent update must not make a stick that is in service start
		// trying to broadcast a network. The image config opts in.
		ProvisioningAP: "off",
		// Post-quantum preferred rather than required, on the device side.
		// A Node that REQUIRED it would become unreachable from an older NAS
		// the moment it was updated, and a device the owner cannot reach is a
		// worse outcome than a session key that is merely as good as last
		// year's. Core is the side that can safely require it.
		SecurityLevel: string(proto.LevelStandard),
		PQProfile:     "pq_standard",
		PQPolicy:      "preferred",
		// Optional and preferred are the defaults that keep an updated device
		// reachable from an older Core and able to install a release from an
		// older publisher. A deployment that wants strictness chooses
		// PQ_EXTREME deliberately. Whatever the policy, a post-quantum key
		// that has been pinned for a peer stays mandatory for that peer.
		PQIdentityPolicy:   string(proto.PQIdentityOptional),
		PQIdentity:         true,
		OTASignaturePolicy: string(proto.OTASignaturePreferred),
		// Standard transport. KCP is opt-in: it costs bandwidth and it is only
		// worth it on a link that is actually losing packets.
		TransportMode: "standard",
		KCPProfile:    "balanced",
		KCPFEC:        "off",
	}
}

// Load reads a configuration file. A missing file is not an error: the defaults
// are a working configuration, and requiring a file would make the package
// harder to install for no benefit.
func Load(path string) (Config, error) {
	config := Default()
	if path == "" {
		return config, nil
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return config, nil
	}
	if err != nil {
		return config, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if err := parse(file, &config, path); err != nil {
		return Default(), err
	}
	return config, nil
}

// Parse reads configuration from any reader, for tests.
func Parse(reader io.Reader) (Config, error) {
	config := Default()
	err := parse(reader, &config, "config")
	return config, err
}

func parse(reader io.Reader, config *Config, name string) error {
	scanner := bufio.NewScanner(reader)
	// A configuration line is short. A very long one is a corrupt file or a
	// binary served by mistake, and reading it into memory helps nobody.
	scanner.Buffer(make([]byte, 0, 4096), 64<<10)

	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value, found := strings.Cut(text, "=")
		if !found {
			return fmt.Errorf("%s:%d: %q is not `key = value`", name, line, text)
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)
		// A quoted value is accepted so trailing spaces can be made explicit,
		// but quoting is never required.
		value = strings.Trim(value, `"`)

		if err := assign(config, key, value); err != nil {
			return fmt.Errorf("%s:%d: %w", name, line, err)
		}
	}
	return scanner.Err()
}

func assign(config *Config, key, value string) error {
	switch key {
	case "state_dir":
		config.StateDir = value
	case "log_dir":
		config.LogDir = value
	case "listen":
		config.Listen = value
	case "modem_backend":
		config.ModemBackend = value
	case "platform":
		config.Platform = value
	case "model":
		config.Model = value
	case "mock_scenario":
		config.MockScenario = value
	case "qmi_device":
		config.QMIDevice = value
	case "audio_card":
		config.AudioCard = value
	case "voice_media":
		return assignBool(&config.VoiceMedia, key, value)
	case "voice_dtmf":
		return assignBool(&config.VoiceDTMF, key, value)
	case "update_url":
		config.UpdateURL = value
	case "update_channel":
		config.UpdateChannel = value
	case "updates":
		return assignBool(&config.Updates, key, value)
	case "ota_keys":
		config.OTAKeys = value
	case "security_level":
		config.SecurityLevel = value
	case "pq_profile":
		config.PQProfile = value
	case "pq_policy":
		config.PQPolicy = value
	case "pq_identity_policy":
		config.PQIdentityPolicy = value
	case "pq_identity":
		return assignBool(&config.PQIdentity, key, value)
	case "ota_signature_policy":
		config.OTASignaturePolicy = value
	case "transport_mode":
		config.TransportMode = value
	case "kcp_profile":
		config.KCPProfile = value
	case "kcp_fec":
		config.KCPFEC = value
	case "plaintext":
		return assignBool(&config.Plaintext, key, value)
	case "announce":
		return assignBool(&config.Announce, key, value)
	case "admin_listen":
		config.AdminListen = value
	case "local_admin":
		return assignBool(&config.LocalAdmin, key, value)
	case "provisioning":
		return assignBool(&config.Provisioning, key, value)
	case "provisioning_ap":
		config.ProvisioningAP = strings.ToLower(value)
	case "session_ttl":
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("session_ttl %q is not a duration such as 30m", value)
		}
		if duration < 0 {
			return fmt.Errorf("session_ttl %q is negative", value)
		}
		config.SessionTTL = duration
	default:
		// The loud failure described in the package doc.
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}

func assignBool(target *bool, key, value string) error {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("%s %q is not true or false", key, value)
	}
	*target = parsed
	return nil
}

// Validate catches the settings that would produce a device that starts and
// then does not work, which is worse than one that refuses to start.
func Validate(config Config) error {
	if strings.TrimSpace(config.StateDir) == "" {
		return fmt.Errorf("state_dir must be set; the device identity lives there and a device " +
			"that regenerates it appears as a new device on every boot")
	}
	if strings.TrimSpace(config.Listen) == "" {
		return fmt.Errorf("listen must be set")
	}
	switch config.ModemBackend {
	case "msm8916", "mock":
	default:
		return fmt.Errorf("modem_backend %q is not msm8916 or mock", config.ModemBackend)
	}
	if config.VoiceMedia && (config.ModemBackend != "msm8916" || config.Plaintext) {
		return fmt.Errorf("voice_media requires msm8916 backend and TLS")
	}
	if config.VoiceDTMF && !config.VoiceMedia {
		return fmt.Errorf("voice_dtmf requires voice_media")
	}
	switch config.Platform {
	case "msm8916", "mock":
	default:
		return fmt.Errorf("platform %q is not msm8916 or mock", config.Platform)
	}
	switch config.ProvisioningAP {
	case "auto", "off":
	default:
		return fmt.Errorf("provisioning_ap %q is not auto or off", config.ProvisioningAP)
	}
	switch config.UpdateChannel {
	case "", "stable", "beta":
	default:
		return fmt.Errorf("update_channel %q is not stable or beta", config.UpdateChannel)
	}
	if err := proto.ValidateSecurityLevel(proto.SecurityLevel(config.SecurityLevel)); err != nil {
		return err
	}
	if err := proto.ValidatePQIdentityPolicy(proto.PQIdentityPolicy(config.PQIdentityPolicy)); err != nil {
		return err
	}
	if err := proto.ValidateOTASignaturePolicy(proto.OTASignaturePolicy(config.OTASignaturePolicy)); err != nil {
		return err
	}
	if err := proto.ValidatePQProfile(proto.PQProfile(config.PQProfile)); err != nil {
		return err
	}
	if err := proto.ValidatePQPolicy(proto.PQPolicy(config.PQPolicy)); err != nil {
		return err
	}
	if err := proto.ValidateTransportMode(proto.TransportMode(config.TransportMode)); err != nil {
		return err
	}
	switch config.KCPProfile {
	case "balanced", "aggressive":
	default:
		return fmt.Errorf("kcp_profile %q is not balanced or aggressive", config.KCPProfile)
	}
	switch config.KCPFEC {
	case "off", "balanced", "aggressive":
	default:
		return fmt.Errorf("kcp_fec %q is not off, balanced or aggressive", config.KCPFEC)
	}
	return nil
}
