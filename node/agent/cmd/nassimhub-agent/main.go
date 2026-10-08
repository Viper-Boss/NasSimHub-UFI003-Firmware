// Command nassimhub-agent is the NasSimHub Node agent.
//
// It is a single static binary with no runtime dependencies beyond the Go
// standard library: no database, no Python, no container, no Redis, no SIP
// stack. Long-term messaging history and NAS services
// live on the NAS; the agent's job is to be the honest, low-cost edge of that
// system on hardware with 256 MB of RAM and a rootfs that has already been
// filled to 100% once. The embedded local console manages this device independently
// of NAS pairing and needs no separate web server.
//
// Concretely the agent owns: device identity, pairing, device and network
// status, SIM and modem state, SMS and call commands, Wi-Fi provisioning,
// backend abstraction, version reporting and a bounded diagnostic log. It owns
// nothing else.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/human-agent65535/nassimhub-node/agent/internal/simnumber"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/advertise"
	"github.com/human-agent65535/nassimhub-node/agent/internal/config"
	"github.com/human-agent65535/nassimhub-node/agent/internal/imsprobe"
	"github.com/human-agent65535/nassimhub-node/agent/internal/provisioning"
	"github.com/human-agent65535/nassimhub-node/agent/internal/voicealsa"
	"github.com/human-agent65535/nassimhub-node/agent/internal/voicemedia"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/modembackend/msm8916"
	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/netbackend/networkmanager"
	"github.com/human-agent65535/nassimhub-node/agent/nodeserver"
	"github.com/human-agent65535/nassimhub-node/agent/ota"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "nassimhub-agent: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 1 && arguments[0] == "-probe-sim-number" {
		return simnumber.Refresh(context.Background())
	}
	// Two passes over the arguments. The first finds -config so the file can be
	// read; the second parses everything with the file's values as defaults, so
	// a flag that was actually typed beats the file and one that was not does
	// not silently override it. A single pass cannot distinguish "the operator
	// asked for the default" from "the operator said nothing".
	settings, err := loadSettings(arguments)
	if err != nil {
		return err
	}

	flags := flag.NewFlagSet("nassimhub-agent", flag.ContinueOnError)
	var (
		configPath  = flags.String("config", defaultConfigPath, "configuration file; missing is not an error")
		stateDir    = flags.String("state-dir", settings.StateDir, "directory holding device identity and pairing state")
		logDir      = flags.String("log-dir", settings.LogDir, "directory for the rotating diagnostic log; empty keeps logs in memory only")
		listen      = flags.String("listen", settings.Listen, "comma-separated listen addresses; the same protocol is served on each")
		backend     = flags.String("modem-backend", settings.ModemBackend, "modem backend: msm8916 or mock")
		platform    = flags.String("platform", settings.Platform, "hardware platform recorded in the device identity")
		model       = flags.String("model", settings.Model, "hardware model label")
		scenario    = flags.String("mock-scenario", settings.MockScenario, "mock backend scenario: mobile, unicom or telecom")
		qmiDevice   = flags.String("qmi-device", settings.QMIDevice, "QMI device node, recorded for the future hardware backend")
		audioCard   = flags.String("audio-card", settings.AudioCard, "ALSA card, recorded for the future hardware backend")
		voiceMedia  = flags.Bool("voice-media", settings.VoiceMedia, "enable experimental UFI003 voice control and PCM media")
		plaintext   = flags.Bool("plaintext", settings.Plaintext, "serve the node protocol without TLS; for local development only")
		announce    = flags.Bool("announce", settings.Announce, "answer DNS-SD browse queries so the NAS can find this device")
		adminListen = flags.String("admin-listen", settings.AdminListen, "independent management HTTPS listener")
		localAdmin  = flags.Bool("local-admin", settings.LocalAdmin, "serve the independent device management console over HTTPS")
		provision   = flags.Bool("provisioning", settings.Provisioning, "serve the first-boot Wi-Fi provisioning API while the device is in its setup AP")
		checkOnly   = flags.Bool("check-config", false, "validate the configuration and exit without starting")
		showVer     = flags.Bool("version", false, "print the version and exit")
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	_ = configPath // resolved in loadSettings; declared here so -help lists it
	if *showVer {
		fmt.Printf("nassimhub-agent %s (protocol %s.%d, needs core %s+, built %s)\n",
			version, proto.ProtocolVersion, proto.ProtocolMinor, proto.MinCoreVersion, buildDate)
		return nil
	}

	settings.StateDir = *stateDir
	settings.LogDir = *logDir
	settings.Listen = *listen
	settings.ModemBackend = *backend
	settings.Platform = *platform
	settings.Model = *model
	settings.MockScenario = *scenario
	settings.QMIDevice = *qmiDevice
	settings.AudioCard = *audioCard
	settings.VoiceMedia = *voiceMedia
	settings.Plaintext = *plaintext
	settings.Announce = *announce
	settings.Provisioning = *provision
	settings.LocalAdmin = *localAdmin
	settings.AdminListen = *adminListen
	if err := config.Validate(settings); err != nil {
		return err
	}
	if *checkOnly {
		fmt.Printf("configuration is valid\n")
		return nil
	}

	resolvedPlatform := proto.Platform(settings.Platform)

	// Which agent runs. Every start begins in the agent from the system image;
	// if a verified release is installed, this call replaces the process with
	// it and does not return. See agent/ota/boot.go.
	//
	// It comes after -version and -check-config on purpose: a staged binary is
	// validated by running it with -version, and that must answer and exit
	// without looking at what is installed.
	//
	// The post-quantum provider is registered first: this call verifies the
	// stored release, dual signature included. (ota.Launch registers it too;
	// nodeserver.New, further down, is too late for this.)
	proto.EnableStandardPQ()
	launched, err := ota.Launch(ota.LaunchOptions{
		StateDir:        settings.StateDir,
		Version:         version,
		KeyFile:         settings.OTAKeys,
		Platform:        resolvedPlatform,
		Channel:         proto.OTAChannel(settings.UpdateChannel),
		SignaturePolicy: updateSignaturePolicy(settings),
		Arguments:       arguments,
		// Only the configured switch. A build without a release version
		// ("dev", or anything that does not parse) is refused by Launch
		// itself, which reports that as its own reason.
		Disabled: !settings.Updates,
		Logf: func(format string, arguments ...any) {
			fmt.Fprintf(os.Stderr, "nassimhub-agent: update: "+format+"\n", arguments...)
		},
	})
	if err != nil {
		return err
	}
	// Applying or undoing an update ends with this process exiting cleanly so
	// the supervisor starts it again; the start-up code above then picks the
	// agent that should run.
	restartRequested := make(chan string, 1)
	updater, err := ota.NewUpdater(ota.UpdaterOptions{
		Decision: launched.Decision,
		StateDir: settings.StateDir,
		Keys:     launched.Keys,
		Restart: func(reason string) {
			select {
			case restartRequested <- reason:
			default:
			}
		},
		Logf: func(format string, arguments ...any) {
			fmt.Fprintf(os.Stderr, "nassimhub-agent: update: "+format+"\n", arguments...)
		},
	})
	if err != nil {
		return err
	}
	defer updater.Close()

	modem, err := buildModem(settings.ModemBackend, settings.MockScenario,
		settings.QMIDevice, settings.AudioCard, settings.VoiceMedia)
	if device, ok := modem.(*msm8916.Backend); ok {
		device.ConfigureDTMF(settings.VoiceDTMF, settings.StateDir)
	}
	if err != nil {
		return err
	}
	var callMedia voicemedia.Opener
	if settings.VoiceMedia {
		callMedia, err = voicealsa.New(voicealsa.Options{})
		if err != nil {
			return err
		}
	}

	listeners := splitAddresses(settings.Listen)
	network := buildNetwork
	if *backend == "msm8916" {
		// The setup access point only makes sense with the setup page that is
		// served through it, so turning provisioning off turns it off too.
		accessPoint := settings.ProvisioningAP
		if !settings.Provisioning {
			accessPoint = networkmanager.ProvisioningAPOff
		}
		network = func(deviceID string) netbackend.Backend {
			return networkmanager.New(networkmanager.Options{
				StateDir:       settings.StateDir,
				DeviceID:       deviceID,
				ProvisioningAP: accessPoint,
				Logf: func(format string, arguments ...any) {
					fmt.Fprintf(os.Stderr, "nassimhub-agent: wifi: "+format+"\n", arguments...)
				},
			})
		}
	}
	// The Wi-Fi backend is built once and shared: the provisioning API and the
	// node protocol must be driving the same radio, or a join completed through
	// one would be invisible to the other.
	var shared netbackend.Backend
	sharedFactory := func(deviceID string) netbackend.Backend {
		if shared == nil {
			shared = network(deviceID)
		}
		return shared
	}

	server, err := nodeserver.New(nodeserver.Options{
		StateDir:             settings.StateDir,
		LogDir:               settings.LogDir,
		Platform:             resolvedPlatform,
		Model:                settings.Model,
		Listeners:            listeners,
		Modem:                modem,
		CallMedia:            callMedia,
		NetworkFactory:       sharedFactory,
		AgentVersion:         version,
		BuildDate:            buildDate,
		SessionTTL:           settings.SessionTTL,
		EnableTLS:            !settings.Plaintext,
		EnableLocalAdmin:     settings.LocalAdmin && !settings.Plaintext,
		AdminListen:          settings.AdminListen,
		CertificateAddresses: localAddresses(),
		// Security and transport come from the configuration file rather than
		// from flags: they are properties of a deployment, and a device whose
		// post-quantum policy depended on how someone typed a command line
		// would be a device nobody could reason about after the fact.
		SecurityLevel:     proto.SecurityLevel(settings.SecurityLevel),
		PQIdentityPolicy:  proto.PQIdentityPolicy(settings.PQIdentityPolicy),
		DisablePQIdentity: !settings.PQIdentity,
		Updates:           updater,
		PQProfile:         proto.PQProfile(settings.PQProfile),
		PQPolicy:          proto.PQPolicy(settings.PQPolicy),
		TransportMode:     proto.TransportMode(settings.TransportMode),
		KCPProfile:        settings.KCPProfile,
		KCPFEC:            settings.KCPFEC,
	})
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}

	background, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
	go updater.Supervise(background)
	if status := updater.Status(); status.Supported {
		server.Logs.Infof("ota", "updates available: %d release key(s), %d post-quantum; running %s",
			status.Keys.Classical, status.Keys.PostQuantum, runningDescription(status))
	} else {
		server.Logs.Infof("ota", "updates unavailable: %s", status.UnsupportedReason)
	}

	// A backend that has to watch the radio itself - to offer the setup access
	// point, to notice a lost network - is run for as long as the agent serves.
	if supervised, ok := sharedFactory(server.Identity.DeviceID).(netbackend.Supervised); ok {
		go supervised.Run(background)
	}

	if settings.Provisioning {
		// The provisioning API is deliberately not part of the node protocol.
		// It listens on the setup AP address only, serves three endpoints, and
		// closes as soon as the device has joined a network - see
		// agent/internal/provisioning. Nothing about the privileged API is
		// relaxed to make first boot easier.
		supervisor, err := provisioning.NewSupervisor(provisioning.Options{
			Identity: provisioning.Identity{
				DeviceID:     server.Identity.DeviceID,
				Platform:     server.Identity.Platform,
				Model:        server.Identity.Model,
				AgentVersion: version,
			},
			Network: sharedFactory(server.Identity.DeviceID),
			Pairing: server.Pairing,
			Logf: func(format string, arguments ...any) {
				server.Logs.Infof("provisioning", format, arguments...)
			},
		}, 2*time.Second)
		if err != nil {
			return fmt.Errorf("prepare provisioning: %w", err)
		}
		go supervisor.Run(background)
	}

	if settings.Announce {
		// Announcements are a convenience for finding the device, never a
		// statement of who it is: the NAS still has to complete a TLS
		// handshake with the key that derives this device id. A failure here
		// is logged and tolerated - a Node that cannot multicast is still
		// reachable at a known address over USB.
		if err := startAnnouncing(background, server, listeners); err != nil {
			server.Logs.Warnf("advertise", "not announcing on the local network: %v", err)
		}
	}

	fmt.Printf("nassimhub-agent %s\n", version)
	fmt.Printf("  device id : %s\n", server.Identity.DeviceID)
	fmt.Printf("  platform  : %s (%s)\n", server.Identity.Platform, server.Identity.Model)
	fmt.Printf("  pairing   : %s\n", server.Pairing.State())
	if identity := server.PQIdentity.Identity(); identity.Present() {
		fmt.Printf("  pq identity: %s\n", identity.Algorithm)
	} else {
		fmt.Printf("  pq identity: none (%s)\n", server.PQIdentity.Status())
	}
	fmt.Printf("  backend   : %s\n", modem.Name())
	if status := updater.Status(); status.ActiveRelease != "" {
		fmt.Printf("  release   : %s (system agent %s)\n", status.ActiveRelease, status.FactoryVersion)
	}
	if address := server.AdminAddress(); address != "" {
		fmt.Printf("  management: https://%s/\n", address)
	}
	for _, address := range server.Addresses() {
		fmt.Printf("  listening : %s://%s/v1/node\n", server.Scheme(), address)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	select {
	case <-signals:
	case reason := <-restartRequested:
		// A clean exit; systemd restarts the service (Restart=always).
		server.Logs.Warnf("ota", "restarting: %s", reason)
		fmt.Fprintf(os.Stderr, "nassimhub-agent: restarting: %s\n", reason)
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Stop(shutdown)
}

// updateSignaturePolicy is the stricter of the configured update signature
// policy and the one the security level demands. A level can only raise it.
func updateSignaturePolicy(settings config.Config) proto.OTASignaturePolicy {
	configured := proto.OTASignaturePolicy(settings.OTASignaturePolicy)
	if proto.OTARequirementFor(proto.SecurityLevel(settings.SecurityLevel)) == proto.OTASignatureRequired {
		return proto.OTASignatureRequired
	}
	if configured == "" {
		return proto.OTASignaturePreferred
	}
	return configured
}

func runningDescription(status proto.OTADeviceStatus) string {
	if status.ActiveRelease == "" {
		return "the system agent " + status.CurrentVersion
	}
	return "release " + status.ActiveRelease + " (" + status.CurrentVersion + "), system agent " + status.FactoryVersion
}

func buildModem(name, scenarioName, qmiDevice, audioCard string, voiceMedia bool) (modembackend.Backend, error) {
	switch name {
	case "msm8916":
		// Observe an already-running ModemManager without enabling it. SMS,
		// mobile data and voice remain disabled until separate hardware tests.
		return msm8916.New(msm8916.Options{QMIDevice: qmiDevice, AudioCard: audioCard, ReadOnly: true, SMSWrite: true, VoiceWrite: voiceMedia, VoiceAudioReady: voicealsa.Ready, RunQMI: imsprobe.Query, ReadOwnNumber: simnumber.Read}), nil
	case "mock":
		resolved, ok := mock.ScenarioByName(scenarioName)
		if !ok {
			return nil, fmt.Errorf("unknown mock scenario %q; use mobile, unicom or telecom", scenarioName)
		}
		return mock.New(mock.Options{Scenario: resolved}), nil
	default:
		return nil, fmt.Errorf("unknown modem backend %q; use msm8916 or mock", name)
	}
}

// buildNetwork returns the Wi-Fi backend for a resolved device id.
//
// The mock remains the development default. Physical MSM8916 builds select the
// NetworkManager backend above without changing the protocol-facing layers.
func buildNetwork(deviceID string) netbackend.Backend {
	return netmock.New(netmock.Options{DeviceID: deviceID})
}

// startAnnouncing brings up the DNS-SD responder on the mDNS group.
//
// This is the one part of the agent that cannot be exercised without a real
// network: the wire format and the responder logic are covered by tests over a
// loopback UDP pair, but joining a multicast group is an operating system
// behaviour. It is therefore written to fail softly.
func startAnnouncing(ctx context.Context, server *nodeserver.Server, listeners []string) error {
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	connection, err := net.ListenMulticastUDP("udp4", nil, group)
	if err != nil {
		return err
	}
	responder, err := advertise.New(advertise.Options{
		DeviceID:  server.Identity.DeviceID,
		Platform:  server.Identity.Platform,
		Port:      advertisedPort(server.Addresses(), listeners),
		Addresses: localAddresses(),
		Paired:    func() bool { return server.Pairing.State() == proto.PairingPaired },
		Conn:      connection,
		To:        group,
	})
	if err != nil {
		_ = connection.Close()
		return err
	}
	go func() {
		defer connection.Close()
		if err := responder.Serve(ctx); err != nil && ctx.Err() == nil {
			server.Logs.Warnf("advertise", "responder stopped: %v", err)
		}
	}()
	return nil
}

// advertisedPort is the port the NAS should be told to connect to.
func advertisedPort(resolved, configured []string) uint16 {
	candidates := append(append([]string{}, resolved...), configured...)
	for _, address := range candidates {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		number, err := strconv.Atoi(port)
		if err != nil || number <= 0 || number > 65535 {
			continue
		}
		return uint16(number)
	}
	return 7580
}

// localAddresses are the device's own unicast addresses.
//
// They become IP SANs on the certificate and A records in announcements. Core
// uses neither for identity - it connects by the hostname derived from
// device_id and verifies the key - so a wrong or stale address here costs a
// retry, not a security property.
func localAddresses() []net.IP {
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	addresses := make([]net.IP, 0, len(interfaces))
	for _, entry := range interfaces {
		network, ok := entry.(*net.IPNet)
		if !ok || network.IP.IsLoopback() || network.IP.IsLinkLocalUnicast() {
			continue
		}
		addresses = append(addresses, network.IP)
	}
	return addresses
}

func splitAddresses(value string) []string {
	parts := strings.Split(value, ",")
	addresses := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			addresses = append(addresses, trimmed)
		}
	}
	return addresses
}

// defaultConfigPath is where the package installs the configuration file.
const defaultConfigPath = "/etc/nassimhub/agent.conf"

// loadSettings does the first of the two argument passes described in run.
//
// It looks only for -config, ignoring everything else, so that a bad flag later
// in the line produces one clear error from the real parser rather than two
// confusing ones from two parsers.
func loadSettings(arguments []string) (config.Config, error) {
	path := defaultConfigPath
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case argument == "-config" || argument == "--config":
			if index+1 < len(arguments) {
				path = arguments[index+1]
			}
		case strings.HasPrefix(argument, "-config="):
			path = strings.TrimPrefix(argument, "-config=")
		case strings.HasPrefix(argument, "--config="):
			path = strings.TrimPrefix(argument, "--config=")
		}
	}
	return config.Load(path)
}
