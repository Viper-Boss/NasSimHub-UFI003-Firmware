// Command mock-nassimhub-node runs a complete NasSimHub Node in software.
//
// It serves the real Node Protocol from the real handler with the real pairing
// and identity code; only the two backends are simulated. Several instances run
// side by side on one machine, each with its own state directory, its own
// device_id and its own operator, which is what makes it possible to build and
// regression-test the multi-Node NAS experience with no MSM8916 hardware in the
// room.
//
// Alongside the Node Protocol it serves a small control API on a second,
// separate port. Keeping the two apart matters: the control API can inject an
// incoming call or yank a SIM, and it must never be reachable on the same
// surface a NAS talks to.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/modembackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/netbackend"
	netmock "github.com/human-agent65535/nassimhub-node/agent/netbackend/mock"
	"github.com/human-agent65535/nassimhub-node/agent/nodeserver"
	"github.com/human-agent65535/nassimhub-node/proto"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "mock-nassimhub-node: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("mock-nassimhub-node", flag.ContinueOnError)
	var (
		stateDir = flags.String("state-dir", "", "state directory; defaults to ./.mock-nodes/<name>")
		name     = flags.String("name", "node-a", "instance name, used for the default state directory")
		usbAddr  = flags.String("usb-listen", "127.0.0.1:7581", "address standing in for the USB network link; empty disables it")
		wifiAddr = flags.String("wifi-listen", "127.0.0.1:7582", "address standing in for the Wi-Fi link; empty disables it")
		control  = flags.String("control-listen", "127.0.0.1:7583", "address for the scenario control API; empty disables it")
		scenario = flags.String("scenario", "mobile", "operator scenario: mobile, unicom or telecom")
		signal_  = flags.Float64("signal", 0, "override the scenario's signal in dBm; 0 keeps the preset")
		wifiSSID = flags.String("wifi-ssid", "", "pre-seed a saved Wi-Fi network so the node starts CONNECTED")
		// Development only: serve the protocol over the real device-certificate
		// TLS, as the agent binary does, and optionally present the MSM8916
		// platform so the device ID has the production NSH-410- form. This is
		// what a gateway end-to-end test needs to exercise key pinning.
		useTLS       = flags.Bool("tls", false, "serve the node protocol over device-certificate TLS")
		platformName = flags.String("platform", "mock", "reported platform: mock or msm8916")
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	resolved, ok := mock.ScenarioByName(*scenario)
	if !ok {
		return fmt.Errorf("unknown scenario %q; use mobile, unicom or telecom", *scenario)
	}
	if *signal_ != 0 {
		resolved.SignalDBM = *signal_
	}

	directory := *stateDir
	if directory == "" {
		directory = ".mock-nodes/" + *name
	}

	platform, model := proto.PlatformMock, "mock-node"
	switch *platformName {
	case "mock":
	case "msm8916":
		platform, model = proto.PlatformMSM8916, "UFI003"
	default:
		return fmt.Errorf("unknown platform %q; use mock or msm8916", *platformName)
	}

	modem := mock.New(mock.Options{Scenario: resolved})
	server, err := nodeserver.New(nodeserver.Options{
		StateDir:  directory,
		Platform:  platform,
		Model:     model,
		EnableTLS: *useTLS,
		// Two listeners, one handler. This is the whole point of the mock: the
		// NAS can be pointed at either address and cannot tell the difference,
		// which is exactly the property USB/Wi-Fi failover depends on.
		Listeners: addresses(*usbAddr, *wifiAddr),
		Modem:     modem,
		NetworkFactory: func(deviceID string) netbackend.Backend {
			return netmock.New(netmock.Options{DeviceID: deviceID, SavedSSID: *wifiSSID})
		},
		AgentVersion: "mock-" + version,
		BuildDate:    time.Now().UTC().Format("2006-01-02"),
	})
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}

	fmt.Printf("mock node %q\n", *name)
	fmt.Printf("  device id : %s\n", server.Identity.DeviceID)
	fmt.Printf("  operator  : %s\n", resolved.OperatorName)
	fmt.Printf("  signal    : %.0f dBm\n", resolved.SignalDBM)
	fmt.Printf("  voice     : control=%v audio=%v volte=%s\n", resolved.VoiceControl, resolved.VoiceAudio, resolved.VoLTE)
	fmt.Printf("  state dir : %s\n", directory)
	if *usbAddr != "" {
		fmt.Printf("  usb link  : http://%s/v1/node\n", *usbAddr)
	}
	if *wifiAddr != "" {
		fmt.Printf("  wifi link : http://%s/v1/node\n", *wifiAddr)
	}

	var controlServer *http.Server
	if *control != "" {
		controlServer = &http.Server{
			Addr:              *control,
			Handler:           controlAPI(modem, server, *usbAddr, *wifiAddr),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := controlServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "control api: %v\n", err)
			}
		}()
		fmt.Printf("  control   : http://%s/control/help\n", *control)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals

	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if controlServer != nil {
		_ = controlServer.Shutdown(shutdown)
	}
	return server.Stop(shutdown)
}

func addresses(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// controlAPI is the development-only scenario driver.
//
// It is unauthenticated by design and therefore bound to loopback by default
// and served on its own port. It exists so a developer, a demo or an
// integration test can make a Node ring, drop its SIM or lose its signal
// without a radio, and it has no counterpart in the real agent.
func controlAPI(modem *mock.Backend, server *nodeserver.Server, usbAddr, wifiAddr string) http.Handler {
	mux := http.NewServeMux()

	write := func(w http.ResponseWriter, status int, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	fail := func(w http.ResponseWriter, err error) {
		write(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	mux.HandleFunc("GET /control/help", func(w http.ResponseWriter, _ *http.Request) {
		write(w, http.StatusOK, map[string]any{
			"device_id": server.Identity.DeviceID,
			"endpoints": []string{
				"POST /control/sms/incoming?from=10086&text=hello",
				"POST /control/call/incoming?from=%2B8613900139000",
				"POST /control/sim?state=ready|missing|pin_locked|puk_locked",
				"POST /control/modem?state=ready|offline|failed",
				"POST /control/modem/restart?seconds=10",
				"POST /control/signal?dbm=-95",
				"POST /control/network?registration=registered&technology=lte",
				"POST /control/voice?control=true&audio=false&volte=unknown",
				"POST /control/link?type=usb|wifi&up=false   (simulate a pulled cable)",
			},
		})
	})

	mux.HandleFunc("POST /control/sms/incoming", func(w http.ResponseWriter, r *http.Request) {
		from := valueOr(r, "from", "10086")
		text := valueOr(r, "text", "mock message")
		message, err := modem.InjectIncomingSMS(from, text)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, http.StatusCreated, message)
	})

	mux.HandleFunc("POST /control/call/incoming", func(w http.ResponseWriter, r *http.Request) {
		call, err := modem.InjectIncomingCall(valueOr(r, "from", "+8613900139000"))
		if err != nil {
			fail(w, err)
			return
		}
		write(w, http.StatusCreated, call)
	})

	mux.HandleFunc("POST /control/sim", func(w http.ResponseWriter, r *http.Request) {
		state := proto.SIMState(valueOr(r, "state", "ready"))
		switch state {
		case proto.SIMReady, proto.SIMMissing, proto.SIMPINLocked, proto.SIMPUKLocked, proto.SIMError, proto.SIMUnknown:
		default:
			fail(w, fmt.Errorf("unknown sim state %q", state))
			return
		}
		modem.SetSIMState(state)
		write(w, http.StatusOK, map[string]string{"sim_state": string(state)})
	})

	mux.HandleFunc("POST /control/modem", func(w http.ResponseWriter, r *http.Request) {
		state := proto.ModemState(valueOr(r, "state", "ready"))
		switch state {
		case proto.ModemReady, proto.ModemOffline, proto.ModemFailed, proto.ModemRestarting, proto.ModemUnknown:
		default:
			fail(w, fmt.Errorf("unknown modem state %q", state))
			return
		}
		modem.SetModemState(state)
		write(w, http.StatusOK, map[string]string{"modem_state": string(state)})
	})

	mux.HandleFunc("POST /control/modem/restart", func(w http.ResponseWriter, r *http.Request) {
		seconds, err := strconv.Atoi(valueOr(r, "seconds", "10"))
		if err != nil || seconds < 0 {
			fail(w, fmt.Errorf("seconds must be a non-negative integer"))
			return
		}
		modem.RestartModem(time.Duration(seconds) * time.Second)
		write(w, http.StatusAccepted, map[string]int{"restarting_for_seconds": seconds})
	})

	mux.HandleFunc("POST /control/signal", func(w http.ResponseWriter, r *http.Request) {
		dbm, err := strconv.ParseFloat(valueOr(r, "dbm", "-80"), 64)
		if err != nil {
			fail(w, fmt.Errorf("dbm must be a number"))
			return
		}
		modem.SetSignalDBM(dbm)
		write(w, http.StatusOK, map[string]any{"dbm": dbm, "bars": proto.BarsFromDBM(dbm)})
	})

	mux.HandleFunc("POST /control/network", func(w http.ResponseWriter, r *http.Request) {
		registration := proto.RegistrationState(valueOr(r, "registration", "registered"))
		technology := proto.AccessTechnology(valueOr(r, "technology", "lte"))
		modem.SetRegistration(registration, technology)
		write(w, http.StatusOK, map[string]string{
			"registration": string(registration),
			"technology":   string(technology),
		})
	})

	mux.HandleFunc("POST /control/voice", func(w http.ResponseWriter, r *http.Request) {
		control := valueOr(r, "control", "false") == "true"
		audio := valueOr(r, "audio", "false") == "true"
		volte := proto.Tristate(valueOr(r, "volte", "unknown"))
		modem.SetVoiceCapability(control, audio, volte)
		write(w, http.StatusOK, map[string]any{"control": control, "audio": audio, "volte": volte})
	})

	// Link control is how USB/Wi-Fi failover is exercised without hardware: it
	// takes one listener down so the NAS experiences a real transport failure
	// on that path while the other stays up.
	mux.HandleFunc("POST /control/link", func(w http.ResponseWriter, r *http.Request) {
		kind := valueOr(r, "type", "usb")
		up := valueOr(r, "up", "true") == "true"
		address := usbAddr
		if kind == "wifi" {
			address = wifiAddr
		}
		if address == "" {
			fail(w, fmt.Errorf("this node has no %s link", kind))
			return
		}
		if !server.SetLinkUp(address, up) {
			fail(w, fmt.Errorf("link %s is not known", address))
			return
		}
		write(w, http.StatusOK, map[string]any{"link": kind, "address": address, "up": up})
	})

	return mux
}

func valueOr(r *http.Request, key, fallback string) string {
	if value := strings.TrimSpace(r.URL.Query().Get(key)); value != "" {
		return value
	}
	return fallback
}
