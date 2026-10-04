package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreAWorkingConfiguration(t *testing.T) {
	t.Parallel()

	if err := Validate(Default()); err != nil {
		t.Fatalf("the built-in defaults do not validate: %v", err)
	}
	config := Default()
	if config.Plaintext {
		t.Fatal("the default is plaintext; TLS must be on unless it is deliberately turned off")
	}
	if !config.Announce || !config.Provisioning {
		t.Fatal("a device with default settings cannot be found or set up")
	}
}

func TestAMissingFileUsesDefaults(t *testing.T) {
	t.Parallel()

	config, err := Load(filepath.Join(t.TempDir(), "absent.conf"))
	if err != nil {
		t.Fatalf("a missing configuration file is not an error: %v", err)
	}
	if config != Default() {
		t.Fatalf("a missing file produced %+v", config)
	}
}

func TestEverySettingRoundTrips(t *testing.T) {
	t.Parallel()

	config, err := Parse(strings.NewReader(`
# NasSimHub Node agent
state_dir      = /srv/nassimhub
log_dir        = /srv/log
listen         = 10.55.0.1:7580,192.168.1.5:7580
modem_backend  = mock
platform       = mock
model          = "bench unit"
mock_scenario  = unicom
qmi_device     = /dev/cdc-wdm0
audio_card     = hw:0
plaintext      = true
announce       = false
provisioning   = false
session_ttl    = 45m
update_url     = https://updates.example.invalid/manifest.json
update_channel = beta
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if config.StateDir != "/srv/nassimhub" || config.LogDir != "/srv/log" {
		t.Fatalf("directories are %q / %q", config.StateDir, config.LogDir)
	}
	if config.Listen != "10.55.0.1:7580,192.168.1.5:7580" {
		t.Fatalf("listen is %q", config.Listen)
	}
	if config.Model != "bench unit" {
		t.Fatalf("a quoted value kept its quotes: %q", config.Model)
	}
	if !config.Plaintext || config.Announce || config.Provisioning {
		t.Fatalf("booleans are %+v", config)
	}
	if config.SessionTTL != 45*time.Minute {
		t.Fatalf("session_ttl is %s", config.SessionTTL)
	}
	if config.UpdateChannel != "beta" {
		t.Fatalf("update_channel is %q", config.UpdateChannel)
	}
}

// The decision that makes the file safe to hand-edit: a typo stops the device
// with a line number instead of being silently ignored.
func TestATypoIsAnErrorWithALineNumber(t *testing.T) {
	t.Parallel()

	_, err := Parse(strings.NewReader("state_dir = /var/lib/nassimhub\nlisten_addr = 0.0.0.0:7580\n"))
	if err == nil {
		t.Fatal("a misspelled setting was accepted")
	}
	if !strings.Contains(err.Error(), "listen_addr") {
		t.Fatalf("the error does not name the setting: %v", err)
	}
	if !strings.Contains(err.Error(), ":2:") {
		t.Fatalf("the error does not give the line number: %v", err)
	}
}

func TestABadValueIsRejected(t *testing.T) {
	t.Parallel()

	for _, line := range []string{
		"plaintext = yes-please",
		"session_ttl = forever",
		"session_ttl = -5m",
		"state_dir",
	} {
		if _, err := Parse(strings.NewReader(line + "\n")); err == nil {
			t.Fatalf("%q was accepted", line)
		}
	}
}

// A file that fails to parse must not leave a half-applied configuration
// behind: the device would then start with some of the operator's settings and
// some defaults, which is the hardest state to debug.
func TestAFailedParseAppliesNothing(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "agent.conf")
	if err := os.WriteFile(path, []byte("state_dir = /srv/one\nnonsense = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err == nil {
		t.Fatal("a file with an unknown setting loaded successfully")
	}
	if config.StateDir != Default().StateDir {
		t.Fatalf("a failed load applied state_dir = %q", config.StateDir)
	}
}

func TestCommentsAndBlankLinesAreIgnored(t *testing.T) {
	t.Parallel()

	config, err := Parse(strings.NewReader("\n# a comment\n\n   # indented\nmodel = X\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if config.Model != "X" {
		t.Fatalf("model is %q", config.Model)
	}
}

func TestValidateRefusesAnUnusableDevice(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*Config){
		"no state dir":     func(c *Config) { c.StateDir = "  " },
		"no listener":      func(c *Config) { c.Listen = "" },
		"unknown backend":  func(c *Config) { c.ModemBackend = "quectel" },
		"unknown platform": func(c *Config) { c.Platform = "rpi" },
		"unknown channel":  func(c *Config) { c.UpdateChannel = "nightly" },
		"voice on mock":    func(c *Config) { c.VoiceMedia = true; c.ModemBackend = "mock" },
		"voice plaintext":  func(c *Config) { c.VoiceMedia = true; c.Plaintext = true },
	}
	for name, damage := range cases {
		config := Default()
		damage(&config)
		if err := Validate(config); err == nil {
			t.Fatalf("%s validated", name)
		}
	}
}

// The shipped sample file must parse and validate. A sample that does not is a
// support case waiting to happen.
func TestTheShippedSampleIsValid(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "..", "deploy", "nassimhub-agent.conf")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no sample file at %s: %v", path, err)
	}
	config, err := Parse(strings.NewReader(string(content)))
	if err != nil {
		t.Fatalf("the shipped sample does not parse: %v", err)
	}
	if err := Validate(config); err != nil {
		t.Fatalf("the shipped sample does not validate: %v", err)
	}
	if strings.Contains(strings.ToLower(string(content)), "password") ||
		strings.Contains(strings.ToLower(string(content)), "secret") {
		t.Fatal("the sample configuration mentions a password or secret; " +
			"nothing here reads one and the file must not teach operators to put one in it")
	}
}
