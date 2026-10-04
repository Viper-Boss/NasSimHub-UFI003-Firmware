package proto

import (
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDeviceIDShapeAndStability(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public().(ed25519.PublicKey)

	id := DeviceID(PlatformMSM8916, public)
	if !strings.HasPrefix(id, "NSH-410-") {
		t.Fatalf("device id %q does not carry the platform segment", id)
	}
	if len(id) != len("NSH-410-")+6 {
		t.Fatalf("device id %q has unexpected length %d", id, len(id))
	}
	if again := DeviceID(PlatformMSM8916, public); again != id {
		t.Fatalf("device id is not deterministic: %q then %q", id, again)
	}
}

func TestDeviceIDIsIndependentOfPlatformlessInputs(t *testing.T) {
	// The same key on two platforms must not collide, and no input other than
	// the key and the platform may participate.
	seed := make([]byte, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public().(ed25519.PublicKey)
	if DeviceID(PlatformMSM8916, public) == DeviceID(PlatformMock, public) {
		t.Fatal("different platforms produced the same device id")
	}
}

func TestValidateDeviceIDRejectsForgedClaim(t *testing.T) {
	honest, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	impostor, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	id := DeviceID(PlatformMSM8916, honest)
	if !ValidateDeviceID(id, PlatformMSM8916, honest) {
		t.Fatal("honest device id failed validation")
	}
	if ValidateDeviceID(id, PlatformMSM8916, impostor) {
		t.Fatal("a different key validated against someone else's device id")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	decoded, err := DecodePublicKey(EncodeKey(public))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !decoded.Equal(public) {
		t.Fatal("public key did not survive the round trip")
	}
	if _, err := DecodePublicKey("not base64!!"); err == nil {
		t.Fatal("expected a decode failure for malformed input")
	}
	if _, err := DecodePublicKey(EncodeKey([]byte("short"))); err == nil {
		t.Fatal("expected a length failure for a truncated key")
	}
}

func TestSigningStringBindsMethodPathAndBody(t *testing.T) {
	stamp := FormatTimestamp(time.Unix(0, 0))
	base := SigningString("POST", "/v1/pair", stamp, "nonce", []byte(`{"a":1}`))

	if string(SigningString("post", "/v1/pair", stamp, "nonce", []byte(`{"a":1}`))) != string(base) {
		t.Fatal("method case changed the canonical string")
	}
	for name, other := range map[string][]byte{
		"method": SigningString("GET", "/v1/pair", stamp, "nonce", []byte(`{"a":1}`)),
		"path":   SigningString("POST", "/v1/session", stamp, "nonce", []byte(`{"a":1}`)),
		"nonce":  SigningString("POST", "/v1/pair", stamp, "other", []byte(`{"a":1}`)),
		"body":   SigningString("POST", "/v1/pair", stamp, "nonce", []byte(`{"a":2}`)),
	} {
		if string(other) == string(base) {
			t.Fatalf("canonical string ignored the %s", name)
		}
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	parsed, err := ParseTimestamp(FormatTimestamp(now))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Equal(now) {
		t.Fatalf("timestamp round trip lost precision: %v vs %v", parsed, now)
	}
	if _, err := ParseTimestamp("yesterday"); err == nil {
		t.Fatal("expected a parse failure")
	}
}

func TestErrorCodeStatusMapping(t *testing.T) {
	cases := map[ErrorCode]int{
		ErrorInvalidArgument:    http.StatusBadRequest,
		ErrorNotFound:           http.StatusNotFound,
		ErrorConflict:           http.StatusConflict,
		ErrorNotSupported:       http.StatusNotImplemented,
		ErrorUnauthenticated:    http.StatusUnauthorized,
		ErrorPermissionDenied:   http.StatusForbidden,
		ErrorFailedPrecondition: http.StatusPreconditionFailed,
		ErrorNetworkRejected:    http.StatusUnprocessableEntity,
		ErrorUnavailable:        http.StatusServiceUnavailable,
		ErrorInternal:           http.StatusInternalServerError,
	}
	for code, want := range cases {
		if got := code.HTTPStatus(); got != want {
			t.Fatalf("%s mapped to %d, want %d", code, got, want)
		}
	}
}

func TestCodeOfUnwrapsAndDefaults(t *testing.T) {
	if got := CodeOf(NotSupported("dial", "no voice")); got != ErrorNotSupported {
		t.Fatalf("CodeOf returned %s", got)
	}
	if got := CodeOf(Internal("x", "y", nil)); got != ErrorInternal {
		t.Fatalf("CodeOf returned %s", got)
	}
	if got := CodeOf(errPlain{}); got != ErrorInternal {
		t.Fatalf("uncoded error should default to internal, got %s", got)
	}
}

type errPlain struct{}

func (errPlain) Error() string { return "plain" }

func TestBarsFromDBM(t *testing.T) {
	cases := []struct {
		dbm  float64
		want int
	}{{-50, 5}, {-65, 5}, {-70, 4}, {-78, 3}, {-90, 2}, {-100, 1}, {-120, 0}}
	for _, c := range cases {
		if got := BarsFromDBM(c.dbm); got != c.want {
			t.Fatalf("BarsFromDBM(%v) = %d, want %d", c.dbm, got, c.want)
		}
	}
}

func TestSIMIDIsICCIDAndNeverFallsBack(t *testing.T) {
	present := SIMInfo{State: SIMReady, ICCID: "89860000000000000000"}
	if present.SIMID() != "89860000000000000000" {
		t.Fatal("SIMID must be the ICCID when one is reported")
	}
	absent := SIMInfo{State: SIMMissing}
	if absent.SIMID() != "" {
		t.Fatal("SIMID must be empty rather than a substitute identifier")
	}
}
