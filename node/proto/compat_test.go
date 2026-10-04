package proto

import (
	"errors"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	for _, testCase := range []struct {
		input string
		want  Version
	}{
		{"1.2.3", Version{1, 2, 3}},
		{"v1.2.3", Version{1, 2, 3}},
		{"1.2", Version{1, 2, 0}},
		{"1", Version{1, 0, 0}},
		{"  2.0.1  ", Version{2, 0, 1}},
		{"1.2.3-rc1", Version{1, 2, 3}},
		{"1.2.3+build7", Version{1, 2, 3}},
	} {
		got, err := ParseVersion(testCase.input)
		if err != nil {
			t.Fatalf("ParseVersion(%q) = %v", testCase.input, err)
		}
		if got != testCase.want {
			t.Fatalf("ParseVersion(%q) = %v, want %v", testCase.input, got, testCase.want)
		}
	}
	for _, bad := range []string{"", "   ", "abc", "1.x.3", "1.2.3.4", "-1.0.0", "v"} {
		if got, err := ParseVersion(bad); err == nil {
			t.Fatalf("ParseVersion(%q) accepted and returned %v", bad, got)
		}
	}
}

func TestVersionOrdering(t *testing.T) {
	ordered := []string{"0.1.0", "0.9.9", "1.0.0", "1.0.1", "1.1.0", "2.0.0"}
	for index := 1; index < len(ordered); index++ {
		older, _ := ParseVersion(ordered[index-1])
		newer, _ := ParseVersion(ordered[index])
		if !newer.AtLeast(older) {
			t.Fatalf("%s should be at least %s", newer, older)
		}
		if older.AtLeast(newer) {
			t.Fatalf("%s should not be at least %s", older, newer)
		}
	}
	same, _ := ParseVersion("1.2.3")
	if !same.AtLeast(Version{1, 2, 3}) {
		t.Fatal("a version should be at least itself")
	}
}

// The happy path: this build talking to itself.
func TestLocalVersionsAgree(t *testing.T) {
	if err := Negotiate(LocalCompatibility("1.0.0"), LocalCoreRequirements("1.0.0")); err != nil {
		t.Fatalf("this build cannot talk to itself: %v", err)
	}
}

func TestProtocolMajorMismatchIsRefusedBothWays(t *testing.T) {
	node := LocalCompatibility("1.0.0")
	node.ProtocolMajor = 2
	core := LocalCoreRequirements("1.0.0")

	err := Negotiate(node, core)
	if err == nil {
		t.Fatal("a different protocol generation was accepted")
	}
	var incompatible *IncompatibleError
	if !errors.As(err, &incompatible) {
		t.Fatalf("error is %T, want *IncompatibleError", err)
	}
	if incompatible.Reason != ReasonProtocolMajor {
		t.Fatalf("reason is %q", incompatible.Reason)
	}

	// And the other direction - an older Node meeting a newer Core.
	node.ProtocolMajor = 1
	core.ProtocolMajor = 2
	if err := Negotiate(node, core); err == nil {
		t.Fatal("a Node from an older generation was accepted by a newer Core")
	}
}

func TestCoreCanRequireANewerProtocolMinor(t *testing.T) {
	node := LocalCompatibility("1.0.0")
	node.ProtocolMinor = 0
	core := LocalCoreRequirements("1.0.0")
	core.MinProtocolMinor = 3

	err := Negotiate(node, core)
	var incompatible *IncompatibleError
	if !errors.As(err, &incompatible) || incompatible.Reason != ReasonNodeProtocolOld {
		t.Fatalf("an old minor produced %v", err)
	}
	if incompatible.Upgrade() != "update the device" {
		t.Fatalf("upgrade advice is %q", incompatible.Upgrade())
	}

	// A newer Node against a Core that requires less is fine: minors are
	// additive, so the extra fields are simply unread.
	node.ProtocolMinor = 9
	if err := Negotiate(node, core); err != nil {
		t.Fatalf("a newer Node was refused by an older Core: %v", err)
	}
}

func TestAgentOlderThanCoreSupports(t *testing.T) {
	node := LocalCompatibility("0.0.5")
	core := LocalCoreRequirements("1.0.0")
	core.MinAgentVersion = "1.0.0"

	err := Negotiate(node, core)
	var incompatible *IncompatibleError
	if !errors.As(err, &incompatible) || incompatible.Reason != ReasonAgentOld {
		t.Fatalf("an ancient agent produced %v", err)
	}
	if !strings.Contains(incompatible.Error(), "0.0.5") {
		t.Fatalf("the error does not name the agent version: %s", incompatible)
	}
}

// The direction people forget: a NAS restored from an old backup meeting a Node
// that has moved on.
func TestCoreOlderThanTheNodeAccepts(t *testing.T) {
	node := LocalCompatibility("2.0.0")
	node.MinCoreVersion = "1.5.0"
	core := LocalCoreRequirements("1.0.0")

	err := Negotiate(node, core)
	var incompatible *IncompatibleError
	if !errors.As(err, &incompatible) || incompatible.Reason != ReasonCoreOld {
		t.Fatalf("an old Core produced %v", err)
	}
	if incompatible.Upgrade() != "update NasSimHub on the NAS" {
		t.Fatalf("upgrade advice is %q; the user would go and update the wrong thing",
			incompatible.Upgrade())
	}
}

// Incompatibility must never be mistaken for a link failure. This is the whole
// reason the type exists.
func TestIncompatibilityIsItsOwnError(t *testing.T) {
	node := LocalCompatibility("1.0.0")
	node.ProtocolMajor = 99
	err := Negotiate(node, LocalCoreRequirements("1.0.0"))

	if !errors.Is(err, ErrIncompatible) {
		t.Fatal("errors.Is(err, ErrIncompatible) is false; callers cannot classify it")
	}
	if errors.Is(err, errors.New("connection refused")) {
		t.Fatal("an incompatibility matched an unrelated error")
	}
}

// A version label is a statement about oneself and must not brick adoption when
// it is oddly formatted. A demand is different - see the next test.
func TestAnOddlyLabelledAgentIsStillUsable(t *testing.T) {
	for _, label := range []string{"test-1.0", "dev", "", "unknown", "nightly"} {
		node := LocalCompatibility(label)
		core := LocalCoreRequirements("1.0.0")
		core.MinAgentVersion = "1.0.0"
		if err := Negotiate(node, core); err != nil {
			t.Fatalf("agent labelled %q was refused: %v", label, err)
		}
	}
}

func TestAnUnreadableDemandIsRefused(t *testing.T) {
	node := LocalCompatibility("1.0.0")
	node.MinCoreVersion = "whatever-is-newest"
	core := LocalCoreRequirements("1.0.0")

	err := Negotiate(node, core)
	var incompatible *IncompatibleError
	if !errors.As(err, &incompatible) || incompatible.Reason != ReasonUnreadable {
		t.Fatalf("an unreadable minimum-core demand produced %v", err)
	}
}

// A development Core is exempt from a Node's demand, or the product could not
// be developed against a released Node.
func TestADevelopmentCoreIsExemptFromTheNodeDemand(t *testing.T) {
	node := LocalCompatibility("2.0.0")
	node.MinCoreVersion = "99.0.0"
	for _, coreVersion := range []string{"", "dev", "DEV", "unknown"} {
		if err := Negotiate(node, LocalCoreRequirements(coreVersion)); err != nil {
			t.Fatalf("development core %q was refused: %v", coreVersion, err)
		}
	}
	// But a released Core is not exempt.
	if err := Negotiate(node, LocalCoreRequirements("1.0.0")); err == nil {
		t.Fatal("a released Core ignored the Node's minimum")
	}
}

// An identity document from an agent that predates these fields must read as a
// 1.0 Node with no demand, not as a broken one.
func TestASilentDocumentReadsAsTheOldestCompatibleNode(t *testing.T) {
	document := Node{AgentVersion: "0.9.0", ProtocolVersion: 1}
	compatibility := document.Compatibility()
	if compatibility.ProtocolMajor != 1 || compatibility.ProtocolMinor != 0 {
		t.Fatalf("silence read as %+v", compatibility)
	}
	if compatibility.MinCoreVersion != "" {
		t.Fatalf("silence produced a demand: %q", compatibility.MinCoreVersion)
	}
	if err := Negotiate(compatibility, LocalCoreRequirements("1.0.0")); err != nil {
		t.Fatalf("a 1.0 Node was refused by a 1.1 Core: %v", err)
	}
}

// A document with no protocol number at all - the field absent rather than zero
// - must not be read as "generation 0" and refused.
func TestAMissingProtocolNumberDefaultsToThisGeneration(t *testing.T) {
	document := Node{AgentVersion: "1.0.0"}
	if got := document.Compatibility().ProtocolMajor; got != ProtocolMajor {
		t.Fatalf("a missing protocol number read as %d", got)
	}
}
