package proto

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version compatibility.
//
// A Node and a Core that cannot understand each other must say so. The failure
// this design exists to prevent is the quiet one: an incompatible Node showing
// up in the UI as "offline", because then the user power-cycles the device,
// re-pairs it, moves it closer to the router, and eventually returns it - none
// of which can work, because nothing is wrong with the link.
//
// So incompatibility is decided from the unauthenticated identity document,
// before pairing is attempted, and it is reported as its own error type with a
// machine-readable reason. ErrOffline and ErrIncompatible are never
// interchangeable.
//
// Four numbers take part:
//
//   - protocol major: the wire contract. Different major means the two cannot
//     talk at all, in either direction.
//   - protocol minor: additive changes. A Core may require a minimum minor when
//     it needs a field that older agents do not send. An agent never requires a
//     minimum minor from Core, because Core's requests are the older shape and
//     an agent can always serve those.
//   - agent version: Core states the oldest agent it supports.
//   - min_core_version: the agent states the oldest Core it accepts. This is the
//     direction people forget. A Node deployed in a cupboard for a year will
//     meet a Core much newer than itself, but it can also meet an OLDER Core -
//     a NAS restored from a backup image - and a Node whose pairing format has
//     moved on must refuse that rather than half-work.

const (
	// ProtocolMajor is the wire contract number. It appears in
	// ProtocolVersion as well; the two must agree.
	ProtocolMajor = 1

	// ProtocolMinor counts additive, backward-compatible changes within a
	// major. Adding a field to a response bumps this; changing the meaning of
	// one does not - that is a major.
	//
	//	1.0  initial Node protocol
	//	1.1  identity document gained min_core_version and protocol_minor
	//	1.2  identity document gained pq_identity; POST /v1/transport/key added
	//	     for the KCP transport secret. Both additive: a Core that does not
	//	     know about either keeps working over TCP, and a Node that does not
	//	     serve the endpoint answers 404, which the Core reports as "weak
	//	     network transport unavailable on this device" rather than as a
	//	     failure.
	//	1.3  POST /v1/identity/attest (dual-signed live identity); the pair
	//	     request gained core_pq and signed requests gained an optional
	//	     post-quantum signature header; GET/POST /v1/ota/* for the agent
	//	     update lifecycle. All additive: an older Node answers the new
	//	     endpoints with 404 and ignores the new field and header, and the
	//	     Core reports the result as classical-only or as "update not
	//	     supported on this device".
	//	1.4  POST /v1/trust/policy and GET /v1/trust: the device enforces a
	//	     trust policy its paired Core signed (trustpolicy.go). Additive: an
	//	     older Core never calls them and nothing changes for it; an older
	//	     Node answers 404 and the Core reports "this device does not
	//	     enforce". The identity document itself gained no field.
	// 1.5 adds optional dtmf capability and POST /v1/calls/{id}/dtmf.
	// Missing capability on an older Node means unsupported, never host fallback.
	ProtocolMinor = 5
)

// MinCoreVersion is the oldest NasSimHub Core this agent build will talk to.
//
// It is deliberately low. Raising it strands working deployments, so it moves
// only when an older Core would actually misbehave - not merely when it would
// miss a feature.
const MinCoreVersion = "0.1.0"

// MinAgentVersion is the oldest agent this Core build will talk to, and it
// follows the same rule in the other direction.
const MinAgentVersion = "0.1.0"

// ErrIncompatible reports that two versions cannot work together. It is
// distinct from a transport failure and must never be reported as one.
var ErrIncompatible = errors.New("node and core versions are not compatible")

// IncompatibilityReason is the machine-readable cause, so the UI can say
// something specific instead of "incompatible".
type IncompatibilityReason string

const (
	// ReasonProtocolMajor means the wire contracts differ. Nothing can be done
	// short of updating one side.
	ReasonProtocolMajor IncompatibilityReason = "protocol_major_mismatch"
	// ReasonNodeProtocolOld means the Node speaks an older minor than this
	// Core requires.
	ReasonNodeProtocolOld IncompatibilityReason = "node_protocol_too_old"
	// ReasonAgentOld means the agent build predates what this Core supports.
	ReasonAgentOld IncompatibilityReason = "agent_too_old"
	// ReasonCoreOld means this Core predates what the Node accepts.
	ReasonCoreOld IncompatibilityReason = "core_too_old"
	// ReasonUnreadable means a version string that had to be evaluated could
	// not be parsed. It applies to min_core_version, which is a demand, and
	// not to a side's own version label - see Negotiate for why the two are
	// treated differently.
	ReasonUnreadable IncompatibilityReason = "version_unreadable"
)

// IncompatibleError carries both sides of the disagreement so the message can
// name what to upgrade.
type IncompatibleError struct {
	Reason   IncompatibilityReason
	NodeSide string
	CoreSide string
	Detail   string
}

func (e *IncompatibleError) Error() string {
	return fmt.Sprintf("%s: %s (node %s, core %s)", e.Reason, e.Detail, e.NodeSide, e.CoreSide)
}

// Is makes errors.Is(err, ErrIncompatible) work, which is how callers tell this
// apart from a link failure without type-switching everywhere.
func (e *IncompatibleError) Is(target error) bool { return target == ErrIncompatible }

// Upgrade names which side has to move, in words a UI can show.
func (e *IncompatibleError) Upgrade() string {
	switch e.Reason {
	case ReasonNodeProtocolOld, ReasonAgentOld:
		return "update the device"
	case ReasonCoreOld:
		return "update NasSimHub on the NAS"
	case ReasonProtocolMajor:
		return "update both the device and NasSimHub"
	default:
		return "check the device"
	}
}

// Compatibility is what a Node publishes about itself, in the unauthenticated
// identity document. It is readable before pairing on purpose: the user should
// learn "this device needs a newer NasSimHub" while looking at the add-device
// screen, not after adopting it.
type Compatibility struct {
	ProtocolMajor  int    `json:"protocol_major"`
	ProtocolMinor  int    `json:"protocol_minor"`
	AgentVersion   string `json:"agent_version"`
	MinCoreVersion string `json:"min_core_version"`
}

// LocalCompatibility is what this agent build publishes.
func LocalCompatibility(agentVersion string) Compatibility {
	return Compatibility{
		ProtocolMajor:  ProtocolMajor,
		ProtocolMinor:  ProtocolMinor,
		AgentVersion:   agentVersion,
		MinCoreVersion: MinCoreVersion,
	}
}

// CoreRequirements is what a Core build demands of a Node.
type CoreRequirements struct {
	CoreVersion      string
	ProtocolMajor    int
	MinProtocolMinor int
	MinAgentVersion  string
}

// LocalCoreRequirements is what this Core build demands.
func LocalCoreRequirements(coreVersion string) CoreRequirements {
	return CoreRequirements{
		CoreVersion:      coreVersion,
		ProtocolMajor:    ProtocolMajor,
		MinProtocolMinor: 0,
		MinAgentVersion:  MinAgentVersion,
	}
}

// Negotiate decides whether a Core and a Node can work together.
//
// It returns nil or an *IncompatibleError, and never a transport error: it does
// no I/O. The checks run most-fundamental first, so the reported reason is the
// one worth showing rather than whichever happened to be tested first.
func Negotiate(node Compatibility, core CoreRequirements) error {
	if node.ProtocolMajor != core.ProtocolMajor {
		return &IncompatibleError{
			Reason:   ReasonProtocolMajor,
			NodeSide: fmt.Sprintf("protocol %d.%d", node.ProtocolMajor, node.ProtocolMinor),
			CoreSide: fmt.Sprintf("protocol %d.x", core.ProtocolMajor),
			Detail:   "the device and NasSimHub speak different protocol generations",
		}
	}
	if node.ProtocolMinor < core.MinProtocolMinor {
		return &IncompatibleError{
			Reason:   ReasonNodeProtocolOld,
			NodeSide: fmt.Sprintf("protocol %d.%d", node.ProtocolMajor, node.ProtocolMinor),
			CoreSide: fmt.Sprintf("requires %d.%d or newer", core.ProtocolMajor, core.MinProtocolMinor),
			Detail:   "the device's firmware is older than this NasSimHub supports",
		}
	}

	// The agent version floor. An unreadable or development version is exempt
	// from it rather than rejected, and the asymmetry with min_core_version
	// below is deliberate: a version string is a STATEMENT ABOUT ONESELF, and
	// refusing to talk to a device because its own label is oddly formatted
	// would brick adoption over a cosmetic defect. The protocol major and minor
	// above are the real gate, and they are numbers that cannot be mis-spelled.
	agent, err := ParseVersion(node.AgentVersion)
	if err == nil && !isDevelopmentVersion(node.AgentVersion) {
		minimumAgent, err := ParseVersion(core.MinAgentVersion)
		if err != nil {
			return &IncompatibleError{
				Reason:   ReasonUnreadable,
				NodeSide: node.AgentVersion,
				CoreSide: core.MinAgentVersion,
				Detail:   "this NasSimHub build has an unreadable minimum agent version",
			}
		}
		if !agent.AtLeast(minimumAgent) {
			return &IncompatibleError{
				Reason:   ReasonAgentOld,
				NodeSide: agent.String(),
				CoreSide: "requires " + minimumAgent.String() + " or newer",
				Detail:   "the device's software is older than this NasSimHub supports",
			}
		}
	}

	// The other direction, and the one with different rules. min_core_version
	// is not a label, it is a DEMAND: the Node is saying it will not work
	// correctly with anything older. A demand that cannot be evaluated cannot
	// be assumed satisfied, so an unreadable one is fatal here even though an
	// unreadable agent version is not.
	//
	// A development Core ("dev", "") is still exempt: refusing to talk to an
	// unversioned Core would make the product untestable, and whoever is
	// running a development Core has already accepted that risk.
	if node.MinCoreVersion != "" && !isDevelopmentVersion(core.CoreVersion) {
		minimumCore, err := ParseVersion(node.MinCoreVersion)
		if err != nil {
			return &IncompatibleError{
				Reason:   ReasonUnreadable,
				NodeSide: node.MinCoreVersion,
				CoreSide: core.CoreVersion,
				Detail:   "the device stated an unreadable minimum NasSimHub version",
			}
		}
		running, err := ParseVersion(core.CoreVersion)
		if err != nil {
			return &IncompatibleError{
				Reason:   ReasonUnreadable,
				NodeSide: node.MinCoreVersion,
				CoreSide: core.CoreVersion,
				Detail:   "this NasSimHub build has an unreadable version",
			}
		}
		if !running.AtLeast(minimumCore) {
			return &IncompatibleError{
				Reason:   ReasonCoreOld,
				NodeSide: "requires NasSimHub " + minimumCore.String() + " or newer",
				CoreSide: running.String(),
				Detail:   "this NasSimHub is older than the device accepts",
			}
		}
	}
	return nil
}

// isDevelopmentVersion reports whether a version string is a build that has no
// release number.
func isDevelopmentVersion(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	return trimmed == "" || trimmed == "dev" || trimmed == "devel" || trimmed == "unknown"
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

// Version is a semantic version, without pre-release or build metadata.
//
// Those are deliberately parsed and then ignored for ordering: "1.2.0-rc1" is
// treated as 1.2.0 for compatibility purposes. Ordering pre-releases correctly
// is a well-known source of bugs, and the question being asked here - can these
// two talk - does not need it.
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion reads "1.2.3", "v1.2.3", "1.2", or "1", with any pre-release or
// build suffix discarded.
func ParseVersion(value string) (Version, error) {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "v")
	if trimmed == "" {
		return Version{}, errors.New("empty version")
	}
	// Discard "-rc1" and "+build".
	if index := strings.IndexAny(trimmed, "-+"); index >= 0 {
		trimmed = trimmed[:index]
	}
	if trimmed == "" {
		return Version{}, fmt.Errorf("version %q has no numbers", value)
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) > 3 {
		return Version{}, fmt.Errorf("version %q has too many components", value)
	}
	numbers := make([]int, 3)
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return Version{}, fmt.Errorf("version %q has a non-numeric component %q", value, part)
		}
		numbers[index] = number
	}
	return Version{Major: numbers[0], Minor: numbers[1], Patch: numbers[2]}, nil
}

// String renders the version canonically.
func (v Version) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// Compare returns -1, 0 or 1.
func (v Version) Compare(other Version) int {
	switch {
	case v.Major != other.Major:
		return sign(v.Major - other.Major)
	case v.Minor != other.Minor:
		return sign(v.Minor - other.Minor)
	case v.Patch != other.Patch:
		return sign(v.Patch - other.Patch)
	default:
		return 0
	}
}

// AtLeast reports whether v is other or newer.
func (v Version) AtLeast(other Version) bool { return v.Compare(other) >= 0 }

func sign(value int) int {
	if value < 0 {
		return -1
	}
	if value > 0 {
		return 1
	}
	return 0
}
