package proto

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// ParseMMCallID accepts the legacy object index and the lifetime-scoped ID.
// Parsing alone never authorizes control: the backend verifies the lifetime.
func ParseMMCallID(id string) (epoch, index string, ok bool) {
	if !strings.HasPrefix(id, "mm-") {
		return "", "", false
	}
	rest := strings.TrimPrefix(id, "mm-")
	parts := strings.Split(rest, "-")
	switch len(parts) {
	case 1:
		index = parts[0]
	case 2:
		epoch, index = parts[0], parts[1]
		if len(epoch) != 32 || strings.ToLower(epoch) != epoch {
			return "", "", false
		}
		if _, err := hex.DecodeString(epoch); err != nil {
			return "", "", false
		}
	default:
		return "", "", false
	}
	n, err := strconv.ParseUint(index, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != index {
		return "", "", false
	}
	return epoch, index, true
}
