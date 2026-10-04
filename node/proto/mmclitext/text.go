// Package mmclitext handles the GLib C escaping used by mmcli key-value output.
// Decode only at this command-output boundary, never on arbitrary SMS content.
package mmclitext

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

func Decode(s string) (string, bool) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out = append(out, s[i])
			continue
		}
		i++
		if i >= len(s) {
			return s, false
		}
		switch s[i] {
		case '\\', '"':
			out = append(out, s[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		default:
			if i+2 >= len(s) || s[i] < '0' || s[i] > '3' || s[i+1] < '0' || s[i+1] > '7' || s[i+2] < '0' || s[i+2] > '7' {
				return s, false
			}
			out = append(out, (s[i]-'0')*64+(s[i+1]-'0')*8+s[i+2]-'0')
			i += 2
		}
	}
	if !utf8.Valid(out) {
		return s, false
	}
	return string(out), true
}

// Encode reconstructs historical mmcli output for identity-preserving repairs.
func Encode(s string) string {
	var out strings.Builder
	for _, b := range []byte(s) {
		switch b {
		case '\\':
			out.WriteString("\\\\")
		case '"':
			out.WriteString("\\\"")
		case '\b':
			out.WriteString("\\b")
		case '\f':
			out.WriteString("\\f")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		case '\t':
			out.WriteString("\\t")
		default:
			if b < 32 || b >= 127 {
				fmt.Fprintf(&out, "\\%03o", b)
			} else {
				out.WriteByte(b)
			}
		}
	}
	return out.String()
}
