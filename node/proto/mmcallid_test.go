package proto

import "testing"

func TestMMCallIDGrammar(t *testing.T) {
	for _, id := range []string{"mm-0", "mm-4294967295", "mm-0123456789abcdef0123456789abcdef-7"} {
		if _, _, ok := ParseMMCallID(id); !ok {
			t.Fatalf("rejected %q", id)
		}
	}
	for _, id := range []string{"mm-", "mm-01", "mm-+1", "mm-4294967296", "mm-../7", "mm-7;reboot", "mm-bad-7", "mm-0123456789abcdef0123456789abcdef-7-extra"} {
		if _, _, ok := ParseMMCallID(id); ok {
			t.Fatalf("accepted %q", id)
		}
	}
}
