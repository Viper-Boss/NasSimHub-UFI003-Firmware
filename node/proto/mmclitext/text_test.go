package mmclitext

import "testing"

func TestGLibRoundTripAndSingleDecode(t *testing.T) {
	for _, s := range []string{"你好【中文】😀", "666", "line1\nline2\tquote\"", `literal\343\200 and C:\temp`} {
		encoded := Encode(s)
		got, ok := Decode(encoded)
		if !ok || got != s {
			t.Fatalf("roundtrip failed: %q -> %q", s, got)
		}
	}
}
func TestMalformedEscapesPreserveOriginal(t *testing.T) {
	for _, s := range []string{`\400`, `\34`, `\377`, `\q`, `trailing\`} {
		got, ok := Decode(s)
		if ok || got != s {
			t.Fatal("invalid input was changed")
		}
	}
}
func TestKnownUTF8Octal(t *testing.T) {
	got, ok := Decode(`\343\200\220\344\275\240\345\245\275\343\200\221`)
	if !ok || got != "【你好】" {
		t.Fatal(got, ok)
	}
}
