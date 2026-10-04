package localadmin

import (
	"strings"
	"testing"
)

func TestOwnerSetupProofDisappearsAfterPasswordCreation(t *testing.T) {
	a, err := Open(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	configured, proof := a.OwnerSetup()
	if configured || len(proof) != 43 {
		t.Fatal("missing first setup proof")
	}
	public := call(t, a.Wrap(nil), "/admin/session", "GET", nil, nil, "", "")
	if strings.Contains(public.Body.String(), proof) {
		t.Fatal("public session leaked proof")
	}
	login(t, a, "a-private-management-password")
	configured, proof = a.OwnerSetup()
	if !configured || proof != "" {
		t.Fatal("configured device still provides proof")
	}
}
