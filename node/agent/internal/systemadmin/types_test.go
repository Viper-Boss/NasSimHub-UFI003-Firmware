package systemadmin

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func testKey() string {
	b := make([]byte, 51)
	binary.BigEndian.PutUint32(b[:4], 11)
	copy(b[4:], "ssh-ed25519")
	binary.BigEndian.PutUint32(b[15:19], 32)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b) + " test"
}
func TestRequestsRejectPrivilegeAndInjection(t *testing.T) {
	for _, r := range []Request{{Action: "create", User: "root", Password: "abcdefghijkl"}, {Action: "delete", User: "root"}, {Action: "sudo", User: "nassimhub", Enabled: true}, {Action: "create", User: "--help", Password: "abcdefghijkl"}, {Action: "password", User: "alice", Password: "abcdefghijkl\nroot:bad"}, {Action: "keys", User: "alice", Keys: []string{"command=\"id\" " + testKey()}}, {Action: "keys", User: "alice", Keys: []string{testKey() + "\n"}}, {Action: "ssh", SSH: &SSHSettings{Port: 22}}, {Action: "ssh", SSH: &SSHSettings{Port: 7581}}, {Action: "status", User: "root"}, {Action: "exec", User: "alice"}} {
		if Validate(r) == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	for _, r := range []Request{{Action: "status"}, {Action: "password", User: "root", Password: "abcdefghijkl"}, {Action: "keys", User: "root", Keys: []string{testKey()}}, {Action: "keys", User: "alice", Keys: []string{}}, {Action: "ssh", SSH: &SSHSettings{Port: 2222}}} {
		if e := Validate(r); e != nil {
			t.Fatal(e)
		}
	}
}
