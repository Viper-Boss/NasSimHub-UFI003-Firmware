//go:build linux

package systemadmin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (*Manager, *[]string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned fixture requires root")
	}
	root := t.TempDir()
	for _, d := range []string{"etc", "home"} {
		if e := os.Mkdir(filepath.Join(root, d), 0755); e != nil {
			t.Fatal(e)
		}
	}
	for name, b := range map[string]string{"passwd": "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nnassimhub:x:101:103::/:/usr/sbin/nologin\n", "shadow": "root:!:1:0:99999:7:::\nalice:$hash:1:0:99999:7:::\n", "group": "sudo:x:27:alice\n"} {
		if e := os.WriteFile(filepath.Join(root, "etc", name), []byte(b), 0600); e != nil {
			t.Fatal(e)
		}
	}
	calls := []string{}
	m := &Manager{Root: root}
	m.Run = func(_ context.Context, input, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "/usr/bin/ssh-keygen" && len(args) > 1 && args[0] == "-q" {
			if e := os.WriteFile(args[len(args)-1], []byte("private"), 0600); e != nil {
				return "", e
			}
		}
		if strings.Contains(name, "systemctl") && len(args) > 0 && args[0] == "is-active" {
			return "", errors.New("inactive")
		}
		return "", nil
	}
	return m, &calls
}
func TestPasswordsOnlyOnStdinAndHomePreserved(t *testing.T) {
	m, calls := fixture(t)
	old := m.Run
	m.Run = func(ctx context.Context, input, name string, args ...string) (string, error) {
		if name == "/usr/sbin/chpasswd" && input != "root:abcdefghijkl\n" {
			t.Fatal("incorrect stdin")
		}
		for _, a := range args {
			if strings.Contains(a, "abcdefghijkl") {
				t.Fatal("password in argv")
			}
		}
		return old(ctx, input, name, args...)
	}
	if _, e := m.Execute(context.Background(), Request{Action: "password", User: "root", Password: "abcdefghijkl"}); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Execute(context.Background(), Request{Action: "delete", User: "alice"}); e != nil {
		t.Fatal(e)
	}
	for _, c := range *calls {
		if strings.Contains(c, "userdel") && c != "/usr/sbin/userdel alice" {
			t.Fatal(c)
		}
		if strings.Contains(c, "enable") {
			t.Fatal("account mutation enabled SSH")
		}
	}
}
func TestSSHValidationFailureRetainsConfig(t *testing.T) {
	m, _ := fixture(t)
	if e := m.prepare(); e != nil {
		t.Fatal(e)
	}
	conf := filepath.Join(m.dir(), "sshd_config")
	os.WriteFile(conf, []byte("old"), 0600)
	old := m.Run
	m.Run = func(ctx context.Context, input, name string, args ...string) (string, error) {
		if name == "/usr/sbin/sshd" {
			return "", errors.New("invalid")
		}
		return old(ctx, input, name, args...)
	}
	if _, e := m.Execute(context.Background(), Request{Action: "ssh", SSH: &SSHSettings{Port: 2222, Enabled: true}}); e == nil {
		t.Fatal("expected failure")
	}
	b, _ := os.ReadFile(conf)
	if string(b) != "old" {
		t.Fatal("lost old config")
	}
}
func TestSSHStartFailureRollsBack(t *testing.T) {
	m, calls := fixture(t)
	m.prepare()
	conf := filepath.Join(m.dir(), "sshd_config")
	os.WriteFile(conf, []byte("old"), 0600)
	old := m.Run
	m.Run = func(ctx context.Context, input, name string, args ...string) (string, error) {
		if name == "/usr/bin/systemctl" && args[0] == "enable" {
			*calls = append(*calls, "failed enable")
			return "", errors.New("port busy")
		}
		return old(ctx, input, name, args...)
	}
	if _, e := m.Execute(context.Background(), Request{Action: "ssh", SSH: &SSHSettings{Port: 2222, Enabled: true}}); e == nil {
		t.Fatal("expected failure")
	}
	b, _ := os.ReadFile(conf)
	if string(b) != "old" {
		t.Fatal("rollback failed")
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "disable --now "+Unit) {
		t.Fatal("service not restored")
	}
}
func TestUnsafeDirectoriesAndKeysRejected(t *testing.T) {
	m, _ := fixture(t)
	os.Symlink("/tmp", m.path("/etc/nassimhub"))
	if _, e := m.Execute(context.Background(), Request{Action: "status"}); e == nil {
		t.Fatal("symlink allowed")
	}
	m, _ = fixture(t)
	m.prepare()
	os.Symlink("/etc/passwd", filepath.Join(m.dir(), "ssh_host_ed25519_key"))
	if _, e := m.Execute(context.Background(), Request{Action: "ssh", SSH: &SSHSettings{Port: 2222}}); e == nil {
		t.Fatal("symlink hostkey allowed")
	}
}
func TestSSHRootKeyOnlyAndExplicitAccounts(t *testing.T) {
	s := sshConfig(SSHSettings{Port: 2222, RootLogin: true, PasswordLogin: true}, "/etc/nassimhub/system-admin", []Account{{Name: "root"}, {Name: "alice", Shell: "/bin/bash"}, {Name: "daemon", Shell: "/usr/sbin/nologin"}})
	for _, want := range []string{"PermitRootLogin prohibit-password\n", "AllowUsers root alice\n", "PasswordAuthentication yes\n"} {
		if !strings.Contains(s, want) {
			t.Fatal(s)
		}
	}
	if strings.Contains(s, "daemon") {
		t.Fatal("service account exposed")
	}
}

func TestPublicKeyDirectoriesTraversableUnderRestrictiveUmask(t *testing.T) {
	m, _ := fixture(t)
	if e := m.prepare(); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{m.dir(), filepath.Join(m.dir(), "keys")} {
		if e := os.Chmod(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := m.prepare(); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{m.dir(), filepath.Join(m.dir(), "keys")} {
		st, e := os.Stat(p)
		if e != nil || st.Mode().Perm() != 0755 {
			t.Fatalf("public keys inaccessible: %s", p)
		}
	}
}
