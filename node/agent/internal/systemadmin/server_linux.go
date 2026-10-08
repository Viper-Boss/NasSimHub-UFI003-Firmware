//go:build linux

package systemadmin

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Runner func(context.Context, string, string, ...string) (string, error)
type Manager struct {
	Root string
	Run  Runner
	mu   sync.Mutex
}

func command(ctx context.Context, input, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	b, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if name == "/usr/bin/systemctl" && strings.Contains(string(exit.Stderr), "not enough space") {
				return "", errors.New("insufficient /run space; remove temporary staging files and retry manually")
			}
			if name == "/usr/sbin/userdel" && exit.ExitCode() == 8 {
				return "", errors.New("account has running processes; stop its sessions or programs before deleting it")
			}
		}
		return "", errors.New("system command failed; check installed packages or account state")
	}
	if len(b) > 64<<10 {
		return "", errors.New("system response too large")
	}
	return string(b), nil
}
func (m *Manager) path(p string) string { return filepath.Join(m.Root, p) }
func (m *Manager) exec(ctx context.Context, input, name string, args ...string) (string, error) {
	run := m.Run
	if run == nil {
		run = command
	}
	return run(ctx, input, name, args...)
}
func (m *Manager) dir() string { return m.path("/etc/nassimhub/system-admin") }
func (m *Manager) prepare() error {
	// All ancestors of the credential directory must belong to root and be
	// non-writable by ordinary users. Never follow an untrusted symlink.
	for _, p := range []string{m.path("/etc"), m.path("/etc/nassimhub"), m.dir(), filepath.Join(m.dir(), "keys")} {
		if err := os.Mkdir(p, 0755); err != nil && !os.IsExist(err) {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe system administration directory")
		}
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil || st.Uid != 0 {
			return errors.New("system administration directory must be root-owned")
		}
		// sshd reads public authorized_keys after switching to the login UID.
		// Only our public-key directories need to be traversable; private files
		// remain 0600. Do not widen the pre-existing parent configuration dir.
		if p == m.dir() || p == filepath.Join(m.dir(), "keys") {
			if err := os.Chmod(p, 0755); err != nil {
				return err
			}
		}
	}
	return nil
}
func readRegular(p string) ([]byte, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 128<<10 {
		return nil, errors.New("invalid system file")
	}
	return os.ReadFile(p)
}
func writeAtomic(p string, b []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(p), ".system-admin-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), p)
}
func (m *Manager) accounts() ([]Account, error) {
	passwd, e := readRegular(m.path("/etc/passwd"))
	if e != nil {
		return nil, e
	}
	shadow, e := readRegular(m.path("/etc/shadow"))
	if e != nil {
		return nil, e
	}
	locked := map[string]bool{}
	for _, line := range strings.Split(string(shadow), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 8 {
			locked[f[0]] = strings.HasPrefix(f[1], "!") || strings.HasPrefix(f[1], "*") || f[1] == "" || f[7] == "1"
		}
	}
	groups, e := readRegular(m.path("/etc/group"))
	if e != nil {
		return nil, e
	}
	sudo := map[string]bool{}
	for _, line := range strings.Split(string(groups), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 4 && f[0] == "sudo" {
			for _, name := range strings.Split(f[3], ",") {
				sudo[name] = true
			}
		}
	}
	result := []Account{}
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) != 7 {
			continue
		}
		uid, e := strconv.Atoi(f[2])
		if e != nil || (uid < 1000 && f[0] != "root") || uid >= 65534 || !userName.MatchString(f[0]) || f[0] == "nassimhub" {
			continue
		}
		keys := []string{}
		b, e := readRegular(filepath.Join(m.dir(), "keys", f[0]))
		if e == nil {
			for _, key := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if validKey(key) {
					keys = append(keys, key)
				}
			}
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		result = append(result, Account{Name: f[0], UID: uid, Home: f[5], Shell: f[6], Locked: locked[f[0]] || !strings.Contains(string(shadow), "\n"+f[0]+":"), Sudo: sudo[f[0]], Keys: keys})
	}
	return result, nil
}
func shadowEntry(shadow []byte, name string) bool {
	for _, line := range strings.Split(string(shadow), "\n") {
		if strings.HasPrefix(line, name+":") {
			return true
		}
	}
	return false
}
func (m *Manager) settings() (SSHSettings, error) {
	v := SSHSettings{Port: 2222}
	b, e := readRegular(filepath.Join(m.dir(), "settings.json"))
	if os.IsNotExist(e) {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	if e = json.Unmarshal(b, &v); e != nil {
		return v, e
	}
	if e = Validate(Request{Action: "ssh", SSH: &v}); e != nil {
		return v, e
	}
	return v, nil
}
func (m *Manager) status(ctx context.Context) (Status, error) {
	a, e := m.accounts()
	if e != nil {
		return Status{}, e
	}
	v, e := m.settings()
	if e != nil {
		return Status{}, e
	}
	_, active := m.exec(ctx, "", "/usr/bin/systemctl", "is-active", "--quiet", Unit)
	fingerprint := ""
	if _, e := os.Stat(filepath.Join(m.dir(), "ssh_host_ed25519_key.pub")); e == nil {
		out, e := m.exec(ctx, "", "/usr/bin/ssh-keygen", "-lf", filepath.Join(m.dir(), "ssh_host_ed25519_key.pub"))
		if e == nil {
			f := strings.Fields(out)
			if len(f) > 1 {
				fingerprint = f[1]
			}
		}
	}
	return Status{Accounts: a, SSH: v, Running: active == nil, HostFingerprint: fingerprint}, nil
}
func sshConfig(v SSHSettings, dir string, accounts []Account) string {
	names := []string{}
	for _, a := range accounts {
		if a.Name == "root" {
			if v.RootLogin {
				names = append(names, "root")
			}
		} else if a.Shell == "/bin/bash" || a.Shell == "/bin/sh" {
			names = append(names, a.Name)
		}
	}
	// An empty AllowUsers cannot mean "allow everybody".
	if len(names) == 0 {
		names = []string{"nsh-no-login-users"}
	}
	root := "no"
	if v.RootLogin {
		root = "prohibit-password"
	}
	password := "no"
	if v.PasswordLogin {
		password = "yes"
	}
	return "Port " + strconv.Itoa(v.Port) + "\nHostKey " + dir + "/ssh_host_ed25519_key\nAuthorizedKeysFile " + dir + "/keys/%u\nPermitRootLogin " + root + "\nPasswordAuthentication " + password + "\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nPubkeyAuthentication yes\nUsePAM yes\nStrictModes yes\nAllowUsers " + strings.Join(names, " ") + "\nLoginGraceTime 30\nMaxAuthTries 3\nMaxSessions 8\nSubsystem sftp internal-sftp\n"
}
func (m *Manager) applySSH(ctx context.Context, v SSHSettings) error {
	old, e := m.settings()
	if e != nil {
		return e
	}
	accounts, e := m.accounts()
	if e != nil {
		return e
	}
	key := filepath.Join(m.dir(), "ssh_host_ed25519_key")
	if _, e := os.Lstat(key); os.IsNotExist(e) {
		if _, e = m.exec(ctx, "", "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	var keyStat unix.Stat_t
	if e = unix.Lstat(key, &keyStat); e != nil || keyStat.Uid != 0 || keyStat.Mode&unix.S_IFMT != unix.S_IFREG || keyStat.Mode&0077 != 0 {
		return errors.New("unsafe SSH host key")
	}
	if e = os.MkdirAll(m.path("/run/sshd"), 0755); e != nil {
		return e
	}
	conf := filepath.Join(m.dir(), "sshd_config")
	candidate := conf + ".candidate"
	if e = writeAtomic(candidate, []byte(sshConfig(v, m.dir(), accounts)), 0600); e != nil {
		return e
	}
	defer os.Remove(candidate)
	if _, e = m.exec(ctx, "", "/usr/sbin/sshd", "-t", "-f", candidate); e != nil {
		return errors.New("SSH configuration check failed; previous configuration retained")
	}
	previous, e := readRegular(conf)
	existed := e == nil
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if e = os.Rename(candidate, conf); e != nil {
		return e
	}
	action := "disable"
	if v.Enabled {
		action = "enable"
	}
	_, e = m.exec(ctx, "", "/usr/bin/systemctl", action, "--now", Unit)
	if e == nil && v.Enabled {
		_, e = m.exec(ctx, "", "/usr/bin/systemctl", "reload-or-restart", Unit)
	}
	if e == nil {
		b, _ := json.Marshal(v)
		e = writeAtomic(filepath.Join(m.dir(), "settings.json"), b, 0600)
	}
	if e != nil {
		var configRestoreErr error
		if existed {
			configRestoreErr = writeAtomic(conf, previous, 0600)
		} else {
			configRestoreErr = os.Remove(conf)
			if os.IsNotExist(configRestoreErr) {
				configRestoreErr = nil
			}
		}
		restore := "disable"
		if old.Enabled {
			restore = "enable"
		}
		_, restoreErr := m.exec(context.Background(), "", "/usr/bin/systemctl", restore, "--now", Unit)
		if restoreErr == nil && old.Enabled {
			_, restoreErr = m.exec(context.Background(), "", "/usr/bin/systemctl", "reload-or-restart", Unit)
		}
		if restoreErr != nil || configRestoreErr != nil {
			return errors.New("SSH change failed and recovery needs local maintenance")
		}
		return errors.New("SSH change failed; previous configuration restored")
	}
	return nil
}
func (m *Manager) Execute(ctx context.Context, r Request) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := Validate(r); e != nil {
		return Status{}, e
	}
	if e := m.prepare(); e != nil {
		return Status{}, e
	}
	if r.Action == "status" {
		return m.status(ctx)
	}
	if r.Action == "ssh" {
		if e := m.applySSH(ctx, *r.SSH); e != nil {
			return Status{}, e
		}
		return m.status(ctx)
	}
	accounts, e := m.accounts()
	if e != nil {
		return Status{}, e
	}
	var account *Account
	for i := range accounts {
		if accounts[i].Name == r.User {
			account = &accounts[i]
		}
	}
	if r.Action == "create" {
		if account != nil {
			return Status{}, errors.New("account already exists")
		}
		if _, e := os.Lstat(m.path("/home/" + r.User)); !os.IsNotExist(e) {
			return Status{}, errors.New("home directory already exists or cannot be checked")
		}
		// No shell, inherited environment or caller-selected home/UID.
		if _, e = m.exec(ctx, "", "/usr/sbin/useradd", "-m", "-U", "-s", "/bin/bash", r.User); e != nil {
			return Status{}, e
		}
		if _, e = m.exec(ctx, r.User+":"+r.Password+"\n", "/usr/sbin/chpasswd"); e != nil {
			return Status{}, errors.New("account created locked; password setup failed, retry password operation")
		}
	} else {
		if account == nil {
			return Status{}, errors.New("account not found or protected")
		}
		switch r.Action {
		case "password":
			_, e = m.exec(ctx, r.User+":"+r.Password+"\n", "/usr/sbin/chpasswd")
		case "sudo":
			if account.Sudo != r.Enabled {
				arg := "-d"
				if r.Enabled {
					arg = "-a"
				}
				_, e = m.exec(ctx, "", "/usr/bin/gpasswd", arg, r.User, "sudo")
			}
		case "lock":
			if r.Enabled {
				_, e = m.exec(ctx, "", "/usr/sbin/usermod", "-L", "-e", "1", r.User)
			} else {
				_, e = m.exec(ctx, "", "/usr/sbin/usermod", "-U", "-e", "", r.User)
			}
		case "delete":
			_, e = m.exec(ctx, "", "/usr/sbin/userdel", r.User)
			if e == nil {
				e = os.Remove(filepath.Join(m.dir(), "keys", r.User))
				if os.IsNotExist(e) {
					e = nil
				}
			}
		case "keys":
			e = writeAtomic(filepath.Join(m.dir(), "keys", r.User), []byte(strings.Join(r.Keys, "\n")+"\n"), 0644)
		}
		if e != nil {
			return Status{}, e
		}
	}
	// Account existence affects AllowUsers. Apply the current policy, never
	// enable SSH as a side effect of creating or changing an account.
	v, e := m.settings()
	if e != nil {
		return Status{}, e
	}
	if v.Enabled {
		if e = m.applySSH(ctx, v); e != nil {
			return Status{}, errors.New("account updated; SSH policy reload failed, check SSH settings")
		}
	}
	return m.status(ctx)
}

func Serve() error {
	if os.Geteuid() != 0 {
		return errors.New("system manager must run as root")
	}
	account, e := user.Lookup("nassimhub")
	if e != nil {
		return e
	}
	uid, e := strconv.Atoi(account.Uid)
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(account.Gid)
	if e != nil {
		return e
	}
	// RuntimeDirectory is supplied by the root-owned systemd service.
	dir := filepath.Dir(Socket)
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe socket directory")
	}
	var dirStat unix.Stat_t
	if e = unix.Lstat(dir, &dirStat); e != nil || dirStat.Uid != 0 {
		return errors.New("socket directory must be root-owned")
	}
	if info, e := os.Lstat(Socket); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("unexpected control socket path")
		}
		if e = os.Remove(Socket); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: Socket, Net: "unix"})
	if e != nil {
		return e
	}
	defer listener.Close()
	if e = os.Chown(Socket, 0, gid); e != nil {
		return e
	}
	if e = os.Chmod(Socket, 0660); e != nil {
		return e
	}
	manager := &Manager{}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		allowed := false
		if u, ok := c.(*net.UnixConn); ok {
			raw, e := u.SyscallConn()
			if e == nil {
				_ = raw.Control(func(fd uintptr) {
					cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
					allowed = e == nil && cred.Uid == uint32(uid)
				})
			}
		}
		return context.WithValue(ctx, peerKey{}, allowed)
	}}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if ok, _ := r.Context().Value(peerKey{}).(bool); !ok {
			w.WriteHeader(403)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/control" {
			w.WriteHeader(404)
			return
		}
		var request Request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		d.DisallowUnknownFields()
		if e := d.Decode(&request); e != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})
			return
		}
		if d.Decode(&struct{}{}) != io.EOF {
			w.WriteHeader(400)
			return
		}
		result, e := manager.Execute(r.Context(), request)
		if e != nil {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	return server.Serve(listener)
}

type peerKey struct{}
