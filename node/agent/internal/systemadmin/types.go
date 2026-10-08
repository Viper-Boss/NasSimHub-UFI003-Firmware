// Package systemadmin is the bounded Unix-socket interface to device account
// administration. It never accepts commands, paths or password hashes.
package systemadmin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const Socket = "/run/nassimhub-system-admin/control.sock"
const Unit = "nassimhub-user-ssh.service"

type Request struct {
	Action   string       `json:"action"`
	User     string       `json:"user,omitempty"`
	Password string       `json:"password,omitempty"`
	Enabled  bool         `json:"enabled,omitempty"`
	Keys     []string     `json:"keys,omitempty"`
	SSH      *SSHSettings `json:"ssh,omitempty"`
}
type SSHSettings struct {
	Enabled       bool `json:"enabled"`
	Port          int  `json:"port"`
	PasswordLogin bool `json:"password_login"`
	RootLogin     bool `json:"root_login"`
}
type Account struct {
	Name   string   `json:"name"`
	UID    int      `json:"uid"`
	Home   string   `json:"home"`
	Shell  string   `json:"shell"`
	Locked bool     `json:"locked"`
	Sudo   bool     `json:"sudo"`
	Keys   []string `json:"keys"`
}
type Status struct {
	Accounts        []Account   `json:"accounts"`
	SSH             SSHSettings `json:"ssh"`
	Running         bool        `json:"running"`
	HostFingerprint string      `json:"host_fingerprint,omitempty"`
}

var userName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)

func Validate(r Request) error {
	if r.Action == "status" {
		if r.User != "" || r.Password != "" || len(r.Keys) > 0 || r.SSH != nil || r.Enabled {
			return errors.New("status takes no arguments")
		}
		return nil
	}
	if r.Action == "ssh" {
		if r.SSH == nil || r.User != "" || r.Password != "" || len(r.Keys) > 0 || r.Enabled {
			return errors.New("invalid SSH request")
		}
		if r.SSH.Port < 1024 || r.SSH.Port > 65535 || r.SSH.Port == 7580 || r.SSH.Port == 7581 {
			return errors.New("SSH port must be 1024-65535, excluding management ports")
		}
		return nil
	}
	if !userName.MatchString(r.User) || r.User == "nassimhub" || r.SSH != nil {
		return errors.New("invalid or protected account")
	}
	switch r.Action {
	case "create", "password":
		if r.Action == "create" && r.User == "root" {
			return errors.New("root already exists")
		}
		if len(r.Password) < 12 || len(r.Password) > 256 || strings.ContainsAny(r.Password, "\x00\r\n:") || len(r.Keys) > 0 || r.Enabled {
			return errors.New("password must be 12-256 bytes without line breaks or colon")
		}
	case "sudo", "lock", "delete":
		if r.User == "root" || r.Password != "" || len(r.Keys) > 0 || (r.Action == "delete" && r.Enabled) {
			return errors.New("protected account or invalid request")
		}
	case "keys":
		if len(r.Keys) > 10 || r.Password != "" || r.Enabled {
			return errors.New("invalid key request")
		}
		for _, key := range r.Keys {
			if !validKey(key) {
				return errors.New("only plain Ed25519 public keys are accepted")
			}
		}
	default:
		return errors.New("unsupported system operation")
	}
	return nil
}
func validKey(key string) bool {
	if len(key) > 512 || strings.ContainsAny(key, "\r\n\x00") {
		return false
	}
	f := strings.Fields(key)
	if len(f) < 2 || f[0] != "ssh-ed25519" {
		return false
	}
	raw, e := base64.StdEncoding.DecodeString(f[1])
	if e != nil || len(raw) != 51 {
		return false
	}
	return binary.BigEndian.Uint32(raw[:4]) == 11 && string(raw[4:15]) == "ssh-ed25519" && binary.BigEndian.Uint32(raw[15:19]) == 32
}

type Client struct{ Path string }

func (c Client) Execute(ctx context.Context, r Request) (Status, error) {
	var result Status
	if err := Validate(r); err != nil {
		return result, err
	}
	path := c.Path
	if path == "" {
		path = Socket
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer tr.CloseIdleConnections()
	b, _ := json.Marshal(r)
	req, e := http.NewRequestWithContext(ctx, "POST", "http://localhost/control", bytes.NewReader(b))
	if e != nil {
		return result, e
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := (&http.Client{Transport: tr, Timeout: 25 * time.Second}).Do(req)
	if e != nil {
		return result, errors.New("system administration service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		var v struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 2048)).Decode(&v)
		if v.Error == "" {
			v.Error = "system operation failed"
		}
		return result, errors.New(v.Error)
	}
	e = json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result)
	return result, e
}
