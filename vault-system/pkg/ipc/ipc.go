// Package ipc contains the socket protocol between the vault CLI and vaultd:
// one JSON request and one JSON response per connection over a Unix socket
// at $XDG_RUNTIME_DIR/vault.sock.
package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	SocketName = "vault.sock"
	PIDName    = "vault.pid"

	// MaxMessage bounds request/response size.
	MaxMessage = 1 << 20
)

// ErrNotRunning means no daemon is listening on the socket.
var ErrNotRunning = errors.New("vaultd not running")

type Request struct {
	Op    string `json:"op"`
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type Response struct {
	OK        bool     `json:"ok"`
	Value     string   `json:"value,omitempty"`
	Error     string   `json:"error,omitempty"`
	PID       int      `json:"pid,omitempty"`
	StartedAt int64    `json:"started_at,omitempty"`
	KeyType   string   `json:"keytype,omitempty"`
	Keys      []string `json:"keys,omitempty"`
	// ping: seconds (0 = disabled) and unix time of the automatic shutdown (0 = never)
	IdleTimeout int64 `json:"idle_timeout,omitempty"`
	MaxLifetime int64 `json:"max_lifetime,omitempty"`
	ExpiresAt   int64 `json:"expires_at,omitempty"`
}

// RuntimeDir returns $XDG_RUNTIME_DIR, or /tmp/vault-<uid> (created 0700)
// if it is unset. The directory must be owned by us and not group/world
// accessible.
func RuntimeDir() (string, error) {
	uid := os.Getuid()
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "vault-"+strconv.Itoa(uid))
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("runtime dir: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != uid {
		return "", fmt.Errorf("runtime dir %s is not a directory owned by uid %d", dir, uid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("runtime dir %s has unsafe permissions %o (want 0700)", dir, fi.Mode().Perm())
	}
	return dir, nil
}

func SocketPath() (string, error) {
	d, err := RuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, SocketName), nil
}

func PIDPath() (string, error) {
	d, err := RuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, PIDName), nil
}

// PeerCred returns the credentials of the process on the other end of c
// (SO_PEERCRED, filled in by the kernel at connect time).
func PeerCred(c *net.UnixConn) (*syscall.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, credErr
}

// Call sends one request to the daemon and returns its response. It also
// verifies that the daemon runs as the same user (mutual SO_PEERCRED).
func Call(req Request) (*Response, error) {
	sock, err := SocketPath()
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, ErrNotRunning
		}
		return nil, fmt.Errorf("cannot connect to vaultd: %w", err)
	}
	uc := conn.(*net.UnixConn)
	defer uc.Close()

	cred, err := PeerCred(uc)
	if err != nil {
		return nil, fmt.Errorf("cannot verify vaultd identity: %w", err)
	}
	if int(cred.Uid) != os.Getuid() {
		return nil, fmt.Errorf("refusing to talk to socket owned by uid %d", cred.Uid)
	}

	uc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(uc).Encode(req); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(uc, MaxMessage)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return &resp, nil
}
