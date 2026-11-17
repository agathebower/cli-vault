// Package server is the request handler of vaultd. It holds the vault AES
// key in memory; the key is never sent over the socket. The vault file is
// decrypted per request and re-encrypted on every change.
//
// The server expires after IdleTimeout without a credential request
// (add/get/list/rm; status pings don't count) or MaxLifetime after start,
// whichever comes first. Both use wall-clock time, so time spent in
// suspend counts.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	vcrypto "vault-system/pkg/crypto"
	"vault-system/pkg/ipc"
	"vault-system/pkg/vaultfile"
)

const (
	MaxKeyLen   = 256
	MaxValueLen = 512 * 1024
)

// ErrPermission is sent to peers whose UID differs from AllowedUID.
var ErrPermission = errors.New("permission denied")

type Server struct {
	key       []byte
	vaultPath string
	headLen   int
	KeyType   string
	Started   time.Time
	// AllowedUID is the only UID accepted on the socket (default: our own).
	AllowedUID int
	// IdleTimeout / MaxLifetime: 0 disables.
	IdleTimeout time.Duration
	MaxLifetime time.Duration

	lastActive atomic.Int64 // unix nanos (wall clock)
	mu         sync.Mutex   // serializes read-modify-write of the vault file
}

func New(key []byte, vaultPath string, headLen int, keyType string) *Server {
	s := &Server{key: key, vaultPath: vaultPath, headLen: headLen, KeyType: keyType,
		Started: time.Now().Round(0), AllowedUID: os.Getuid()}
	s.touch()
	return s
}

func (s *Server) touch() { s.lastActive.Store(time.Now().UnixNano()) }

// ExpiresAt is when the server shuts down; zero time if never.
func (s *Server) ExpiresAt() time.Time {
	var t time.Time
	if s.IdleTimeout > 0 {
		t = time.Unix(0, s.lastActive.Load()).Add(s.IdleTimeout)
	}
	if s.MaxLifetime > 0 {
		if m := s.Started.Add(s.MaxLifetime); t.IsZero() || m.Before(t) {
			t = m
		}
	}
	return t
}

// WaitExpired blocks until the server has expired. It re-checks the wall
// clock at least every 5s, so a resume from suspend is noticed quickly.
func (s *Server) WaitExpired() {
	for {
		exp := s.ExpiresAt()
		if exp.IsZero() {
			time.Sleep(time.Hour)
			continue
		}
		left := exp.Sub(time.Now().Round(0))
		if left <= 0 {
			return
		}
		time.Sleep(min(left, 5*time.Second))
	}
}

// Verify checks that the key decrypts the vault file.
func (s *Server) Verify() error {
	f, err := vaultfile.Load(s.vaultPath)
	if err != nil {
		return err
	}
	_, err = f.Open(s.headLen, s.key)
	return err
}

// Wipe zeroes the in-memory key.
func (s *Server) Wipe() {
	s.mu.Lock()
	vcrypto.Zero(s.key)
	s.mu.Unlock()
}

// Serve accepts connections until l is closed.
func (s *Server) Serve(l *net.UnixListener) error {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.HandleConn(c)
	}
}

// CheckPeer enforces that the connecting process runs as uid (SO_PEERCRED).
func CheckPeer(c *net.UnixConn, uid int) error {
	cred, err := ipc.PeerCred(c)
	if err != nil || int(cred.Uid) != uid {
		return ErrPermission
	}
	return nil
}

// HandleConn serves exactly one request on c and closes it.
func (s *Server) HandleConn(c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	enc := json.NewEncoder(c)

	if err := CheckPeer(c, s.AllowedUID); err != nil {
		enc.Encode(ipc.Response{OK: false, Error: err.Error()})
		return
	}

	var req ipc.Request
	dec := json.NewDecoder(io.LimitReader(c, ipc.MaxMessage))
	if err := dec.Decode(&req); err != nil {
		enc.Encode(ipc.Response{Error: "bad request"})
		return
	}
	enc.Encode(s.handle(&req))
}

func (s *Server) handle(req *ipc.Request) ipc.Response {
	fail := func(msg string) ipc.Response { return ipc.Response{Error: msg} }

	if req.Op != "ping" {
		s.touch()
	}
	switch req.Op {
	case "ping":
		r := ipc.Response{OK: true, PID: os.Getpid(), StartedAt: s.Started.Unix(), KeyType: s.KeyType,
			IdleTimeout: int64(s.IdleTimeout.Seconds()), MaxLifetime: int64(s.MaxLifetime.Seconds())}
		if exp := s.ExpiresAt(); !exp.IsZero() {
			r.ExpiresAt = exp.Unix()
		}
		return r

	case "get":
		if err := checkKey(req.Key); err != nil {
			return fail(err.Error())
		}
		p, _, err := s.load()
		if err != nil {
			return fail(err.Error())
		}
		v, ok := p.Credentials[req.Key]
		if !ok {
			return fail("not found: " + req.Key)
		}
		return ipc.Response{OK: true, Value: v}

	case "list":
		p, _, err := s.load()
		if err != nil {
			return fail(err.Error())
		}
		keys := make([]string, 0, len(p.Credentials))
		for k := range p.Credentials {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return ipc.Response{OK: true, Keys: keys}

	case "add", "delete":
		if err := checkKey(req.Key); err != nil {
			return fail(err.Error())
		}
		if req.Op == "add" {
			if len(req.Value) > MaxValueLen {
				return fail("value too large")
			}
			if !utf8.ValidString(req.Value) {
				return fail("value must be valid UTF-8")
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		p, f, err := s.loadLocked()
		if err != nil {
			return fail(err.Error())
		}
		if req.Op == "add" {
			p.Credentials[req.Key] = req.Value
		} else {
			if _, ok := p.Credentials[req.Key]; !ok {
				return fail("not found: " + req.Key)
			}
			delete(p.Credentials, req.Key)
		}
		data, err := f.Reseal(s.headLen, s.key, p)
		if err != nil {
			return fail("encrypting vault: " + err.Error())
		}
		if err := vaultfile.WriteAtomic(s.vaultPath, data); err != nil {
			return fail("writing vault: " + err.Error())
		}
		return ipc.Response{OK: true}
	}
	return fail("unknown op")
}

func (s *Server) load() (*vaultfile.Payload, *vaultfile.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Server) loadLocked() (*vaultfile.Payload, *vaultfile.File, error) {
	f, err := vaultfile.Load(s.vaultPath)
	if err != nil {
		return nil, nil, err
	}
	p, err := f.Open(s.headLen, s.key)
	if err != nil {
		return nil, nil, err
	}
	return p, f, nil
}

func checkKey(k string) error {
	if k == "" {
		return errors.New("empty key")
	}
	if len(k) > MaxKeyLen || !utf8.ValidString(k) {
		return errors.New("invalid key")
	}
	return nil
}
