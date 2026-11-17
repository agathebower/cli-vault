// Package vaultfile implements the on-disk vault format (v2):
//
//	head ‖ nonce(12) ‖ AES-256-GCM ciphertext       (head is the GCM AAD)
//
// head depends on how the vault is unlocked and is the only thing needed
// to recover the AES key:
//
//	password        16-byte PBKDF2 salt
//	ssh-rsa         RSA-OAEP wrapped key (modulus size, e.g. 256 bytes)
//	ssh-ed25519     32-byte ephemeral X25519 public key
//	ssh-ecdsa-p256  32-byte X coordinate of the ephemeral P-256 key (even Y)
//
// There is no magic, version, keytype, public key or any other plaintext
// field: every byte of the file is a salt, a key-wrapping value, a nonce or
// ciphertext, so the file is indistinguishable from random data. The
// unlock method is supplied by the user (--password / --key) and tells us
// how long head is. A wrong method fails like a wrong password.
//
// The file name is derived per machine and user (see DefaultPath), so it
// does not reveal what it is either.
package vaultfile

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vault-system/pkg/crypto"
)

const (
	KeyTypePassword = "password"
	KeyTypeRSA      = "ssh-rsa"
	KeyTypeEd25519  = "ssh-ed25519"
	KeyTypeECDSA    = "ssh-ecdsa-p256"

	// PBKDF2Iterations for password vaults (fixed: the format stores no
	// parameters).
	PBKDF2Iterations = 100000
	// SaltSize is the head length of password vaults.
	SaltSize = 16

	gcmOverhead = 12 + 16
)

// ErrDecrypt means the vault could not be decrypted with the given key.
var ErrDecrypt = errors.New("failed to decrypt vault (wrong password or key)")

// Payload is the encrypted part of the vault.
type Payload struct {
	Credentials map[string]string `json:"credentials"`
}

// File is a raw (still encrypted) vault file.
type File struct{ data []byte }

// DefaultPath returns ~/.local/share/.<16 hex chars> for the current user.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return PathFor(home, os.Getuid()), nil
}

// PathFor derives the vault path: the name is HMAC-SHA256(machine-id,
// "vault-file:" uid), truncated to 8 bytes. It is stable for a machine and
// user, needs no pointer file, and looks like any other cache blob.
func PathFor(home string, uid int) string {
	mac := hmac.New(sha256.New, machineID())
	mac.Write([]byte("vault-file:" + strconv.Itoa(uid)))
	name := "." + hex.EncodeToString(mac.Sum(nil)[:8])
	return filepath.Join(home, ".local", "share", name)
}

func machineID() []byte {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return []byte(id)
			}
		}
	}
	return []byte("no-machine-id")
}

// Create builds a complete new vault file.
func Create(head, key []byte, p *Payload) ([]byte, error) {
	if len(head) == 0 {
		return nil, errors.New("empty vault head")
	}
	if p.Credentials == nil {
		p.Credentials = map[string]string{}
	}
	pt, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(pt)
	ct, err := crypto.Encrypt(key, pt, head)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(head)+len(ct))
	out = append(out, head...)
	return append(out, ct...), nil
}

// Head returns the first n bytes (the key-recovery part) of the file.
func (f *File) Head(n int) ([]byte, error) {
	if n <= 0 || len(f.data) < n+gcmOverhead {
		return nil, ErrDecrypt
	}
	return f.data[:n], nil
}

// Open decrypts the payload; headLen depends on the unlock method.
func (f *File) Open(headLen int, key []byte) (*Payload, error) {
	head, err := f.Head(headLen)
	if err != nil {
		return nil, err
	}
	pt, err := crypto.Decrypt(key, f.data[headLen:], head)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer crypto.Zero(pt)
	return decodePayload(pt)
}

// Reseal encrypts a new payload under the same head and key.
func (f *File) Reseal(headLen int, key []byte, p *Payload) ([]byte, error) {
	head, err := f.Head(headLen)
	if err != nil {
		return nil, err
	}
	return Create(head, key, p)
}

func decodePayload(pt []byte) (*Payload, error) {
	var p Payload
	if err := json.Unmarshal(pt, &p); err != nil {
		return nil, fmt.Errorf("corrupt vault payload: %w", err)
	}
	if p.Credentials == nil {
		p.Credentials = map[string]string{}
	}
	return &p, nil
}

// Load reads the vault file at path.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("no vault found (run 'vault init')")
		}
		return nil, err
	}
	return &File{data: data}, nil
}

// Exists reports whether something exists at path.
func Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// WriteAtomic writes data to path with mode 0600 via temp file + rename,
// so a crash never leaves a half-written vault behind. Missing parent
// directories are created with 0700.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// Backup renames src to <dst>.<epoch> and returns the new name. dst is the
// current vault path, so backups are as inconspicuous as the vault itself.
func Backup(src, dst string) (string, error) {
	bak := dst + "." + strconv.FormatInt(time.Now().Unix(), 10)
	if err := os.MkdirAll(filepath.Dir(bak), 0o700); err != nil {
		return "", err
	}
	if err := os.Rename(src, bak); err != nil {
		return "", err
	}
	return bak, nil
}
