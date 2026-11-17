package vaultfile

// Legacy (v1) format, only kept so an existing ~/.vault can be migrated:
//
//	"VAUT" | version 1 | uint16 BE header length | header JSON | "\n" | nonce ‖ AES-256-GCM ciphertext
//
// The header (keytype, public key, salt, ...) is readable plaintext, which is
// exactly why the format was replaced.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"vault-system/pkg/crypto"
)

const (
	legacyMagic    = "VAUT"
	legacyVersion  = 1
	legacyFixedLen = len(legacyMagic) + 1 + 2
)

// LegacyHeader is the plaintext header of a v1 vault.
type LegacyHeader struct {
	KeyType          string `json:"keytype"`
	Salt             string `json:"salt,omitempty"`
	PBKDF2Iterations int    `json:"pbkdf2_iterations,omitempty"`
	PublicKey        string `json:"public_key,omitempty"`
	WrappedKey       string `json:"wrapped_key,omitempty"`
	ECDHEphemeralPub string `json:"ecdh_ephemeral_pub,omitempty"`
	CreatedAt        int64  `json:"created_at"`
}

// LegacyFile is a parsed v1 vault.
type LegacyFile struct {
	Header     LegacyHeader
	prefix     []byte
	ciphertext []byte
}

// LegacyPath returns ~/.vault.
func LegacyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".vault"), nil
}

// LoadLegacy reads a v1 vault.
func LoadLegacy(path string) (*LegacyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < legacyFixedLen || string(data[:4]) != legacyMagic || data[4] != legacyVersion {
		return nil, errors.New("not a legacy vault file")
	}
	hl := int(binary.BigEndian.Uint16(data[5:7]))
	end := legacyFixedLen + hl
	if len(data) < end+1 || data[end] != '\n' {
		return nil, errors.New("corrupt legacy vault (truncated header)")
	}
	f := &LegacyFile{prefix: data[:end+1], ciphertext: data[end+1:]}
	if err := json.NewDecoder(bytes.NewReader(data[legacyFixedLen:end])).Decode(&f.Header); err != nil {
		return nil, fmt.Errorf("corrupt legacy vault header: %w", err)
	}
	return f, nil
}

// Open decrypts the payload of a v1 vault.
func (f *LegacyFile) Open(key []byte) (*Payload, error) {
	pt, err := crypto.Decrypt(key, f.ciphertext, f.prefix)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer crypto.Zero(pt)
	return decodePayload(pt)
}
