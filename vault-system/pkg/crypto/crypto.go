// Package crypto contains the symmetric primitives used by the vault:
// AES-256-GCM for the payload and PBKDF2-SHA256 for password-based keys.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// KeySize is the AES-256 key size in bytes.
const KeySize = 32

// ErrAuth is returned when GCM authentication fails (wrong key or tampered data).
var ErrAuth = errors.New("message authentication failed")

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key length %d (want %d)", len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt seals plaintext with AES-256-GCM. The random 12-byte nonce is
// prepended to the result. aad is authenticated but not encrypted.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, err := Random(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt opens data produced by Encrypt.
func Decrypt(key, data, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// DeriveKey derives a 32-byte key from a password with PBKDF2-SHA256.
func DeriveKey(password, salt []byte, iterations int) []byte {
	return pbkdf2.Key(password, salt, iterations, KeySize, sha256.New)
}

// Random returns n cryptographically secure random bytes.
func Random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return b, nil
}

// Zero overwrites b with zeros (best effort; Go may have made copies).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
