// Package keys loads SSH/PEM private keys and wraps/unwraps the vault's AES
// key with them:
//
//   - ssh-rsa:        random AES key, encrypted with RSA-OAEP(SHA-256, label "")
//   - ssh-ed25519:    Ed25519 key converted to X25519; ephemeral X25519 ECDH;
//     AES key = SHA256(shared || "vault-ed25519")
//   - ssh-ecdsa-p256: ephemeral P-256 ECDH; AES key = SHA256(shared || "vault-ecdsa-p256")
//
// The vault file stores only the wrapped key / ephemeral public key, never
// the user's public key or the key type.
package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	vcrypto "vault-system/pkg/crypto"
	"vault-system/pkg/vaultfile"
)

// ErrBadPassphrase is returned when an encrypted private key cannot be decrypted.
var ErrBadPassphrase = errors.New("failed to decrypt private key (wrong passphrase)")

// PassphraseFunc is called when the key file is encrypted.
type PassphraseFunc func() ([]byte, error)

// Load reads a private key (OpenSSH, PKCS#1, PKCS#8 or SEC1 PEM). The result
// is one of *rsa.PrivateKey, ed25519.PrivateKey or *ecdsa.PrivateKey.
func Load(path string, askPass PassphraseFunc) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key: %w", err)
	}
	defer vcrypto.Zero(data)

	raw, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		pass, perr := askPass()
		if perr != nil {
			return nil, perr
		}
		defer vcrypto.Zero(pass)
		if len(pass) == 0 {
			return nil, ErrBadPassphrase
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(data, pass)
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) || strings.Contains(err.Error(), "incorrect") {
				return nil, ErrBadPassphrase
			}
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("cannot parse private key %s: %w", path, err)
	}

	switch k := raw.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ed25519.PrivateKey:
		return *k, nil
	case ed25519.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("unsupported ECDSA curve %s (only P-256 is supported)", k.Curve.Params().Name)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T (supported: RSA, Ed25519, ECDSA P-256)", raw)
	}
}

// KeyType returns the vault keytype for a private key.
func KeyType(priv any) (string, error) {
	switch priv.(type) {
	case *rsa.PrivateKey:
		return vaultfile.KeyTypeRSA, nil
	case ed25519.PrivateKey:
		return vaultfile.KeyTypeEd25519, nil
	case *ecdsa.PrivateKey:
		return vaultfile.KeyTypeECDSA, nil
	}
	return "", fmt.Errorf("unsupported key type %T", priv)
}

// HeadLen is the length of the key-recovery head in a vault protected by priv.
func HeadLen(priv any) (int, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return k.Size(), nil
	case ed25519.PrivateKey, *ecdsa.PrivateKey:
		return 32, nil
	}
	return 0, fmt.Errorf("unsupported key type %T", priv)
}

// Wrap creates a new vault AES key protected by priv's public key and
// returns it together with the file head needed to recover it:
// the RSA-OAEP wrapped key, or the ephemeral ECDH public key (X25519: 32
// bytes; P-256: X coordinate only, Y is forced even). No public key or key
// type is stored. The caller must zero the returned key.
func Wrap(priv any) (key, head []byte, err error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		key, err := vcrypto.Random(vcrypto.KeySize)
		if err != nil {
			return nil, nil, err
		}
		wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &k.PublicKey, key, nil)
		if err != nil {
			vcrypto.Zero(key)
			return nil, nil, fmt.Errorf("RSA-OAEP: %w", err)
		}
		return key, wrapped, nil
	default:
		static, curve, label, err := ecdhStatic(priv)
		if err != nil {
			return nil, nil, err
		}
		for {
			eph, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			pub := eph.PublicKey().Bytes()
			if curve == ecdh.P256() {
				// 0x04 ‖ X ‖ Y: keep only X, retry until Y is even so the
				// point can be rebuilt without a (recognisable) prefix byte.
				if pub[64]&1 != 0 {
					continue
				}
				pub = pub[1:33]
			}
			shared, err := eph.ECDH(static.PublicKey())
			if err != nil {
				return nil, nil, err
			}
			defer vcrypto.Zero(shared)
			return kdf(shared, label), append([]byte(nil), pub...), nil
		}
	}
}

// Unwrap recovers the vault AES key from head using priv. A wrong key is
// not detected here (nothing about the key is stored); it makes the
// payload fail to decrypt.
func Unwrap(priv any, head []byte) ([]byte, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, k, head, nil)
		if err != nil || len(key) != vcrypto.KeySize {
			return nil, vaultfile.ErrDecrypt
		}
		return key, nil
	default:
		static, curve, label, err := ecdhStatic(priv)
		if err != nil {
			return nil, err
		}
		raw := head
		if curve == ecdh.P256() {
			x, y := elliptic.UnmarshalCompressed(elliptic.P256(), append([]byte{2}, head...))
			if x == nil {
				return nil, vaultfile.ErrDecrypt
			}
			raw = make([]byte, 65)
			raw[0] = 4
			x.FillBytes(raw[1:33])
			y.FillBytes(raw[33:])
		}
		ephPub, err := curve.NewPublicKey(raw)
		if err != nil {
			return nil, vaultfile.ErrDecrypt
		}
		shared, err := static.ECDH(ephPub)
		if err != nil {
			return nil, vaultfile.ErrDecrypt
		}
		defer vcrypto.Zero(shared)
		return kdf(shared, label), nil
	}
}

// UnwrapLegacy recovers the key of a v1 (~/.vault) vault for migration.
func UnwrapLegacy(priv any, h *vaultfile.LegacyHeader) ([]byte, error) {
	kt, err := KeyType(priv)
	if err != nil {
		return nil, err
	}
	if kt != h.KeyType {
		return nil, fmt.Errorf("key type mismatch: vault uses %s, given key is %s", h.KeyType, kt)
	}
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		wrapped, err := base64.StdEncoding.DecodeString(h.WrappedKey)
		if err != nil {
			return nil, fmt.Errorf("invalid wrapped_key: %w", err)
		}
		key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, k, wrapped, nil)
		if err != nil {
			return nil, vaultfile.ErrDecrypt
		}
		return key, nil
	default:
		static, curve, label, err := ecdhStatic(priv)
		if err != nil {
			return nil, err
		}
		ephBytes, err := base64.StdEncoding.DecodeString(h.ECDHEphemeralPub)
		if err != nil {
			return nil, fmt.Errorf("invalid ecdh_ephemeral_pub: %w", err)
		}
		ephPub, err := curve.NewPublicKey(ephBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid ecdh_ephemeral_pub: %w", err)
		}
		shared, err := static.ECDH(ephPub)
		if err != nil {
			return nil, err
		}
		defer vcrypto.Zero(shared)
		return kdf(shared, label), nil
	}
}

// ecdhStatic converts the long-term signing key into an ECDH key.
func ecdhStatic(priv any) (*ecdh.PrivateKey, ecdh.Curve, string, error) {
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		// Standard Ed25519 -> X25519 conversion: the X25519 scalar is the
		// first half of SHA-512(seed) (clamping is applied by X25519 itself).
		hsum := sha512.Sum512(k.Seed())
		defer vcrypto.Zero(hsum[:])
		x, err := ecdh.X25519().NewPrivateKey(hsum[:32])
		return x, ecdh.X25519(), "vault-ed25519", err
	case *ecdsa.PrivateKey:
		x, err := k.ECDH()
		return x, ecdh.P256(), "vault-ecdsa-p256", err
	}
	return nil, nil, "", fmt.Errorf("unsupported key type %T", priv)
}

func kdf(shared []byte, label string) []byte {
	var b bytes.Buffer
	b.Write(shared)
	b.WriteString(label)
	sum := sha256.Sum256(b.Bytes())
	vcrypto.Zero(b.Bytes())
	return sum[:]
}
