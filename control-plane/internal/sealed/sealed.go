// Package sealed encrypts secrets stored in the configuration (state file / PostgreSQL document)
// with AES-256-GCM. Fields of type String are encrypted when marshalled for persistence and
// decrypted transparently when loaded; in memory they are plain strings.
//
// Ciphertext format: "enc:v1:<key id>:<base64(nonce || ciphertext)>". The key id (first 8 hex
// characters of SHA-256 over the key) selects the key, so a previous key can still decrypt values
// during rotation while new values are always written with the current key.
package sealed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
)

const prefix = "enc:v1:"

type key struct {
	id   string
	aead cipher.AEAD
}

type keyring struct {
	current *key
	all     map[string]*key
}

var ring atomic.Pointer[keyring]

// stale counts decoded values that are not sealed with the current key (plain text written before
// encryption was enabled, or a previous key after a rotation); saving re-seals them.
var stale atomic.Int64

// StaleCount returns the number of such values decoded since the process started.
func StaleCount() int64 { return stale.Load() }

var sealedToken = regexp.MustCompile(`"enc:v1:[0-9a-f]+:[A-Za-z0-9+/]*"`)

// Normalize replaces sealed values by a placeholder, so that two serializations of the same
// document compare equal although every seal uses a fresh nonce.
func Normalize(doc []byte) []byte { return sealedToken.ReplaceAll(doc, []byte(`"enc"`)) }

// DeriveKey turns a high-entropy secret (≥ 32 characters) into an AES-256 key.
func DeriveKey(secret string) ([]byte, error) {
	if len(strings.TrimSpace(secret)) < 32 {
		return nil, errors.New("encryption key must be at least 32 characters (openssl rand -hex 32)")
	}
	sum := sha256.Sum256([]byte("aegisproxy-sealed-v1\x00" + strings.TrimSpace(secret)))
	return sum[:], nil
}

func newKey(k []byte) (*key, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(k)
	return &key{id: hex.EncodeToString(sum[:4]), aead: aead}, nil
}

// Configure installs the current key and optional previous keys (decryption only). A nil current
// key disables encryption (values are written in plain text; encrypted values cannot be read).
func Configure(current []byte, previous ...[]byte) error {
	kr := &keyring{all: map[string]*key{}}
	if current != nil {
		k, err := newKey(current)
		if err != nil {
			return err
		}
		kr.current = k
		kr.all[k.id] = k
	}
	for _, p := range previous {
		k, err := newKey(p)
		if err != nil {
			return err
		}
		kr.all[k.id] = k
	}
	ring.Store(kr)
	return nil
}

// Enabled reports whether secrets are encrypted at rest.
func Enabled() bool {
	kr := ring.Load()
	return kr != nil && kr.current != nil
}

// KeyID returns the id of the current key ("" when disabled).
func KeyID() string {
	if kr := ring.Load(); kr != nil && kr.current != nil {
		return kr.current.id
	}
	return ""
}

// Seal encrypts a value with the current key (plain text when encryption is disabled).
func Seal(plain string) (string, error) {
	kr := ring.Load()
	if plain == "" || kr == nil || kr.current == nil {
		return plain, nil
	}
	nonce := make([]byte, kr.current.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := kr.current.aead.Seal(nonce, nonce, []byte(plain), []byte(prefix+kr.current.id))
	return prefix + kr.current.id + ":" + base64.RawStdEncoding.EncodeToString(ct), nil
}

// IsSealed reports whether v is in the ciphertext format.
func IsSealed(v string) bool { return strings.HasPrefix(v, prefix) }

// Open decrypts a sealed value; plain values are returned unchanged.
func Open(v string) (string, error) {
	if !IsSealed(v) {
		return v, nil
	}
	rest := strings.TrimPrefix(v, prefix)
	id, b64, ok := strings.Cut(rest, ":")
	if !ok {
		return "", errors.New("malformed sealed value")
	}
	kr := ring.Load()
	if kr == nil {
		return "", errors.New("encrypted secret found but no encryption key is configured (AEGIS_ENCRYPTION_KEY)")
	}
	k, found := kr.all[id]
	if !found {
		return "", fmt.Errorf("secret was encrypted with key %s, which is not configured (set it as AEGIS_ENCRYPTION_KEY or AEGIS_ENCRYPTION_KEY_PREVIOUS)", id)
	}
	raw, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil || len(raw) < k.aead.NonceSize() {
		return "", errors.New("malformed sealed value")
	}
	pt, err := k.aead.Open(nil, raw[:k.aead.NonceSize()], raw[k.aead.NonceSize():], []byte(prefix+id))
	if err != nil {
		return "", errors.New("secret could not be decrypted (wrong key or tampered value)")
	}
	return string(pt), nil
}

// String is a secret that is encrypted whenever it is serialized. API handlers must never return
// it (models expose Public() copies that blank secrets).
type String string

func (s String) MarshalJSON() ([]byte, error) {
	v, err := Seal(string(s))
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (s *String) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	pt, err := Open(v)
	if err != nil {
		return err
	}
	if kr := ring.Load(); v != "" && kr != nil && kr.current != nil && !strings.HasPrefix(v, prefix+kr.current.id+":") {
		stale.Add(1)
	}
	*s = String(pt)
	return nil
}

// Map is a map of secrets (e.g. HTTP header values).
type Map map[string]String
