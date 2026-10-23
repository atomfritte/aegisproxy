package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// legacyKeyForTest reproduces the hand-rolled PBKDF2 of release 1.x to generate fixtures.
func legacyKeyForTest(t *testing.T, password string) string {
	t.Helper()
	salt, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < legacyPBKDF2Iterations; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return hex.EncodeToString(out)
}
