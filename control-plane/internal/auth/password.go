package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// PBKDF2-HMAC-SHA256 work factor, OWASP Password Storage Cheat Sheet (2023+) recommendation.
const (
	pbkdf2Iterations       = 600_000
	legacyPBKDF2Iterations = 10_000
	pbkdf2KeyLen           = 32
	MinPasswordLength      = 12
)

// dummyHash is verified when a username does not exist so that login timing does not
// reveal which accounts exist.
var dummyHash = HashPassword("aegis-timing-equalizer-not-a-real-password")

// HashPassword returns "pbkdf2-sha256$<iter>$<b64 salt>$<b64 key>".
func HashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		panic("pbkdf2: " + err.Error())
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, enc.EncodeToString(salt), enc.EncodeToString(dk))
}

// VerifyPassword checks a password against a stored hash. needsRehash is true when the
// stored hash uses an outdated format or work factor and should be upgraded.
func VerifyPassword(password, storedHash string) (ok bool, needsRehash bool) {
	switch {
	case strings.HasPrefix(storedHash, "pbkdf2-sha256$"):
		parts := strings.Split(storedHash, "$")
		if len(parts) != 4 {
			return false, false
		}
		iter, err := strconv.Atoi(parts[1])
		if err != nil || iter < 1000 || iter > 10_000_000 {
			return false, false
		}
		salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
		want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
		if err1 != nil || err2 != nil || len(want) == 0 {
			return false, false
		}
		got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
		if err != nil {
			return false, false
		}
		ok := hmac.Equal(got, want)
		return ok, ok && iter < pbkdf2Iterations
	case strings.HasPrefix(storedHash, "pbkdf2_sha256$"):
		// Format written by releases <= 1.0 (hex salt/key, 10k iterations).
		parts := strings.Split(storedHash, "$")
		if len(parts) != 3 {
			return false, false
		}
		salt, err1 := hex.DecodeString(parts[1])
		want, err2 := hex.DecodeString(parts[2])
		if err1 != nil || err2 != nil || len(want) == 0 {
			return false, false
		}
		got, err := pbkdf2.Key(sha256.New, password, salt, legacyPBKDF2Iterations, len(want))
		if err != nil {
			return false, false
		}
		ok := hmac.Equal(got, want)
		return ok, ok
	default:
		// Unknown/empty hash: burn comparable CPU time, then fail.
		_, _ = VerifyPassword(password, dummyHash)
		return false, false
	}
}

// EqualizeTiming performs a throw-away verification (used for unknown usernames).
func EqualizeTiming(password string) {
	_, _ = VerifyPassword(password, dummyHash)
}

// ValidatePasswordStrength enforces a minimal enterprise password policy.
func ValidatePasswordStrength(password, username string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", MinPasswordLength)
	}
	if len(password) > 256 {
		return errors.New("password must be at most 256 characters long")
	}
	var classes int
	var hasLower, hasUpper, hasDigit, hasOther bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
	}
	for _, b := range []bool{hasLower, hasUpper, hasDigit, hasOther} {
		if b {
			classes++
		}
	}
	if classes < 3 {
		return errors.New("password must contain at least three of: lowercase, uppercase, digits, symbols")
	}
	if username != "" && strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		return errors.New("password must not contain the username")
	}
	return nil
}

// GeneratePassword returns a random password that satisfies ValidatePasswordStrength.
func GeneratePassword() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	// Guarantee character classes: Upper-lower-digit-symbol prefix groups.
	return "Ae7-" + string(out)
}
