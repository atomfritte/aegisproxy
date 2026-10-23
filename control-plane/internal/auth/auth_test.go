package auth

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"aegisproxy/control-plane/internal/models"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	h := HashPassword("Correct-Horse-9")
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if ok, rehash := VerifyPassword("Correct-Horse-9", h); !ok || rehash {
		t.Fatalf("verify failed ok=%v rehash=%v", ok, rehash)
	}
	if ok, _ := VerifyPassword("wrong", h); ok {
		t.Fatal("wrong password accepted")
	}
	if ok, _ := VerifyPassword("x", ""); ok {
		t.Fatal("empty hash accepted")
	}
}

func TestLegacyHashNeedsRehash(t *testing.T) {
	// Produced by the 1.x custom PBKDF2 implementation (10k iterations, hex salt/key) for "admin123".
	legacy := "pbkdf2_sha256$000102030405060708090a0b0c0d0e0f$" + legacyKeyForTest(t, "admin123")
	ok, rehash := VerifyPassword("admin123", legacy)
	if !ok || !rehash {
		t.Fatalf("legacy verify ok=%v rehash=%v", ok, rehash)
	}
}

func TestPasswordStrength(t *testing.T) {
	for _, bad := range []string{"short", "alllowercaseletters", "admin-Password1"} {
		if ValidatePasswordStrength(bad, "admin") == nil {
			t.Errorf("weak password %q accepted", bad)
		}
	}
	if err := ValidatePasswordStrength("Tr0ub4dor&3-xyz", "admin"); err != nil {
		t.Errorf("strong password rejected: %v", err)
	}
	if err := ValidatePasswordStrength(GeneratePassword(), "admin"); err != nil {
		t.Errorf("generated password rejected: %v", err)
	}
}

func testUser() *models.User {
	return &models.User{ID: "usr-1", Username: "alice", Role: models.RoleInfoSecApprover, AllowedGroups: []string{"*"}}
}

func TestTokenIssueVerifyAndTamper(t *testing.T) {
	m := NewAuthManager([]byte(strings.Repeat("k", 32)), time.Hour)
	tok, claims, err := m.IssueToken(testUser())
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.VerifyToken(tok)
	if err != nil || got.UserID != "usr-1" || got.JTI != claims.JTI {
		t.Fatalf("verify: %v %+v", err, got)
	}
	parts := strings.Split(tok, ".")
	// Payload tampering (privilege escalation attempt)
	forged := strings.Replace(string(mustB64(t, parts[1])), "INFOSEC_APPROVER", "SUPER_ADMIN", 1)
	if _, err := m.VerifyToken(parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + parts[2]); err == nil {
		t.Fatal("tampered payload accepted")
	}
	// alg=none
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	if _, err := m.VerifyToken(none + "." + parts[1] + "."); err == nil {
		t.Fatal("alg=none accepted")
	}
	// Different secret
	other := NewAuthManager([]byte(strings.Repeat("z", 32)), time.Hour)
	if _, err := other.VerifyToken(tok); err == nil {
		t.Fatal("token from another key accepted")
	}
}

type revokeAll struct{}

func (revokeAll) IsTokenRevoked(string) bool { return true }

func TestTokenRevocationAndExpiry(t *testing.T) {
	m := NewAuthManager([]byte(strings.Repeat("k", 32)), time.Hour)
	tok, _, _ := m.IssueToken(testUser())
	m.SetRevocationChecker(revokeAll{})
	if _, err := m.VerifyToken(tok); err == nil {
		t.Fatal("revoked token accepted")
	}
	short := NewAuthManager([]byte(strings.Repeat("k", 32)), -time.Second)
	tok2, _, _ := short.IssueToken(testUser())
	if _, err := short.VerifyToken(tok2); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestBlockToken(t *testing.T) {
	key := strings.Repeat("d", 40)
	tok, err := SignBlockToken(key, BlockClaims{ServerIP: "10.0.0.5", URL: "https://example.com/x", Method: "GET", TraceID: "flw-1"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyBlockToken(key, tok)
	if err != nil || c.ServerIP != "10.0.0.5" {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifyBlockToken(strings.Repeat("e", 40), tok); err == nil {
		t.Fatal("wrong key accepted")
	}
	tampered := strings.Replace(tok, "v1.", "v1.A", 1)
	if _, err := VerifyBlockToken(key, tampered); err == nil {
		t.Fatal("tampered token accepted")
	}
	exp, _ := SignBlockToken(key, BlockClaims{ServerIP: "1.1.1.1", URL: "https://x.example", Exp: time.Now().Add(-time.Minute).Unix()})
	if _, err := VerifyBlockToken(key, exp); err == nil {
		t.Fatal("expired block token accepted")
	}
}

func TestLoginLimiterLocksOut(t *testing.T) {
	l := NewLoginLimiter()
	for i := 0; i < 5; i++ {
		if l.Check("u:bob") > 0 {
			t.Fatalf("locked too early at attempt %d", i)
		}
		l.Fail("u:bob", "ip:1.2.3.4")
	}
	if l.Check("u:bob") <= 0 {
		t.Fatal("expected lockout after 5 failures")
	}
	l.Success("u:bob")
	if l.Check("u:bob") > 0 {
		t.Fatal("success should reset account lockout")
	}
}

func TestTeamLeadRestrictions(t *testing.T) {
	tl := &TokenClaims{Role: models.RoleTeamLead, AllowedGroups: []string{"grp-a"}}
	cases := []struct {
		name string
		rule models.PolicyRule
	}{
		{"block rule", models.PolicyRule{Action: "BLOCK", HostPattern: "x.com", GroupIDs: []string{"grp-a"}}},
		{"catch-all", models.PolicyRule{Action: "ALLOW", HostPattern: "*", GroupIDs: []string{"grp-a"}}},
		{"tld wildcard", models.PolicyRule{Action: "ALLOW", HostPattern: "*.com", GroupIDs: []string{"grp-a"}}},
		{"foreign group", models.PolicyRule{Action: "ALLOW", HostPattern: "x.com", GroupIDs: []string{"grp-b"}}},
		{"wildcard group", models.PolicyRule{Action: "ALLOW", HostPattern: "x.com", GroupIDs: []string{"*"}}},
	}
	for _, c := range cases {
		if CanModifyRule(tl, c.rule) == nil {
			t.Errorf("%s: team lead should be denied", c.name)
		}
	}
	ok := models.PolicyRule{Action: "ALLOW", HostPattern: "*.github.com", GroupIDs: []string{"grp-a"}}
	if err := CanModifyRule(tl, ok); err != nil {
		t.Errorf("legit team lead rule denied: %v", err)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCrossLanguageBlockToken verifies a token minted by the Python data-plane
// (AEGIS_XLANG_BLOCK_TOKEN, signed with key "k"*40).
func TestCrossLanguageBlockToken(t *testing.T) {
	tok := os.Getenv("AEGIS_XLANG_BLOCK_TOKEN")
	if tok == "" {
		t.Skip("AEGIS_XLANG_BLOCK_TOKEN not set")
	}
	c, err := VerifyBlockToken(strings.Repeat("k", 40), tok)
	if err != nil || c.ServerIP != "10.1.0.5" || c.URL != "https://x.example/ü" || c.Method != "GET" {
		t.Fatalf("python token rejected: %v %+v", err, c)
	}
}
