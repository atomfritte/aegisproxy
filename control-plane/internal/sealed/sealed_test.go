package sealed

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSealRoundTripAndRotation(t *testing.T) {
	t.Cleanup(func() { _ = Configure(nil) })
	if _, err := DeriveKey("short"); err == nil {
		t.Fatal("short key accepted")
	}
	k1, _ := DeriveKey(strings.Repeat("a", 40))
	k2, _ := DeriveKey(strings.Repeat("b", 40))
	if err := Configure(k1); err != nil {
		t.Fatal(err)
	}
	type doc struct {
		S String `json:"s"`
		E String `json:"e"`
	}
	b, _ := json.Marshal(doc{S: "hunter2"})
	if strings.Contains(string(b), "hunter2") || !strings.Contains(string(b), "enc:v1:") || !strings.Contains(string(b), `"e":""`) {
		t.Fatalf("not sealed: %s", b)
	}
	var back doc
	if err := json.Unmarshal(b, &back); err != nil || back.S != "hunter2" {
		t.Fatalf("roundtrip: %v %q", err, back.S)
	}
	// Two encryptions of the same value differ (random nonce).
	b2, _ := json.Marshal(doc{S: "hunter2"})
	if string(b) == string(b2) {
		t.Error("deterministic ciphertext")
	}
	// Rotation: new key current, old key previous -> old values readable, new values use k2.
	if err := Configure(k2, k1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &back); err != nil || back.S != "hunter2" {
		t.Fatalf("previous key: %v", err)
	}
	b3, _ := json.Marshal(doc{S: "x"})
	if !strings.Contains(string(b3), "enc:v1:"+KeyID()+":") {
		t.Errorf("new value not sealed with current key: %s", b3)
	}
	// Without the old key the value cannot be read; tampering is detected.
	_ = Configure(k2)
	if err := json.Unmarshal(b, &back); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("missing key: %v", err)
	}
	_ = Configure(k1)
	tampered := strings.Replace(string(b), "enc:v1:", "enc:v1:", 1)
	tampered = tampered[:len(tampered)-4] + "AAA\"}"
	if err := json.Unmarshal([]byte(tampered), &back); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	// Plain values (API input, pre-encryption state) are accepted unchanged.
	if err := json.Unmarshal([]byte(`{"s":"plain"}`), &back); err != nil || back.S != "plain" {
		t.Fatal("plain value rejected")
	}
}
