package config

import (
	"os"
	"strings"
	"testing"
)

func TestTrustedProxyHosts(t *testing.T) {
	for h, ok := range map[string]bool{
		"aegis-console-headless.aegis.svc.cluster.local": true,
		"console":      true,
		"10.0.0.1":     false,
		"fd00::1":      false,
		"host:8080":    false,
		"bad..name":    false,
		".leading":     false,
		"under_score":  false,
		"":             false,
		"spaces in it": false,
	} {
		if got := validProxyHost(h); got != ok {
			t.Errorf("validProxyHost(%q) = %v, want %v", h, got, ok)
		}
	}
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("AEGIS_TRUSTED_PROXY_HOSTS", "console.aegis.svc,10.0.0.1")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AEGIS_TRUSTED_PROXY_HOSTS") {
		t.Fatalf("an address in AEGIS_TRUSTED_PROXY_HOSTS must be rejected: %v", err)
	}
}

// DEPLOY-1: the proxy secret is a header value in proxy configurations; it must be long and plain.
func TestTrustedProxySecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	for _, bad := range []string{"short", strings.Repeat("a", 31), strings.Repeat("a", 40) + `"; evil`, strings.Repeat("a", 40) + " b"} {
		t.Setenv("AEGIS_TRUSTED_PROXY_SECRET", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AEGIS_TRUSTED_PROXY_SECRET") {
			t.Errorf("secret %q accepted: %v", bad, err)
		}
	}
	good := "0123456789abcdef0123456789abcdef-._~+/="
	t.Setenv("AEGIS_TRUSTED_PROXY_SECRET", good)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.TrustedProxySecret != good {
		t.Fatalf("valid secret: %q", c.TrustedProxySecret)
	}
	file := dir + "/proxy-secret"
	if err := os.WriteFile(file, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEGIS_TRUSTED_PROXY_SECRET", "")
	t.Setenv("AEGIS_TRUSTED_PROXY_SECRET_FILE", file)
	if c, err = Load(); err != nil {
		t.Fatal(err)
	}
	if c.TrustedProxySecret != good {
		t.Fatalf("secret from file: %q", c.TrustedProxySecret)
	}
}
