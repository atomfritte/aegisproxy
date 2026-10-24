package config

import (
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
