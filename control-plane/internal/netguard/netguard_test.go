package netguard

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestForbidden(t *testing.T) {
	for addr, want := range map[string]bool{"169.254.169.254": true, "::ffff:169.254.169.254": true, "fe80::1": true, "0.0.0.0": true,
		"224.0.0.1": true, "127.0.0.1": false, "10.1.2.3": false, "20.190.1.1": false,
		"168.63.129.16": true, "::ffff:168.63.129.16": true, "fd00:ec2::254": true, "100.100.100.200": true, "168.63.129.17": false} {
		if got := Forbidden(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Forbidden(%s) = %v", addr, got)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Dialer(time.Second).DialContext(ctx, "tcp", "169.254.169.254:80"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("metadata address dialed: %v", err)
	}
}

func TestHostInDomains(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://dce-1.westeurope-1.ingest.monitor.azure.com":               true,
		"https://dce-1.westeurope-1.ingest.privatelink.monitor.azure.com/x": true,
		"https://dce.usgovvirginia-1.ingest.monitor.azure.us":               true,
		"https://dce.chinaeast2-1.ingest.monitor.azure.cn.":                 true,
		"https://LOCALHOST:8443/":                                           true,
		"https://127.0.0.1:9/":                                              true,
		"https://[::1]:9/":                                                  true,
		"https://attacker.example/monitor.azure.com":                        false,
		"https://monitor.azure.com.attacker.example":                        false,
		"https://evilmonitor.azure.com":                                     false,
		"https://monitor.azure.com@attacker.example":                        false,
		"https://10.0.0.5":                                                  false,
		"https://localhost.attacker.example":                                false,
		// IP literals whose IPv6 zone looks like a pinned domain dial the literal address.
		"https://[fc00:f853:ccd:e793::1%25.monitor.azure.com]:19142":   false,
		"https://[::ffff:172.17.0.1%25x.monitor.azure.com]/":           false,
		"https://[::ffff:169.254.169.254%25.ingest.monitor.azure.com]": false,
		"https://[::1%25lo.monitor.azure.com]:9/":                      false,
		"https://[::ffff:127.0.0.2%25x.monitor.azure.com]/":            false,
		"https://dce_1.monitor.azure.com":                              false,
		"https://xn--dce-1.westeurope-1.ingest.monitor.azure.com":      true,
	} {
		if got := HostInDomains(raw, AzureMonitorDomains...); got != want {
			t.Errorf("HostInDomains(%q) = %v", raw, got)
		}
	}
	for raw, want := range map[string]bool{
		"https://login.microsoftonline.com":                              true,
		"https://login.microsoftonline.us/":                              true,
		"https://login.chinacloudapi.cn":                                 true,
		"https://login.partner.microsoftonline.cn":                       true,
		"https://login.microsoftonline.com.evil.io":                      false,
		"https://attacker.example":                                       false,
		"https://[::ffff:172.17.0.1%25.login.microsoftonline.com]:19142": false,
	} {
		if got := HostInDomains(raw, EntraAuthorityDomains...); got != want {
			t.Errorf("HostInDomains(%q, entra) = %v", raw, got)
		}
	}
}
