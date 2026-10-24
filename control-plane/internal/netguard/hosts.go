package netguard

import (
	"net/netip"
	"net/url"
	"strings"
)

// Microsoft cloud domains (public, US Government, China) that pin integrations presenting platform
// credentials (managed identity, workload identity, Entra ID app tokens) to Microsoft endpoints.
var (
	// EntraAuthorityDomains host the Entra ID token endpoints.
	EntraAuthorityDomains = []string{"microsoftonline.com", "microsoftonline.us", "microsoftonline.cn", "chinacloudapi.cn"}
	// AzureMonitorDomains host the Logs Ingestion API (data collection endpoints, also via Private Link).
	AzureMonitorDomains = []string{"monitor.azure.com", "monitor.azure.us", "monitor.azure.cn"}
)

// LoopbackURL reports whether raw points at localhost or a loopback address (local test doubles).
func LoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Unmap().IsLoopback()
}

// HostInDomains reports whether the host of raw is one of domains or a subdomain of one. Loopback
// hosts are accepted so integrations can be tested against local doubles.
func HostInDomains(raw string, domains ...string) bool {
	if LoopbackURL(raw) {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, d := range domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}
