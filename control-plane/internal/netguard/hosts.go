package netguard

import (
	"net/netip"
	"net/url"
	"regexp"
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
	return err == nil && a.Zone() == "" && a.Unmap().IsLoopback()
}

// dnsNameRe is a host name made of LDH labels (IDNs in their xn-- form): no IP literals, IPv6 zones,
// brackets or other characters a dialer could interpret differently from a suffix check.
var dnsNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// HostInDomains reports whether the host of raw is a DNS name equal to one of domains or a subdomain
// of one. Loopback hosts are accepted so integrations can be tested against local doubles.
func HostInDomains(raw string, domains ...string) bool {
	if LoopbackURL(raw) {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if _, err := netip.ParseAddr(h); err == nil || !dnsNameRe.MatchString(h) {
		return false
	}
	for _, d := range domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}
