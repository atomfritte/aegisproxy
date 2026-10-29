package netguard

import "net/netip"

// Address classification shared by the policy engine (engine.IsInternalAddr), the proxy evaluation
// (store.alwaysForbiddenAddr) and the outbound integrations (Forbidden). Explicit tables instead of
// netip.Addr.IsPrivate / Python's ipaddress.is_private, whose ranges differ; the data-plane mirrors them in
// data-plane/aegis_dp/addresses.py (_FORBIDDEN_NETS, _INTERNAL_NETS). Shared vectors: testdata/destination_vectors.json.

// forbiddenPrefixes are destinations no rule may ever open: unspecified, loopback, link-local (169.254.169.254
// instance metadata), multicast and the cloud metadata endpoints outside the link-local range (cloudMetadata).
var forbiddenPrefixes = append([]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}, cloudMetadata...)

// internalPrefixes are, besides the forbidden ones, addresses that are not globally reachable: private,
// shared (CGNAT), documentation, benchmarking and reserved ranges.
var internalPrefixes = append([]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. 255.255.255.255
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated)
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4-translated, SIIT (deprecated)
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"), // IETF protocol assignments, incl. Teredo 2001::/32
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fec0::/10"), // site-local (deprecated)
}, forbiddenPrefixes...)

var (
	nat64Prefix      = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalPrefix = netip.MustParsePrefix("64:ff9b:1::/48")
	compatPrefix     = netip.MustParsePrefix("::/96")
	siitPrefix       = netip.MustParsePrefix("::ffff:0:0:0/96")
	sixToFourPrefix  = netip.MustParsePrefix("2002::/16")
)

// EmbeddedIPv4 returns the IPv4 address carried by an IPv6 address that a gateway or relay translates to IPv4:
// IPv4-mapped (::ffff:0:0/96), NAT64 (64:ff9b::/96, and the local-use 64:ff9b:1::/48 in its /96 layout),
// IPv4-compatible (::/96), IPv4-translated (SIIT, ::ffff:0:0:0/96) and 6to4 (2002::/16).
func EmbeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if a.Is4In6() {
		return a.Unmap(), true
	}
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64Prefix.Contains(a), nat64LocalPrefix.Contains(a), compatPrefix.Contains(a), siitPrefix.Contains(a):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFourPrefix.Contains(a):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

func inPrefixes(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// classify matches an address and the IPv4 address it embeds against a table.
func classify(a netip.Addr, prefixes []netip.Prefix) bool {
	a = a.WithZone("")
	if inPrefixes(a.Unmap(), prefixes) {
		return true
	}
	v4, ok := EmbeddedIPv4(a)
	return ok && inPrefixes(v4, prefixes)
}

// IsForbiddenDestination reports destinations no proxy rule may ever open (see forbiddenPrefixes), also when the
// address embeds one (NAT64, 6to4, IPv4-compatible, IPv4-mapped).
func IsForbiddenDestination(a netip.Addr) bool { return classify(a, forbiddenPrefixes) }

// IsInternal reports addresses that are not globally reachable (internalPrefixes, which include the forbidden
// ones), also when the address embeds one.
func IsInternal(a netip.Addr) bool { return classify(a, internalPrefixes) }

// IsLoopback reports loopback addresses, also embedded ones.
func IsLoopback(a netip.Addr) bool {
	if a.Unmap().IsLoopback() {
		return true
	}
	v4, ok := EmbeddedIPv4(a)
	return ok && v4.IsLoopback()
}
