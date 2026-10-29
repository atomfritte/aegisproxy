// Package netguard provides dialers for outbound integrations that never connect to link-local
// (cloud instance metadata), multicast or unspecified addresses, checked on the resolved address at
// dial time so DNS rebinding cannot bypass it.
package netguard

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// cloudMetadata are cloud platform endpoints outside the link-local range (169.254.0.0/16 is link-local).
// Same list as _CLOUD_METADATA in the data-plane (data-plane/aegis_dp/addresses.py); shared vectors in
// testdata/destination_vectors.json.
var cloudMetadata = []netip.Prefix{
	netip.MustParsePrefix("168.63.129.16/32"),   // Azure WireServer (goal state, extension configuration, health)
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS instance metadata over IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud instance metadata
}

// CloudMetadata reports cloud platform metadata endpoints that are not link-local addresses, also embedded in
// IPv6 (NAT64, 6to4, IPv4-compatible, IPv4-translated, IPv4-mapped).
func CloudMetadata(a netip.Addr) bool { return classify(a, cloudMetadata) }

// Forbidden reports whether an outbound integration must never connect to a: the forbidden proxy destinations
// (IsForbiddenDestination) except loopback, which local integrations (a collector on the same host) may use.
func Forbidden(a netip.Addr) bool { return IsForbiddenDestination(a) && !IsLoopback(a) }

// Dialer returns a dialer that refuses forbidden destinations.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if a, err := netip.ParseAddr(host); err == nil && Forbidden(a) {
				return fmt.Errorf("connection to %s is not allowed (link-local/metadata, multicast or unspecified address)", host)
			}
			return nil
		}}
}
