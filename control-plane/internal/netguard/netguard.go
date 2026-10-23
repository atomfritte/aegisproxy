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

// Forbidden reports whether an outbound integration must never connect to a.
func Forbidden(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast()
}

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
