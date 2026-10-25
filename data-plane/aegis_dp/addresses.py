"""Destination address classification, identical to control-plane/internal/netguard/addrclass.go (shared vectors in
testdata/destination_vectors.json)."""

from __future__ import annotations

import ipaddress

# Explicit tables instead of ipaddress.is_private, whose ranges differ from Go's netip.Addr.IsPrivate.
# Cloud platform endpoints outside the link-local range (169.254.0.0/16 is link-local). Same list as
# netguard.cloudMetadata on the control-plane.
_CLOUD_METADATA = tuple(ipaddress.ip_network(n) for n in (
    "168.63.129.16/32",   # Azure WireServer (goal state, extension configuration, health)
    "fd00:ec2::254/128",  # AWS instance metadata over IPv6
    "100.100.100.200/32",  # Alibaba Cloud instance metadata
))
# Destinations no rule may ever open: unspecified, loopback, link-local, multicast, cloud metadata.
_FORBIDDEN_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/32", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::/128", "::1/128", "fe80::/10", "ff00::/8",
)) + _CLOUD_METADATA
# Not globally reachable (besides the forbidden ones): private, shared (CGNAT), documentation, benchmarking, reserved.
_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
    "::/96",  # IPv4-compatible (deprecated)
    "64:ff9b:1::/48", "100::/64",
    "2001::/23",  # IETF protocol assignments, incl. Teredo 2001::/32
    "2001:db8::/32", "3fff::/20", "fc00::/7",
    "fec0::/10",  # site-local (deprecated)
)) + _FORBIDDEN_NETS
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"), ipaddress.ip_network("::/96"))
_6TO4 = ipaddress.ip_network("2002::/16")


def embedded_ipv4(addr):
    """The IPv4 address carried by an IPv6 address that a gateway or relay translates to IPv4: IPv4-mapped, NAT64
    (64:ff9b::/96, and the local-use 64:ff9b:1::/48 in its /96 layout), IPv4-compatible (::/96) and 6to4 (2002::/16)."""
    if addr.version != 6:
        return None
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if any(addr in net for net in _NAT64):
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if addr in _6TO4:
        return addr.sixtofour
    return None


def _classify(addr, nets) -> bool:
    for a in (addr, embedded_ipv4(addr)):
        if a is not None and any(a.version == net.version and a in net for net in nets):
            return True
    return False


def is_cloud_metadata(addr) -> bool:
    return _classify(addr, _CLOUD_METADATA)


def is_internal_addr(addr) -> bool:
    """Not globally reachable: loopback, private, link-local, CGNAT, documentation, reserved, multicast,
    unspecified and cloud metadata, also embedded in IPv6 (NAT64, 6to4, IPv4-compatible)."""
    return _classify(addr, _INTERNAL_NETS)


def is_forbidden_addr(addr) -> bool:
    """Destinations no rule may ever open: loopback, link-local and other cloud metadata endpoints (Azure
    WireServer, AWS IMDS over IPv6, Alibaba Cloud), unspecified, multicast, also embedded in IPv6."""
    return _classify(addr, _FORBIDDEN_NETS)
