"""Destination binding for non-regular proxy modes (transparent, SOCKS5, reverse, WireGuard, local).

In regular mode the client names the destination (CONNECT target / absolute URL) and mitmproxy connects to
exactly that name. In the other modes the connection already goes to an address chosen by the client (the
original destination IP), while policy is evaluated for the Host header / TLS SNI the client sends. Both are
client-controlled, so the worker only trusts the name when the destination address is one of the name's DNS
answers (same resolver the worker uses for upstream connections, cached briefly).
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from .policy import is_forbidden_addr, is_internal_addr, is_internal_host, normalize_host, parse_ip

Lookup = Callable[[str, int], Awaitable[List[Any]]]


async def _getaddrinfo(host: str, port: int) -> List[Any]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    out: List[Any] = []
    for info in infos:
        a = parse_ip(info[4][0])
        if a is not None and a not in out:
            out.append(a)
    return out


class DnsCache:
    """Short-lived cache of resolver answers. Addresses seen for a name within the TTL are merged, so
    round-robin answers that rotate between lookups do not make a legitimate destination look foreign."""

    def __init__(self, ttl: float = 30.0, max_entries: int = 4096, lookup: Optional[Lookup] = None) -> None:
        self.ttl = ttl
        self.max_entries = max_entries
        self.lookup: Lookup = lookup or _getaddrinfo
        self._entries: Dict[str, Tuple[float, List[Any]]] = {}

    def remember(self, host: str, addrs: List[Any]) -> None:
        host = normalize_host(host)
        now = time.time()
        old = self._entries.get(host)
        merged = list(old[1]) if old and old[0] > now else []
        merged += [a for a in addrs if a not in merged]
        self._entries.pop(host, None)
        if len(self._entries) >= self.max_entries:
            expired = [k for k, v in self._entries.items() if v[0] <= now]
            for k in expired or list(self._entries)[: max(1, self.max_entries // 4)]:  # oldest first
                del self._entries[k]
        self._entries[host] = (now + self.ttl, merged[:64])

    async def resolve(self, host: str, port: int = 0, fresh: bool = False) -> List[Any]:
        """Resolved addresses ([] when the name does not resolve)."""
        host = normalize_host(host)
        entry = self._entries.get(host)
        if entry and not fresh and entry[0] > time.time():
            return entry[1]
        try:
            addrs = await self.lookup(host, port)
        except Exception:  # noqa: BLE001 - OSError, UnicodeError (IDNA), ValueError: an unresolvable name
            addrs = []
        if addrs:
            self.remember(host, addrs)
        entry = self._entries.get(host)
        return entry[1] if entry else []


async def bound(name: str, dest: Any, port: int, dns: DnsCache) -> bool:
    """True when ``dest`` (the address the connection really goes to) is a DNS answer for ``name``."""
    n = normalize_host(name)
    literal = parse_ip(n)
    if literal is not None:
        return literal == dest
    if not n:
        return False
    if dest in await dns.resolve(n, port):
        return True
    return dest in await dns.resolve(n, port, fresh=True)  # the answer may have rotated since it was cached


async def check_binding(name: str, dest_host: str, port: int, dns: DnsCache, block_private: bool,
                        internal_suffixes) -> Optional[Tuple[str, str]]:
    """Validates a request in a non-regular mode. ``name`` is the evaluated Host/SNI, ``dest_host`` the
    address mitmproxy will connect to. Returns (block_reason, explanation) or None when the name is bound."""
    n, d = normalize_host(name), normalize_host(dest_host)
    dest = parse_ip(d)
    if n != d:
        if dest is None:
            return "host_mismatch", f"Security Guard: Host '{n}' does not match the connection's destination '{d}'"
        if not await bound(n, dest, port, dns):
            return "host_mismatch", (f"Security Guard: Host '{n}' does not resolve to the connection's destination "
                                     f"{dest} (spoofed Host header / SNI)")
    if dest is not None:
        if is_forbidden_addr(dest):
            return "forbidden_destination", f"Security Guard: destination {dest} is loopback/link-local/metadata"
        if block_private and is_internal_addr(dest) and not is_internal_host(n, internal_suffixes):
            return "dns_rebinding", f"Security Guard: {n} resolves to internal address {dest} (DNS rebinding protection)"
    return None
