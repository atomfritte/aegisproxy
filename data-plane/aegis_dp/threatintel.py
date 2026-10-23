"""Compiled threat-intelligence snapshot (mirror of control-plane/internal/threatintel/snapshot.go)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ThreatMatch:
    type: str
    indicator: str
    category: str
    source_id: str
    source_name: str


def normalize_url(raw: str) -> Optional[str]:
    """Canonical form used for exact URL matching (identical to Go NormalizeURL)."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 4096:
        return None
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            return None
        host = parts.hostname.lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    if ":" in host:
        host = f"[{host}]"
    if port:
        host = f"{host}:{port}"
    path = parts.path or "/"
    out = f"{scheme}://{host}{path}"
    if parts.query:
        out += "?" + parts.query
    return out


def _parent_domains(host: str):
    d = host
    while "." in d:
        yield d
        d = d.split(".", 1)[1]


class ThreatSnapshot:
    """Immutable lookup structure built from the control-plane export."""

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        data = data or {}
        self.version: str = data.get("version", "")
        self.sources: List[Dict[str, str]] = data.get("sources") or []
        self.exact: Dict[str, int] = data.get("domains") or {}
        self.sub: Dict[str, int] = data.get("domains_sub") or {}
        self.urls: Dict[str, int] = data.get("urls") or {}
        self.hashes: Dict[str, int] = data.get("hashes") or {}
        self.ips: Dict[Any, int] = {}
        for raw, idx in (data.get("ips") or {}).items():
            try:
                self.ips[ipaddress.ip_address(raw)] = idx
            except ValueError:
                continue
        self.nets: Dict[int, Dict[Any, int]] = {}
        for item in data.get("cidrs") or []:
            try:
                net = ipaddress.ip_network(item[0], strict=False)
            except (ValueError, IndexError, TypeError):
                continue
            self.nets.setdefault(net.prefixlen, {})[net] = item[1]
        self.net_lengths = sorted(self.nets.keys(), reverse=True)
        exc = data.get("exceptions") or {}
        self.exc_domains = set(exc.get("domains") or [])
        self.exc_urls = set(exc.get("urls") or [])
        self.exc_hashes = set(exc.get("hashes") or [])
        self.exc_ips = set()
        for raw in exc.get("ips") or []:
            try:
                self.exc_ips.add(ipaddress.ip_address(raw))
            except ValueError:
                pass

    @property
    def empty(self) -> bool:
        return not (self.exact or self.sub or self.urls or self.ips or self.nets or self.hashes)

    def _match(self, kind: str, indicator: str, idx: int) -> ThreatMatch:
        src = self.sources[idx] if 0 <= idx < len(self.sources) else {}
        return ThreatMatch(kind, indicator, src.get("category", "threat_intel"), src.get("id", ""), src.get("name", "threat intelligence"))

    def match_host(self, raw_host: str) -> Optional[ThreatMatch]:
        host = (raw_host or "").strip().lower().rstrip(".").strip("[]")
        if not host:
            return None
        try:
            return self.match_ip(ipaddress.ip_address(host))
        except ValueError:
            pass
        if any(d in self.exc_domains for d in _parent_domains(host)):
            return None
        if host in self.exact:
            return self._match("domain", host, self.exact[host])
        for d in _parent_domains(host):
            if d in self.sub:
                return self._match("domain", d, self.sub[d])
        return None

    def match_url(self, raw_url: str) -> Optional[ThreatMatch]:
        u = normalize_url(raw_url)
        if not u or u in self.exc_urls:
            return None
        if u in self.urls:
            return self._match("url", u, self.urls[u])
        return None

    def match_ip(self, addr) -> Optional[ThreatMatch]:
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        if addr in self.exc_ips:
            return None
        if addr in self.ips:
            return self._match("ip", str(addr), self.ips[addr])
        for length in self.net_lengths:
            if length > addr.max_prefixlen:
                continue
            net = ipaddress.ip_network(f"{addr}/{length}", strict=False)
            idx = self.nets[length].get(net)
            if idx is not None:
                return self._match("cidr", str(net), idx)
        return None

    def hash_excepted(self, digest: str) -> bool:
        """True when InfoSec marked this file as a false positive (also overrides antivirus verdicts)."""
        return (digest or "").lower() in self.exc_hashes

    def match_hash(self, digest: str) -> Optional[ThreatMatch]:
        h = (digest or "").lower()
        if h in self.exc_hashes:
            return None
        if h in self.hashes:
            return self._match("sha256", h, self.hashes[h])
        return None

    def stats(self) -> Tuple[int, int, int, int, int]:
        return len(self.exact) + len(self.sub), len(self.urls), len(self.ips), sum(len(v) for v in self.nets.values()), len(self.hashes)
