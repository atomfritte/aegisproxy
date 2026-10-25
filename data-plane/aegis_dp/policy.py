"""Local policy evaluation (mirror of control-plane/internal/store/evaluate.go and engine.go).

The evaluation order is identical to the control-plane:
  proxy authentication -> quarantine -> threat intelligence -> destination hygiene -> BLOCK rules ->
  TLS passthrough -> learning sessions -> redirect-object grants -> ALLOW rules -> default deny.
"""

from __future__ import annotations

import functools
import hashlib
import ipaddress
import posixpath
import re
import string
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .addresses import is_forbidden_addr, is_internal_addr
from .threatintel import ThreatSnapshot

VERDICT_ALLOWED = "ALLOWED"
VERDICT_BLOCKED = "BLOCKED"
VERDICT_LEARNING = "LEARNING_ALLOWED"
VERDICT_REDIRECT = "REDIRECT_OBJECT_ALLOWED"
VERDICT_TLS_BYPASS = "TLS_BYPASS"
VERDICT_THREAT = "THREAT_BLOCKED"
VERDICT_MALWARE = "MALWARE_BLOCKED"
VERDICT_DLP = "DLP_BLOCKED"
VERDICT_FILETYPE = "FILETYPE_BLOCKED"
VERDICT_POLICY = "POLICY_BLOCKED"
VERDICT_QUARANTINED = "QUARANTINED"
VERDICT_AUTH_FAILED = "AUTH_FAILED"  # invalid proxy credentials: HTTP 407, never an IP fallback
UNREGISTERED_PREFIX = "srv-unregistered-"
# Proxy-Authorization header that is present but cannot be parsed: as "username:token" with an empty token it
# matches no server and fails authentication like any other invalid credential.
MALFORMED_PROXY_AUTH = ":"

ALLOWED_VERDICTS = {VERDICT_ALLOWED, VERDICT_LEARNING, VERDICT_REDIRECT, VERDICT_TLS_BYPASS}
SECURITY_VERDICTS = {VERDICT_THREAT, VERDICT_MALWARE, VERDICT_DLP, VERDICT_FILETYPE, VERDICT_POLICY, VERDICT_QUARANTINED,
                     VERDICT_AUTH_FAILED}
AUTH_FAILED_MESSAGES = {
    "invalid_proxy_token": "Proxy authentication failed: the presented proxy credentials match no registered server "
                           "(unknown, rotated or mistyped token)",
    "proxy_token_required": "Proxy authentication failed: this server's group requires its proxy token "
                            "(a proxy username alone is not accepted)",
}

DEFAULT_INTERNAL_SUFFIXES = (".internal.corp", ".local", ".localdomain", ".internal", ".lan", ".home.arpa")


# ---------------------------------------------------------------------------
# Normalization & matching primitives
# ---------------------------------------------------------------------------

_ASCII_WS = " \t\r\n\f\v"
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_SURROGATE = re.compile("[\ud800-\udfff]")


# normalize_host and canonicalize_path must stay identical to engine.NormalizeHost and engine.CanonicalizePath
# (control-plane): both are tested against testdata/normalization_vectors.json.
def normalize_host(raw_host: str) -> str:
    """Lowercase (ASCII), without surrounding ASCII whitespace, brackets of IPv6 literals, port and trailing
    dots. A port is only stripped when the value has exactly one colon (an unbracketed IPv6 literal stays whole)."""
    h = (raw_host or "").strip(_ASCII_WS).translate(_ASCII_LOWER)
    if h.startswith("["):
        end = h.find("]")
        if end != -1:
            return h[1:end]
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def canonicalize_path(raw_path: str) -> Tuple[str, bool]:
    """Decode up to 3 levels of percent-encoding, reject NUL/backslash smuggling, malformed escapes, paths
    that are not valid UTF-8 and deeper nesting, and resolve dot-segments (/a/../b -> /b)."""
    if not raw_path:
        return "/", True
    cur = raw_path.split("?", 1)[0].split("#", 1)[0]
    for _ in range(3):
        # mitmproxy decodes undecodable path bytes as lone surrogates (surrogateescape)
        if "\x00" in cur or "\\" in cur or _BAD_ESCAPE.search(cur) or _SURROGATE.search(cur):
            return "", False
        try:
            unesc = urllib.parse.unquote(cur, errors="strict")
        except UnicodeDecodeError:
            return "", False
        if "\x00" in unesc or "\\" in unesc:
            return "", False
        if unesc == cur:
            break
        cur = unesc
    if _BAD_ESCAPE.search(cur) or _SURROGATE.search(cur) or urllib.parse.unquote(cur) != cur:
        return "", False
    if not cur.startswith("/"):
        cur = "/" + cur
    cleaned = posixpath.normpath(cur)
    if cleaned.startswith("//"):
        cleaned = "/" + cleaned.lstrip("/")
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    return cleaned, True


def parse_ip(host: str):
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    return addr.ipv4_mapped or addr if isinstance(addr, ipaddress.IPv6Address) else addr


def is_internal_host(host: str, suffixes) -> bool:
    h = normalize_host(host)
    if not h or h == "localhost" or h.endswith(".localhost"):
        return True
    for suf in suffixes:
        if h.endswith(suf) or h == suf.lstrip("."):
            return True
    addr = parse_ip(h)
    return addr is not None and is_internal_addr(addr)


def match_host(pattern: str, host: str) -> bool:
    pat = normalize_host(pattern)
    h = normalize_host(host)
    if not h:
        return False
    if pat in ("*", h):
        return True
    if pat.startswith("*."):
        return h == pat[2:] or h.endswith(pat[1:])
    return False


def is_domain_wide(pattern: str) -> bool:
    return (pattern or "").strip() in ("", "*", "/**")


# Path pattern syntax, identical to engine.MatchPath (shared vectors in testdata/path_vectors.json). Pattern and
# request path are canonicalized first (query ignored, dot-segments and repeated slashes resolved), then:
#   *    a whole segment ("/simple/*"): exactly one non-empty segment; inside a segment ("/v*.json"): any characters
#        except "/"
#   /**  a whole segment: zero or more segments ("/acme/**" matches /acme, /acme/x, /acme/x/y)
#   **   inside a segment ("/release-asset-**"): any characters including "/"
# Matching runs a linear-time automaton (no backtracking regex), so hostile request paths cannot blow it up.
_P_LIT, _P_SEGCHAR, _P_STAR, _P_ANY, _P_OPTSLASH = range(5)


@functools.lru_cache(maxsize=4096)
def _compile_path_pattern(p: str) -> Tuple[Tuple[int, str], ...]:
    toks: List[Tuple[int, str]] = []
    i = 0
    while i < len(p):
        if p.startswith("/**", i) and (i + 3 == len(p) or p[i + 3] == "/"):
            toks += [(_P_OPTSLASH, ""), (_P_ANY, "")]
            i += 3
            continue
        if p[i] != "*":
            toks.append((_P_LIT, p[i]))
            i += 1
            continue
        j = i
        while j < len(p) and p[j] == "*":
            j += 1
        if j - i >= 2:
            toks.append((_P_ANY, ""))
        elif (i == 0 or p[i - 1] == "/") and (j == len(p) or p[j] == "/"):
            toks += [(_P_SEGCHAR, ""), (_P_STAR, "")]
        else:
            toks.append((_P_STAR, ""))
        i = j
    return tuple(toks)


def _match_path_tokens(toks: Tuple[Tuple[int, str], ...], s: str) -> bool:
    n = len(toks)

    def closure(states: set) -> set:
        # Epsilon moves only go forward: one ascending pass suffices.
        for k in range(n):
            if k in states:
                kind = toks[k][0]
                if kind in (_P_STAR, _P_ANY):
                    states.add(k + 1)
                elif kind == _P_OPTSLASH:
                    states.add(k + 2)
        return states

    cur = closure({0})
    for ch in s:
        nxt = set()
        for k in cur:
            if k == n:
                continue
            kind, c = toks[k]
            if kind == _P_LIT:
                if ch == c:
                    nxt.add(k + 1)
            elif kind == _P_SEGCHAR:
                if ch != "/":
                    nxt.add(k + 1)
            elif kind == _P_STAR:
                if ch != "/":
                    nxt.add(k)
            elif kind == _P_ANY:
                nxt.add(k)
            elif ch == "/":  # _P_OPTSLASH
                nxt.add(k + 1)
        if not nxt:
            return False
        cur = closure(nxt)
    return n in cur


def match_path(pattern: str, req_path: str) -> bool:
    pat = (pattern or "").strip()
    clean, ok = canonicalize_path(req_path)
    if not ok:
        return False
    if is_domain_wide(pat):
        return True
    clean_pat, ok_pat = canonicalize_path(pat)
    if not ok_pat:
        return False
    if "*" not in clean_pat:
        return clean == clean_pat
    return _match_path_tokens(_compile_path_pattern(clean_pat), clean)


def _split_companion(comp: str) -> Tuple[str, str]:
    comp = (comp or "").strip()
    if "/" not in comp:
        return comp, "/**"
    i = comp.index("/")
    return comp[:i], comp[i:]


def parse_iso(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Go emits nanosecond precision; Python accepts at most microseconds.
    if "." in s:
        head, _, rest = s.partition(".")
        frac = "".join(ch for ch in rest if ch.isdigit())
        tz = rest[len(frac):]
        s = f"{head}.{frac[:6]}{tz}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def is_expired(value: Optional[str], now: float) -> bool:
    ts = parse_iso(value)
    return ts is not None and now > ts


def match_rule(rule: Dict[str, Any], host: str, path: str, method: str, now: float) -> bool:
    if not rule.get("enabled", True) or is_expired(rule.get("expires_at"), now):
        return False
    methods = [str(m).upper() for m in (rule.get("methods") or [])]
    if methods and method != "CONNECT" and "*" not in methods and method not in methods:
        return False
    is_block = str(rule.get("action", "ALLOW")).upper() == "BLOCK"
    comps = [_split_companion(c) for c in (rule.get("companion_rules") or [])]
    if method == "CONNECT":
        # CONNECT only reveals the host: ALLOW rules match on host; BLOCK rules only when domain-wide.
        candidates = [(rule.get("host_pattern", ""), rule.get("path_pattern", ""))] + comps
        for hp, pp in candidates:
            if match_host(hp, host) and (not is_block or is_domain_wide(pp)):
                return True
        return False
    if match_host(rule.get("host_pattern", ""), host) and match_path(rule.get("path_pattern", ""), path):
        return True
    return any(match_host(ch, host) and match_path(cp, path) for ch, cp in comps)


def rule_applies(rule: Dict[str, Any], srv_id: str, groups: List[str]) -> bool:
    """'*' scopes cover sources with a group membership ('*' group) or registered servers ('*'
    server) — never unknown sources (mirrors engine.IndexedRule.AppliesTo)."""
    r_groups = rule.get("group_ids") or []
    r_servers = rule.get("server_ids") or []
    if "*" in r_groups and groups:
        return True
    if "*" in r_servers and srv_id and not srv_id.startswith(UNREGISTERED_PREFIX):
        return True
    if srv_id in r_servers:
        return True
    return any(g in r_groups for g in groups)


def suggest_pattern(host: str, path: str) -> Tuple[str, str]:
    h = normalize_host(host)
    segs = [s for s in (path or "/").split("?", 1)[0].strip("/").split("/") if s]
    if h in ("github.com", "codeload.github.com") and segs:
        return "github.com", f"/{segs[0]}/**"
    if len(segs) >= 2:
        return h, f"/{segs[0]}/{segs[1]}/**"
    if len(segs) == 1:
        return h, f"/{segs[0]}/**"
    return h, "/**"


def to_bytes(value: str) -> bytes:
    """Original bytes of a protocol string: mitmproxy decodes header bytes with surrogateescape, so undecodable
    bytes come back unchanged; any other lone surrogate is replaced. Never raises."""
    try:
        return value.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return value.encode("utf-8", "replace")


def hash_token(token: str) -> str:
    # Attacker-supplied credentials may carry arbitrary bytes: hash them, never raise.
    return hashlib.sha256(to_bytes(token)).hexdigest()


def printable(value: Any, limit: int = 8192) -> str:
    """Untrusted protocol text (URL, Host, User-Agent) as printable ASCII for block pages, logs and telemetry:
    control characters, non-ASCII and surrogate-escaped bytes are percent-encoded."""
    raw = to_bytes(str(value if value is not None else ""))[:limit]
    if all(0x20 <= b < 0x7f for b in raw):
        return raw.decode("ascii")
    return "".join(chr(b) if 0x20 <= b < 0x7f else f"%{b:02X}" for b in raw)


# ---------------------------------------------------------------------------
# Policy bundle & evaluation
# ---------------------------------------------------------------------------

@dataclass
class EvalResult:
    allowed: bool = False
    verdict: str = VERDICT_BLOCKED
    server_id: str = ""
    server_hostname: str = ""
    group_ids: List[str] = field(default_factory=list)
    matched_rule_id: str = ""
    matched_rule_name: str = ""
    follow_redirects: bool = False
    redirect_hosts: List[str] = field(default_factory=list)  # allowlist for redirect grants of the matched rule
    redirect_parent_url: str = ""
    session_id: str = ""
    tls_bypass: bool = False
    suggested_host: str = ""
    suggested_path: str = "/**"
    block_reason: str = ""
    threat_category: str = ""
    threat_source: str = ""
    threat_indicator: str = ""
    security_flags: List[str] = field(default_factory=list)

    def block(self, verdict: str, reason: str, name: str) -> "EvalResult":
        self.allowed, self.verdict, self.block_reason, self.matched_rule_name = False, verdict, reason, name
        self.follow_redirects = self.tls_bypass = False
        return self


@dataclass
class Identity:
    """Resolved requester. method: token | username (bare proxy username bound to the server's IP/subnet) | ip |
    cidr | "" (unregistered). auth_error is set when presented credentials identify no server
    (invalid_proxy_token, proxy_token_required): the request is refused, never attributed to its address."""
    server_id: str
    hostname: str
    group_ids: List[str]
    method: str = ""
    auth_error: str = ""

    @staticmethod
    def of(srv: Dict[str, Any], method: str) -> "Identity":
        return Identity(srv["id"], srv.get("hostname", ""), list(srv.get("group_ids") or []), method)

    @staticmethod
    def unregistered(ip: str, auth_error: str = "") -> "Identity":
        return Identity(f"{UNREGISTERED_PREFIX}{ip}", f"unregistered-{ip}", [], "", auth_error)


class Policy:
    """Immutable compiled view of one control-plane bundle."""

    def __init__(self, bundle: Dict[str, Any]) -> None:
        self.revision = bundle.get("revision", 0)
        self.security: Dict[str, Any] = bundle.get("security_policy") or {}
        self.internal_suffixes = tuple(s if s.startswith(".") else "." + s for s in (bundle.get("internal_domains") or DEFAULT_INTERNAL_SUFFIXES))
        self.public_url: str = bundle.get("public_url") or ""
        self.dashboard_url: str = bundle.get("dashboard_url") or ""
        self.threat_version: str = bundle.get("threat_intel_version") or ""
        self.tls_bypass: List[Dict[str, Any]] = bundle.get("tls_bypass") or []
        self.sessions: List[Dict[str, Any]] = bundle.get("sessions") or []
        rules = bundle.get("rules") or []
        self.block_rules = [r for r in rules if str(r.get("action", "ALLOW")).upper() == "BLOCK"]
        self.allow_rules = [r for r in rules if str(r.get("action", "ALLOW")).upper() != "BLOCK"]
        self.strict_groups = {g.get("id") for g in (bundle.get("groups") or []) if g.get("strict_isolation")}
        self.token_groups = {g.get("id") for g in (bundle.get("groups") or []) if g.get("require_proxy_token")}
        self.cidrs: List[Tuple[str, Any]] = []
        for g in bundle.get("groups") or []:
            if g.get("require_proxy_token"):
                continue  # CIDR membership is an address match: never identifies sources for such a group
            for c in g.get("cidrs") or []:
                try:
                    self.cidrs.append((g.get("id", ""), ipaddress.ip_network(c.strip(), strict=False)))
                except ValueError:
                    continue
        self.block_pages: Dict[str, Any] = bundle.get("block_pages") or {}
        self.yara_rule_sets: List[Dict[str, Any]] = bundle.get("yara_rule_sets") or []
        self.quarantined = {s.get("id") for s in (bundle.get("servers") or []) if s.get("quarantined")}
        self.by_ip: Dict[str, Dict[str, Any]] = {}
        self.by_user: Dict[str, Dict[str, Any]] = {}
        self.by_token: Dict[str, Dict[str, Any]] = {}
        shared_ips = set()
        for srv in bundle.get("servers") or []:
            ip = (srv.get("ip") or "").strip()
            if ip in self.by_ip or ip in shared_ips:
                self.by_ip.pop(ip, None)  # an address registered for several servers identifies none of them
                shared_ips.add(ip)
            elif ip:
                self.by_ip[ip] = srv
            if srv.get("proxy_auth_user"):
                self.by_user[srv["proxy_auth_user"].strip().lower()] = srv
            if srv.get("proxy_auth_token_hash"):
                self.by_token[srv["proxy_auth_token_hash"].strip().lower()] = srv

    def policy_value(self, key: str, default: Any) -> Any:
        v = self.security.get(key)
        return default if v is None else v

    # -- identity -----------------------------------------------------------
    def _token_required(self, srv: Dict[str, Any]) -> bool:
        return any(g in self.token_groups for g in srv.get("group_ids") or [])

    def identify(self, peer_ip: str, proxy_auth: str) -> Identity:
        """Presented credentials decide alone: a proxy token ("username:token" or a bare token) or a bare proxy
        username bound to the server's IP/subnet; anything else is an authentication failure. Without credentials
        the source address identifies the server it is registered for (only when exactly one server has it and none
        of its groups requires a proxy token), then group CIDRs (except groups requiring a token). Same as
        store.Identify in the control-plane."""
        clean_ip = (peer_ip or "").strip()
        if clean_ip.startswith("::ffff:"):
            clean_ip = clean_ip[7:]
        auth = (proxy_auth or "").strip()
        if auth:
            if ":" in auth:
                user, tok = auth.split(":", 1)
                srv = self.by_token.get(hash_token(tok))
                if srv and (not user or user.lower() == (srv.get("proxy_auth_user") or "").lower()):
                    return Identity.of(srv, "token")
                return Identity.unregistered(clean_ip, "invalid_proxy_token")
            srv = self.by_token.get(hash_token(auth))
            if srv:
                return Identity.of(srv, "token")
            srv = self.by_user.get(auth.lower())
            if srv:
                ok = srv.get("ip") == clean_ip
                if not ok and srv.get("subnet_cidr"):
                    try:
                        ok = ipaddress.ip_address(clean_ip) in ipaddress.ip_network(srv["subnet_cidr"], strict=False)
                    except ValueError:
                        ok = False
                if ok:
                    if self._token_required(srv):
                        return Identity.unregistered(clean_ip, "proxy_token_required")
                    return Identity.of(srv, "username")
            return Identity.unregistered(clean_ip, "invalid_proxy_token")
        srv = self.by_ip.get(clean_ip)
        if srv and not self._token_required(srv):
            return Identity.of(srv, "ip")
        try:
            addr = ipaddress.ip_address(clean_ip)
            matched: List[str] = []
            for gid, net in self.cidrs:
                if addr in net and gid not in matched:
                    matched.append(gid)
            if matched:
                octets = clean_ip.replace(".", "-").replace(":", "-")
                return Identity(f"srv-auto-{octets}", f"node-{octets}", matched, "cidr")
        except ValueError:
            pass
        return Identity.unregistered(clean_ip)

    def resolve_server(self, peer_ip: str, proxy_auth: str) -> Tuple[str, str, List[str]]:
        i = self.identify(peer_ip, proxy_auth)
        return i.server_id, i.hostname, i.group_ids

    def _tls_scope_ok(self, b: Dict[str, Any], srv_id: str, groups: List[str]) -> bool:
        b_servers = b.get("server_ids") or []
        b_groups = b.get("group_ids") or []
        if "*" in b_servers or srv_id in b_servers:
            return True
        if b_groups:
            for bg in b_groups:
                if bg == "*":
                    return bool(groups) and not any(g in self.strict_groups for g in groups)
                if bg in groups:
                    return True
            return False
        if b_servers:
            return False
        return bool(groups) and not any(g in self.strict_groups for g in groups)

    # -- evaluation ---------------------------------------------------------
    def evaluate(self, peer_ip: str, proxy_auth: str, method: str, host: str, port: int, path: str,
                 full_url: str, threat: ThreatSnapshot, grants: "RedirectGrants") -> EvalResult:
        ident = self.identify(peer_ip, proxy_auth)
        srv_id, srv_host, groups = ident.server_id, ident.hostname, ident.group_ids
        method = (method or "GET").upper()
        host = normalize_host(host)
        res = EvalResult(server_id=srv_id, server_hostname=srv_host, group_ids=groups, suggested_host=host)
        if ident.auth_error:
            return res.block(VERDICT_AUTH_FAILED, ident.auth_error, AUTH_FAILED_MESSAGES[ident.auth_error])
        if srv_id in self.quarantined:
            return res.block(VERDICT_QUARANTINED, "quarantined",
                             "Incident response: this server is quarantined — all outbound access is blocked")
        clean_path, ok = canonicalize_path(path)
        if not ok:
            return res.block(VERDICT_POLICY, "malformed_path", "Security Guard: Malformed / Traversal Path Anomaly")
        if method == "CONNECT":
            clean_path = "/"
        res.suggested_host, res.suggested_path = suggest_pattern(host, clean_path)
        if not host:
            return res.block(VERDICT_POLICY, "missing_host", "Security Guard: Missing destination host")
        now = time.time()

        # 1. Threat intelligence
        ti_mode = self.policy_value("threat_intel_mode", "block")
        if ti_mode != "off":
            m = threat.match_host(host) or (threat.match_url(full_url) if full_url else None)
            if m:
                res.threat_category, res.threat_source, res.threat_indicator = m.category, m.source_name, m.indicator
                if ti_mode == "block":
                    res.block(VERDICT_THREAT, "threat_intel", f"Threat Intelligence: {m.category} ({m.source_name})")
                    res.matched_rule_id = m.source_id
                    return res
                res.security_flags.append(f"THREAT_MONITOR:{m.category}")

        # 2. Destination hygiene
        addr = parse_ip(host)
        if addr is not None and is_forbidden_addr(addr):
            return res.block(VERDICT_POLICY, "forbidden_destination",
                             "Security Guard: Loopback / link-local / metadata destinations are never reachable via the proxy")
        if host == "localhost" or host.endswith(".localhost"):
            return res.block(VERDICT_POLICY, "forbidden_destination", "Security Guard: localhost is never reachable via the proxy")
        allowed_ports = self.policy_value("allowed_ports", [80, 443])
        if port and allowed_ports and port not in allowed_ports:
            return res.block(VERDICT_POLICY, "port_not_allowed",
                             f"Security Guard: destination port {port} is not in the allowed port list")
        internal = bool(self.policy_value("block_private_destinations", True)) and is_internal_host(host, self.internal_suffixes)
        if any(label.startswith("xn--") for label in host.split(".")):
            mode = self.policy_value("punycode_mode", "monitor")
            if mode == "block":
                return res.block(VERDICT_POLICY, "punycode", "Security Guard: Internationalized (punycode) domain blocked (homograph protection)")
            if mode == "monitor":
                res.security_flags.append("PUNYCODE")

        # 3. BLOCK guardrails
        for rule in self.block_rules:
            if rule_applies(rule, srv_id, groups) and match_rule(rule, host, clean_path, method, now):
                res.matched_rule_id, res.matched_rule_name, res.block_reason = rule.get("id", ""), rule.get("name", ""), "block_rule"
                return res

        # 4. TLS passthrough
        for b in self.tls_bypass:
            if not b.get("enabled", True) or is_expired(b.get("expires_at"), now):
                continue
            if internal and "*" in (b.get("pattern") or ""):
                continue
            if match_host(b.get("pattern", ""), host) and self._tls_scope_ok(b, srv_id, groups):
                res.allowed, res.verdict, res.tls_bypass = True, VERDICT_TLS_BYPASS, True
                res.matched_rule_id, res.matched_rule_name = b.get("id", ""), f"TLS Passthrough: {b.get('pattern', host)}"
                return res

        ip_needs_explicit = addr is not None and bool(self.policy_value("block_ip_literals", True))
        implicit_ok = not internal and not ip_needs_explicit
        # Temporary grants (learning sessions, redirect objects) never open anything for strict-isolation tiers.
        strict = any(g in self.strict_groups for g in groups)

        if implicit_ok:
            # 5. Learning session, bound to the resolved server identity (the source address only counts where
            # identify() accepted it: no credentials and registered for exactly this server)
            for sess in self.sessions:
                if sess.get("status") != "active" or is_expired(sess.get("expires_at"), now):
                    continue
                if sess.get("server_id") == srv_id:
                    res.session_id = sess.get("id", "")
                    if sess.get("mode") == "record_and_allow" and not strict:
                        res.allowed, res.verdict, res.follow_redirects = True, VERDICT_LEARNING, True
                        res.matched_rule_id, res.matched_rule_name = sess.get("id", ""), f"Learning Session: {sess.get('name', '')}"
                        return res
            # 6. Redirect-object grant of this server
            grant = None if strict else grants.check(srv_id, host, clean_path, method)
            if grant:
                res.allowed, res.verdict = True, VERDICT_REDIRECT
                res.matched_rule_id, res.matched_rule_name = grant[1], f"{grant[2]} (Object Redirect)"
                res.redirect_parent_url = grant[0]
                return res

        # 7. ALLOW rules (internal / IP-literal destinations need an explicit, non-wildcard rule)
        for rule in self.allow_rules:
            if not implicit_ok and "*" in (rule.get("host_pattern") or ""):
                continue
            if rule_applies(rule, srv_id, groups) and match_rule(rule, host, clean_path, method, now):
                res.allowed, res.verdict = True, VERDICT_ALLOWED
                res.matched_rule_id, res.matched_rule_name = rule.get("id", ""), rule.get("name", "")
                res.follow_redirects = bool(rule.get("follow_redirects"))
                res.redirect_hosts = [str(h) for h in (rule.get("redirect_hosts") or [])]
                return res

        if ip_needs_explicit:
            return res.block(VERDICT_POLICY, "ip_literal", "Security Guard: Direct IP-address destinations require an explicit whitelist rule")
        if internal:
            return res.block(VERDICT_POLICY, "internal_destination",
                             "Security Guard: Internal destinations are not reachable via the egress proxy without an explicit rule")
        res.block_reason = "default_deny"
        return res


class RedirectGrants:
    """Short-lived (2 min) single-hop grants for objects reached through an allowed redirect. Grants belong to the
    resolved server identity (server ID), never to the source address: servers behind one NAT address must not
    share each other's grants."""

    TTL = 120.0
    MAX = 8192

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: Dict[str, Tuple[str, str, str, float]] = {}

    def register(self, server_id: str, location: str, parent_url: str, rule_id: str, rule_name: str,
                 internal_suffixes=DEFAULT_INTERNAL_SUFFIXES, allowed_hosts=()) -> bool:
        """Grants the redirect target to server_id for TTL seconds. Internal targets never get a grant; a non-empty
        ``allowed_hosts`` (the rule's redirect_hosts patterns) limits the targets further."""
        if not server_id:
            return False
        try:
            target = urllib.parse.urlsplit(urllib.parse.urljoin(parent_url, location))
        except ValueError:
            return False
        if target.scheme not in ("http", "https") or not target.hostname:
            return False
        host = normalize_host(target.hostname)
        if is_internal_host(host, internal_suffixes):
            return False
        if allowed_hosts and not any(match_host(p, host) for p in allowed_hosts):
            return False
        path, ok = canonicalize_path(target.path or "/")
        if not ok:
            return False
        exp = time.time() + self.TTL
        with self._lock:
            if len(self._grants) >= self.MAX:
                now = time.time()
                for k in [k for k, v in self._grants.items() if v[3] < now]:
                    del self._grants[k]
                if len(self._grants) >= self.MAX:
                    self._grants.clear()
            self._grants[f"{server_id}|{host}|{path}"] = (parent_url, rule_id, rule_name, exp)
            self._grants[f"{server_id}|{host}|CONNECT"] = (parent_url, rule_id, rule_name, exp)
        return True

    def check(self, server_id: str, host: str, path: str, method: str) -> Optional[Tuple[str, str, str, float]]:
        if method not in ("GET", "HEAD", "CONNECT") or not server_id:
            return None
        key = f"{server_id}|{host}|CONNECT" if method == "CONNECT" else f"{server_id}|{host}|{path}"
        with self._lock:
            grant = self._grants.get(key)
        if grant and time.time() < grant[3]:
            return grant
        return None
