"""Long-lived connections and their re-evaluation when the policy changes.

A WebSocket, a streamed or slow transfer, an open CONNECT tunnel, a TLS passthrough (no-break) tunnel or a raw TCP/UDP
relay outlives the evaluation that admitted it. Each one is registered here with the inputs of that evaluation. After
every policy bundle or threat-intelligence update, when a time-limited rule, grant or learning session expires, and
when the policy becomes stale (AEGIS_POLICY_MAX_AGE), every registered connection is evaluated again; the addon closes
the ones that are no longer allowed and records the reason (security flag CONNECTION_TERMINATED:<reason>).

Kept for a connection's lifetime:
  * a redirect-object grant that admitted a download (grants authorize starting a transfer, they do not cut it off
    after their two minutes)
  * a CONNECT tunnel that was opened under default deny (its requests are evaluated one by one and get block pages);
    it is only closed for a hard block (quarantine, threat intelligence, a guardrail)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .policy import (
    SECURITY_VERDICTS, VERDICT_LEARNING, VERDICT_QUARANTINED, VERDICT_REDIRECT, VERDICT_THREAT, VERDICT_TLS_BYPASS,
    EvalResult, Policy, parse_iso,
)

KINDS = ("http", "websocket", "connect", "passthrough", "tcp", "udp")
REASON_TEXT = {
    "quarantined": "the server was quarantined",
    "threat_intel": "the destination is now listed by threat intelligence",
    "rule_revoked": "the allow rule was revoked, disabled or expired",
    "block_rule": "a block rule now covers the destination",
    "group_changed": "the server's group memberships changed",
    "learning_session_ended": "the learning session ended",
    "redirect_grant_expired": "the redirect grant expired",
    "tls_bypass_revoked": "the TLS passthrough rule was removed",
    "raw_tcp_disabled": "raw TCP/UDP relaying was disabled",
    "policy_blocked": "a policy guardrail now blocks the destination",
    "policy_stale": "the worker's policy is older than AEGIS_POLICY_MAX_AGE",
    "internal_error": "re-evaluation failed (fail-closed)",
}


@dataclass
class LiveConn:
    key: Any
    kind: str
    client_id: str
    peer: str
    auth: str
    method: str
    host: str
    port: int
    path: str = "/"
    url: str = ""
    scheme: str = ""
    verdict: str = ""
    allowed: bool = True
    server_id: str = ""
    server_hostname: str = ""
    group_ids: List[str] = field(default_factory=list)
    grant: Optional[Tuple[str, str, str, float]] = None
    flow: Any = None
    started: float = field(default_factory=time.time)
    checked: Tuple[Any, ...] = ()
    terminated: str = ""


class PinnedGrants:
    """Redirect grants for a re-evaluation: the grant that admitted the connection stays valid for it."""

    def __init__(self, grants: Any, pinned: Optional[Tuple[str, str, str, float]]) -> None:
        self.grants, self.pinned = grants, pinned

    def check(self, server_id: str, host: str, path: str, method: str, scheme: str = "https", port: int = 0):
        found = self.grants.check(server_id, host, path, method, scheme, port) if self.grants is not None else None
        if found is None and self.pinned is not None:
            return self.pinned[:3] + (float("inf"),)
        return found


def raw_reason(conn: LiveConn, policy: Policy) -> str:
    """Raw relays are not matched against rules (they only exist with block_raw_tcp off)."""
    if policy.policy_value("block_raw_tcp", True):
        return "raw_tcp_disabled"
    srv_id, _, _ = policy.resolve_server(conn.peer, conn.auth)
    return "quarantined" if srv_id in policy.quarantined else ""


def decide(conn: LiveConn, policy: Policy, threat: Any, grants: Any) -> Tuple[str, Optional[EvalResult]]:
    """Returns (termination reason or "", the new evaluation)."""
    if conn.kind in ("tcp", "udp"):
        return raw_reason(conn, policy), None
    res = policy.evaluate(conn.peer, conn.auth, conn.method, conn.host, conn.port, conn.path, conn.url, threat,
                          PinnedGrants(grants, conn.grant))
    if res.verdict == VERDICT_QUARANTINED:
        return "quarantined", res
    if res.verdict == VERDICT_THREAT:
        return "threat_intel", res
    if conn.kind == "passthrough":
        return ("" if res.verdict == VERDICT_TLS_BYPASS else "tls_bypass_revoked"), res
    if res.allowed:
        return "", res
    if not conn.allowed:
        # Opened under default deny (CONNECT): only a hard block closes it.
        return ("policy_blocked" if res.verdict in SECURITY_VERDICTS else ""), res
    if res.block_reason == "block_rule":
        return "block_rule", res
    if res.verdict in SECURITY_VERDICTS:
        return "policy_blocked", res
    if conn.verdict == VERDICT_LEARNING:
        return "learning_session_ended", res
    if conn.verdict == VERDICT_REDIRECT:
        return "redirect_grant_expired", res
    if sorted(conn.group_ids) != sorted(res.group_ids):
        return "group_changed", res
    return "rule_revoked", res


def next_expiry(policy: Policy, now: float) -> float:
    """Earliest future expiry of a rule, TLS passthrough rule or learning session (inf when none): crossing it can
    revoke access without a new policy bundle."""
    soonest = float("inf")
    items: Iterable[Dict[str, Any]] = list(policy.allow_rules) + list(policy.block_rules) + list(policy.tls_bypass) + list(policy.sessions)
    for item in items:
        ts = parse_iso(item.get("expires_at"))
        if ts is not None and now < ts < soonest:
            soonest = ts
    return soonest


class Registry:
    """Live connections by key, indexed by client connection (all are dropped when the client disconnects)."""

    def __init__(self) -> None:
        self.conns: Dict[Any, LiveConn] = {}
        self.by_client: Dict[str, Set[Any]] = {}
        self._counts: Dict[str, int] = {k: 0 for k in KINDS}  # read by the metrics thread

    def __len__(self) -> int:
        return len(self.conns)

    def add(self, conn: LiveConn) -> LiveConn:
        self.discard(conn.key)
        self.conns[conn.key] = conn
        self.by_client.setdefault(conn.client_id, set()).add(conn.key)
        self._counts[conn.kind] = self._counts.get(conn.kind, 0) + 1
        return conn

    def get(self, key: Any) -> Optional[LiveConn]:
        return self.conns.get(key)

    def discard(self, key: Any) -> Optional[LiveConn]:
        conn = self.conns.pop(key, None)
        if conn is not None:
            self._counts[conn.kind] -= 1
            keys = self.by_client.get(conn.client_id)
            if keys is not None:
                keys.discard(key)
                if not keys:
                    del self.by_client[conn.client_id]
        return conn

    def drop_client(self, client_id: str) -> None:
        for key in list(self.by_client.get(client_id, ())):
            self.discard(key)

    def snapshot(self) -> List[LiveConn]:
        """Most specific first: when a request or WebSocket and its tunnel are both revoked, the one closing of the
        client connection is recorded with the request's reason."""
        return sorted(self.conns.values(), key=lambda c: {"passthrough": 1, "connect": 2}.get(c.kind, 0))

    def kinds(self) -> Dict[str, int]:
        return dict(self._counts)
