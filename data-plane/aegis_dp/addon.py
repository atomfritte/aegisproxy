"""mitmproxy addon: enforces AegisProxy policy on every connection and request.

Hook pipeline (regular proxy mode, rawtcp disabled):
  http_connect       identify the server (Proxy-Authorization), hard-block threats / bad ports / internal targets
  tls_clienthello    SNI must equal the CONNECT target (other modes: must resolve to the destination IP);
                     scoped no-break TLS passthrough
  requestheaders     Host/SNI consistency (destination binding in transparent/SOCKS/reverse modes), policy
                     evaluation, block page with signed block token; Accept-Encoding/Range rewriting for inspection
  request            DLP (secrets in URL/body), upload size limit, ICAP REQMOD
                     (request bodies are only buffered when one of these needs them: buffering.py)
  server_connect     resolve + vet destination IPs (threat IPs, DNS rebinding to internal ranges), pin the IP
  responseheaders    streaming / oversize / undecodable / partial-content decisions
  response           SHA-256 IOC check, file-type policy, YARA, ClamAV, ICAP RESPMOD, redirect lineage, telemetry
  tcp_start/udp_start  reject raw relays (only reachable via --tcp-hosts); payload is dropped in tcp_message

Every hook fails closed: an exception blocks the request (403, or 503 for infrastructure errors), refuses
the upstream connection or kills the flow, and is counted in aegis_dp_hook_errors_total{hook}. A flow that
reaches request/responseheaders/response without a completed evaluation is blocked.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import inspect
import logging
import re
import socket
import time
import urllib.parse
import uuid
from typing import Any, Callable, Dict, List, Optional

from mitmproxy import connection, ctx, http, tcp, tls, udp
from mitmproxy.proxy import server_hooks

from . import __version__, buffering
from .accesslog import AccessLog
from .blockpage import is_cli_client, render_branded, render_cli, render_html
from .buffering import BLOCK, STREAM, BodyGuard, BufferBudget
from .clamav import ClamdClient
from .config import Config
from .content import detect_file_type, scan_dlp
from .decoding import UndecodableContent, decodable, decode_body, filter_accept_encoding, parse_codings, transfer_codings
from .destination import DnsCache, check_binding
from .ops import Metrics, start_ops_server
from .controlplane import ControlPlaneClient, sign_block_token
from .icap import IcapClient, IcapResult
from .yara_scan import YaraEngine
from .policy import (
    VERDICT_DLP, VERDICT_FILETYPE, VERDICT_LEARNING, VERDICT_MALWARE, VERDICT_POLICY, VERDICT_THREAT,
    VERDICT_TLS_BYPASS, EvalResult, Policy, RedirectGrants, is_forbidden_addr, is_internal_addr, is_internal_host,
    normalize_host, parse_ip, printable,
)

log = logging.getLogger("aegis.dataplane")

INTERNAL_HEADERS = ("X-Aegis-DataPlane-Key", "X-Simulated-Server-IP", "Proxy-Authorization", "Proxy-Connection")
STREAM_WITHOUT_INSPECTION = 8 * 1024 * 1024  # bodies nothing inspects are buffered only up to this size
DEFAULT_BUFFER_BUDGET = 512 * 1024 * 1024  # AEGIS_BUFFER_BUDGET unset: min(this, body_size_limit)
MAX_TRACKED_CONNECTIONS = 65536
REGULAR_MODES = ("regular", "upstream")  # the client names the destination; everything else connects to an address
INFRA_ERRORS = (OSError, asyncio.TimeoutError, TimeoutError)  # -> 503 instead of 403
_HOST_RE = re.compile(r"[a-z0-9_\-.]+")
_BLOCKED_RESPONSE_HEADERS = ("Content-Encoding", "Transfer-Encoding", "Content-Disposition", "Content-Range", "ETag",
                             "Last-Modified", "Content-MD5", "Digest", "Repr-Digest", "Location")


def parse_proxy_auth(value: Optional[str]) -> str:
    """Returns "user:token" (Basic) or the bearer token. Never logged or stored by the control-plane."""
    if not value:
        return ""
    scheme, _, cred = value.strip().partition(" ")
    if scheme.lower() == "basic" and cred:
        try:
            decoded = base64.b64decode(cred.strip(), validate=True).decode("utf-8", "ignore").strip()
        except (ValueError, UnicodeDecodeError):
            return ""
        return decoded[:-1] if decoded.endswith(":") else decoded
    if scheme.lower() == "bearer" and cred:
        return cred.strip()
    return ""


def valid_host(host: str) -> bool:
    """A normalized destination host must be a DNS name or an IP literal (no control, non-ASCII or other bytes)."""
    return not host or bool(_HOST_RE.fullmatch(host)) or parse_ip(host) is not None


def _trace_id() -> str:
    return "flw-" + uuid.uuid4().hex[:16]


def _peer(conn: Optional[connection.Client]) -> str:
    if conn and conn.peername:
        ip = conn.peername[0]
        return ip[7:] if ip.startswith("::ffff:") else ip
    return ""


def _bounded_put(d: Dict[Any, Any], key: Any, value: Any, limit: int = MAX_TRACKED_CONNECTIONS) -> None:
    d.pop(key, None)
    while len(d) >= limit:
        d.pop(next(iter(d)))  # oldest first (dicts keep insertion order)
    d[key] = value


def _replace_body(message: http.Message, body: bytes) -> None:
    """Delivers ``body`` as-is (identity): the coding is dropped, Content-Length is recomputed."""
    message.headers.pop("Content-Encoding", None)
    message.content = body


def guarded(fn: Callable) -> Callable:
    """Fail-closed wrapper for mitmproxy hooks: an exception must never let traffic through unchecked."""
    hook = fn.__name__
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def run_async(self: "AegisAddon", data: Any) -> None:
            try:
                await fn(self, data)
            except Exception as exc:  # noqa: BLE001 - see _hook_failed
                self._hook_failed(hook, data, exc)
        return run_async

    @functools.wraps(fn)
    def run(self: "AegisAddon", data: Any) -> None:
        try:
            fn(self, data)
        except Exception as exc:  # noqa: BLE001
            self._hook_failed(hook, data, exc)
    return run


class AegisAddon:
    def __init__(self, cfg: Optional[Config] = None) -> None:
        self.cfg = cfg or Config.from_env()
        self.clamd = ClamdClient(self.cfg.clamd_address, self.cfg.clamd_timeout) if self.cfg.clamd_address else None
        self.yara = YaraEngine()
        self._yara_rev: Optional[int] = None
        self._icap: Dict[str, IcapClient] = {}
        self.cp = ControlPlaneClient(self.cfg, clamav_status=self._clamav_status, on_flow=self._count_flow,
                                     status_headers=self._engine_status)
        self.grants = RedirectGrants()
        self.dns = DnsCache()
        self.conn_auth: Dict[str, str] = {}
        self._bound: Dict[str, Dict[Any, str]] = {}  # client id -> {(dest ip, port): Host/SNI bound to it}
        self._tainted: Dict[str, float] = {}  # client ids whose TLS hook failed: every request is blocked
        self._tasks: List[asyncio.Task] = []
        self._last_unavailable_log = 0.0
        self.metrics = Metrics()
        self._ops = None
        buffering.install()
        self.budget = BufferBudget(self.cfg.buffer_budget or DEFAULT_BUFFER_BUDGET)
        self.access_log = AccessLog(self.cfg.access_log, self.cfg.access_log_format,
                                    self.cfg.access_log_rotate_mb << 20, self.cfg.access_log_keep)

    # ------------------------------------------------------------------ lifecycle
    def running(self) -> None:
        if ctx.options.ssl_insecure:
            log.critical("ssl_insecure=true disables upstream certificate validation — this is not allowed for AegisProxy")
            ctx.options.update(ssl_insecure=False)
        if ctx.options.connection_strategy != "lazy":
            # Never open upstream connections before the request was authorized.
            ctx.options.update(connection_strategy="lazy")
        if getattr(ctx.options, "flow_detail", 0) > 2:
            # flow_detail 3+ makes mitmdump decode every body for display, without any size limit.
            log.warning("flow_detail > 2 is not supported (unbounded body decoding); using 2")
            ctx.options.update(flow_detail=2)
        # Non-HTTP payloads inside CONNECT tunnels must never be relayed: with rawtcp disabled mitmproxy
        # parses them as HTTP, answers 400 and never opens an upstream connection.
        ctx.options.update(rawtcp=False)
        if not self.cfg.buffer_budget:
            try:
                limit = buffering.parse_size(str(ctx.options.body_size_limit or ""))
            except ValueError:
                limit = None
            self.budget.total = min(DEFAULT_BUFFER_BUDGET, limit or DEFAULT_BUFFER_BUDGET)
        log.info("inspection buffer budget %d MiB (body_size_limit=%s)", self.budget.total >> 20, ctx.options.body_size_limit or "unlimited")
        self.cp.start()
        if self.cfg.ops_addr and self._ops is None:
            try:
                self._ops = start_ops_server(self.cfg.ops_addr, self.metrics, self._gauges, lambda: self.cp.policy is not None)
            except OSError as exc:
                log.error("could not start ops endpoint on %s: %s", self.cfg.ops_addr, exc)
        loop = asyncio.get_running_loop()
        self._tasks.append(loop.create_task(self._apply_runtime_options()))
        if self.clamd:
            self._tasks.append(loop.create_task(self._clamd_health()))
        self._tasks.append(loop.create_task(self._icap_health()))
        log.info("AegisProxy data-plane %s started (worker=%s, control-plane=%s, clamd=%s, fail_mode=%s)",
                 __version__, self.cfg.worker_id, self.cfg.control_plane_url, self.cfg.clamd_address or "disabled", self.cfg.fail_mode)

    def done(self) -> None:
        for t in self._tasks:
            t.cancel()
        self.cp.stop()
        if self._ops:
            self._ops.shutdown()
        self.access_log.close()

    def _gauges(self) -> Dict[str, float]:
        d, u, i, c, h = self.cp.threat.stats()
        pol = self.cp.policy
        return {
            "aegis_dp_policy_loaded": 1.0 if pol else 0.0,
            "aegis_dp_policy_revision": float(pol.revision if pol else 0),
            "aegis_dp_policy_sync_age_seconds": (time.time() - self.cp.last_sync_ok) if self.cp.last_sync_ok else -1.0,
            "aegis_dp_threatintel_indicators": float(d + u + i + c + h),
            "aegis_dp_clamd_available": {True: 1.0, False: 0.0}.get(self.clamd.available if self.clamd else None, -1.0),
            "aegis_dp_telemetry_queue": float(self.cp.queue_len()),
            "aegis_dp_identified_connections": float(len(self.conn_auth)),
            "aegis_dp_buffer_budget_bytes": float(self.budget.total),
            "aegis_dp_buffered_bytes": float(self.budget.used),
            "aegis_dp_buffered_bytes_peak": float(self.budget.peak),
            "aegis_dp_access_log_dropped_total": float(self.access_log.dropped),
            "aegis_dp_access_log_rotation_failures_total": float(self.access_log.rotation_failures),
        }

    def client_disconnected(self, client: connection.Client) -> None:
        self.conn_auth.pop(client.id, None)
        self._bound.pop(client.id, None)
        self._tainted.pop(client.id, None)

    def error(self, flow: http.HTTPFlow) -> None:
        buffering.release(flow)  # aborted, killed or disconnected flows return their buffer share

    async def _apply_runtime_options(self) -> None:
        """Mirror policy switches that map to mitmproxy options (runs on the event loop thread)."""
        while True:
            policy = self._policy()
            if policy is not None:
                want_raw = not bool(policy.policy_value("block_raw_tcp", True))
                if ctx.options.rawtcp != want_raw:
                    ctx.options.update(rawtcp=want_raw)
                    log.warning("raw TCP relaying %s by security policy", "ENABLED" if want_raw else "disabled")
            await asyncio.sleep(5)

    async def _clamd_health(self) -> None:
        while True:
            ok = await self.clamd.ping()
            if not ok:
                log.warning("clamd at %s is not reachable", self.cfg.clamd_address)
            await asyncio.sleep(30)

    # ------------------------------------------------------------------ fail-closed hook guard
    def _hook_failed(self, hook: str, data: Any, exc: BaseException) -> None:
        self.metrics.inc("aegis_dp_hook_errors_total", (("hook", hook),))
        log.error("%s hook failed (%s: %s); failing closed", hook, type(exc).__name__, printable(exc, 300), exc_info=exc)
        try:
            self._contain(hook, data, 503 if isinstance(exc, INFRA_ERRORS) else 403)
        except Exception:  # noqa: BLE001 - containment must not raise either: last resort is killing the flow
            log.exception("fail-closed handling of the %s hook failed; killing the flow", hook)
            try:
                if getattr(data, "killable", False):
                    data.kill()
            except Exception:  # noqa: BLE001
                pass

    def _contain(self, hook: str, data: Any, status: int) -> None:
        if isinstance(data, http.HTTPFlow):
            self._deny(data, hook, status, "internal_error",
                       f"Security Guard: policy enforcement failed in the {hook} stage; request blocked (fail-closed)")
        elif isinstance(data, tls.ClientHelloData):
            # Never pass through on an incomplete decision: intercept and block every request of the connection.
            data.ignore_connection = False
            _bounded_put(self._tainted, data.context.client.id, time.time())
        elif isinstance(data, server_hooks.ServerConnectionHookData):
            data.server.error = "AegisProxy: destination checks failed (fail-closed)"
        elif isinstance(data, (tcp.TCPFlow, udp.UDPFlow)):
            data.metadata["aegis_rejected"] = True
            if data.messages:
                data.messages[-1].content = b""
            if data.killable:
                data.kill()

    def _deny(self, flow: http.HTTPFlow, hook: str, status: int, reason: str, name: str) -> None:
        """Blocks a flow without relying on the evaluation (which failed or never happened)."""
        trace = _trace_id()
        msg = f"AegisProxy blocked this request: {name}.\nTrace ID: {trace}\n".encode("utf-8", "replace")
        resp = flow.response
        if hook == "response" and resp is not None and resp.stream:
            if flow.killable:
                flow.kill()  # the body was streamed already: abort the transfer
        elif hook == "responseheaders" and resp is not None:
            self._replace_streamed(flow, status, msg, VERDICT_POLICY)
        else:
            flow.response = http.Response.make(status, msg, {
                "Content-Type": "text/plain; charset=utf-8", "X-Aegis-Verdict": VERDICT_POLICY, "X-Aegis-Trace-ID": trace,
                "Cache-Control": "no-store"})
        flow.metadata["aegis_local"] = flow.metadata["aegis_recorded"] = True
        try:
            meta = flow.metadata.get("aegis")
            if meta:
                res: EvalResult = meta["res"]
                res.block(VERDICT_POLICY, reason, name)
                self.cp.record_flow(self._flow_record(flow, res, meta["peer"], meta["auth"], status, VERDICT_POLICY, trace_id=trace))
                return
            req = flow.request
            self.cp.record_flow({
                "id": trace, "server_ip": _peer(flow.client_conn), "method": printable(req.method, 32), "scheme": req.scheme,
                "host": printable(normalize_host(req.host), 255), "port": req.port,
                "path": printable(req.path.split("?", 1)[0], 2048) or "/", "full_url": printable(req.pretty_url, 4096),
                "user_agent": printable(req.headers.get("User-Agent", ""), 512), "verdict": VERDICT_POLICY,
                "block_reason": reason, "matched_rule_name": name, "status_code": status, "tls_intercepted": req.scheme == "https",
            })
        except Exception:  # noqa: BLE001 - telemetry must not undo the block
            log.exception("could not record blocked flow %s", trace)

    # ------------------------------------------------------------------ scan engines (YARA, ICAP)
    def _engine_status(self) -> Dict[str, str]:
        policy = self.cp.policy
        if policy is not None:
            self._yara_sync(policy)
        icap = []
        for kind in ("respmod", "reqmod"):
            url = policy.policy_value(f"icap_{kind}_url", "") if policy else ""
            if url:
                c = self._icap.get(url)
                state = {True: "ok", False: "down"}.get(c.available if c else None, "unknown")
                icap.append(f"{kind}={state}")
        return {"X-Aegis-YARA": self.yara.heartbeat(), "X-Aegis-ICAP": ",".join(icap) or "disabled"}

    def _yara_sync(self, policy: Policy) -> None:
        if self._yara_rev != policy.revision:
            self.yara.configure(policy.yara_rule_sets)
            self._yara_rev = policy.revision

    def _icap_client(self, url: str, policy: Policy) -> IcapClient:
        timeout = float(policy.policy_value("icap_timeout_seconds", 30) or 30)
        verify = not bool(policy.policy_value("icap_tls_skip_verify", False))
        ca = policy.policy_value("icap_ca_cert_pem", "") or ""
        key = f"{url}|{timeout}|{verify}|{hash(ca)}"
        c = self._icap.get(key)
        if c is None:
            c = IcapClient(url, timeout=timeout, tls_verify=verify, ca_pem=ca)
            self._icap = {k: v for k, v in self._icap.items() if not k.startswith(url + "|") and k != url}
            _bounded_put(self._icap, key, c, 32)
            _bounded_put(self._icap, url, c, 32)
        return c

    async def _icap_call(self, url: str, policy: Policy, mode: str, *args: Any) -> IcapResult:
        """Any failure on the ICAP path (invalid URL, TLS setup, protocol) is an "error" result, so that
        icap_fail_mode decides — never an exception that would skip the scan."""
        try:
            client = self._icap_client(url, policy)
            return await getattr(client, mode)(*args)
        except Exception as exc:  # noqa: BLE001
            log.warning("ICAP %s via %s failed: %s", mode, url, exc)
            return IcapResult("error", detail=f"ICAP error: {type(exc).__name__}: {exc}"[:200])

    async def _icap_health(self) -> None:
        """Probes configured ICAP services with OPTIONS: new URLs within seconds, then every minute."""
        invalid: set = set()
        while True:
            policy = self._policy()
            if policy is not None:
                for kind in ("respmod", "reqmod"):
                    url = policy.policy_value(f"icap_{kind}_url", "")
                    if not url or url in invalid:
                        continue
                    try:
                        client = self._icap_client(url, policy)
                    except Exception as exc:  # noqa: BLE001 - invalid URL or CA bundle: the probe loop must survive
                        if len(invalid) > 64:
                            invalid.clear()
                        invalid.add(url)
                        log.error("invalid ICAP configuration for %s: %s", url, exc)
                        continue
                    if client.available is not None and time.time() - client.last_options < 60:
                        continue
                    if not await client.options():
                        log.warning("ICAP service %s is not reachable", url)
            await asyncio.sleep(5)

    def _count_flow(self, flow: Dict[str, Any]) -> None:
        self.metrics.inc("aegis_dp_flows_total", (("verdict", str(flow.get("verdict", ""))),))
        self.access_log.write(flow)

    def _clamav_status(self) -> str:
        if not self.clamd:
            return "disabled"
        return {True: "yes", False: "no"}.get(self.clamd.available, "unknown")

    # ------------------------------------------------------------------ helpers
    def _policy(self) -> Optional[Policy]:
        return self.cp.policy

    def _urls(self, policy: Optional[Policy]):
        public = (policy.public_url if policy else "") or self.cfg.public_url or self.cfg.control_plane_url
        dashboard = (policy.dashboard_url if policy else "") or self.cfg.dashboard_url or public
        return public.rstrip("/"), dashboard.rstrip("/")

    def _regular_like(self, client: Optional[connection.Client]) -> bool:
        """True when the client names the destination (regular/upstream proxy listener). Uses the mode of the
        listener the client connected to; AEGIS_PROXY_MODE is only the fallback."""
        mode = getattr(client, "proxy_mode", None) if client is not None else None
        return (getattr(mode, "type_name", None) or self.cfg.proxy_mode) in REGULAR_MODES

    def _bind(self, client: Optional[connection.Client], dest: str, port: int, name: str) -> None:
        if client is None:
            return
        bindings = self._bound.get(client.id)
        if bindings is None:
            bindings = {}
            _bounded_put(self._bound, client.id, bindings)
        _bounded_put(bindings, (str(parse_ip(dest) or normalize_host(dest)), int(port)), name, 64)

    def _bound_name(self, client: Optional[connection.Client], dest: Any, port: int) -> str:
        return (self._bound.get(client.id) or {}).get((str(dest), int(port)), "") if client is not None else ""

    def _unavailable(self, flow: http.HTTPFlow) -> bool:
        """No policy bundle loaded yet. Returns True if the request was answered (fail-closed)."""
        if self.cfg.fail_mode == "open":
            return False
        now = time.time()
        if now - self._last_unavailable_log > 10:
            self._last_unavailable_log = now
            log.error("no policy bundle loaded from %s — failing closed", self.cfg.control_plane_url)
        flow.response = http.Response.make(503, b"AegisProxy: policy not available yet (fail-closed). Retry shortly.\n",
                                           {"Content-Type": "text/plain; charset=utf-8", "Retry-After": "5", "X-Aegis-Verdict": "UNAVAILABLE"})
        flow.metadata["aegis_local"] = True
        return True

    def _identity(self, flow: http.HTTPFlow) -> str:
        auth = parse_proxy_auth(flow.request.headers.get("Proxy-Authorization"))
        if auth and flow.client_conn:
            _bounded_put(self.conn_auth, flow.client_conn.id, auth)
        return auth or (self.conn_auth.get(flow.client_conn.id, "") if flow.client_conn else "")

    def _flow_record(self, flow: http.HTTPFlow, res: EvalResult, peer: str, auth: str, status: int, verdict: str, **extra: Any) -> Dict[str, Any]:
        req = flow.request
        user = auth.split(":", 1)[0] if auth else ""
        rec = {
            "id": extra.pop("trace_id", None) or _trace_id(),
            "server_ip": peer, "server_id": res.server_id, "server_hostname": res.server_hostname, "group_ids": res.group_ids,
            "proxy_auth_user": printable(user, 255), "method": printable(req.method, 32), "scheme": req.scheme,
            "host": printable(normalize_host(req.host), 255), "port": req.port,
            "path": printable(req.path.split("?", 1)[0], 2048) or "/", "full_url": printable(req.pretty_url, 4096),
            "user_agent": printable(req.headers.get("User-Agent", ""), 512), "verdict": verdict,
            "matched_rule_id": res.matched_rule_id, "matched_rule_name": res.matched_rule_name,
            "redirect_parent_url": res.redirect_parent_url, "status_code": status,
            "tls_intercepted": req.scheme == "https", "session_id": res.session_id, "follow_redirects": res.follow_redirects,
            "block_reason": res.block_reason, "threat_category": res.threat_category, "threat_source": res.threat_source,
            "threat_indicator": res.threat_indicator, "security_flags": list(res.security_flags),
        }
        rec.update(extra)
        return rec

    def _block(self, flow: http.HTTPFlow, res: EvalResult, peer: str, auth: str, status: int = 403, **extra: Any) -> None:
        policy = self._policy()
        public, dashboard = self._urls(policy)
        trace = _trace_id()
        url = printable(flow.request.pretty_url, 4096)  # Host/URL bytes are attacker-controlled
        method = printable(flow.request.method, 32)
        token = sign_block_token(self.cfg.dataplane_key, {"ip": peer, "sid": res.server_id, "url": url,
                                                          "m": method, "tid": trace, "v": res.verdict})
        page_ctx = {
            "status": str(status), "verdict": res.verdict, "reason": res.matched_rule_name or "No matching whitelist rule (default deny)",
            "server_hostname": res.server_hostname or peer, "server_ip": peer, "method": method, "url": url,
            "trace_id": trace, "block_token": token, "public_url": public, "dashboard_url": dashboard,
            "suggested": f"{res.suggested_host}{res.suggested_path}", "suggested_host": res.suggested_host,
        }
        headers = {"X-Aegis-Verdict": res.verdict, "X-Aegis-Trace-ID": trace, "Cache-Control": "no-store"}
        cli = is_cli_client(flow.request.headers.get("User-Agent", ""), flow.request.headers.get("Accept", ""))
        branded = None
        if policy is not None:
            try:
                branded = render_branded(policy.block_pages, page_ctx, res.group_ids, flow.request.headers.get("Accept-Language", ""), cli)
            except Exception:  # noqa: BLE001 - a broken template must never turn a block into an error
                log.exception("branded block page failed; using the built-in page")
        if cli:
            body = (branded[0] if branded else render_cli(page_ctx, res.group_ids)).encode("utf-8", "replace")
            headers["Content-Type"] = "text/plain; charset=utf-8"
        else:
            page, csp = branded if branded else render_html(page_ctx, res.group_ids)
            body = page.encode("utf-8", "replace")
            headers.update({"Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": csp,
                            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})
        flow.response = http.Response.make(status, body, headers)
        flow.metadata["aegis_recorded"] = flow.metadata["aegis_local"] = True
        self.cp.record_flow(self._flow_record(flow, res, peer, auth, status, res.verdict, trace_id=trace, **extra))

    # ------------------------------------------------------------------ CONNECT
    @guarded
    def http_connect(self, flow: http.HTTPFlow) -> None:
        auth = self._identity(flow)
        for h in INTERNAL_HEADERS:
            flow.request.headers.pop(h, None)
        host = normalize_host(flow.request.host)
        if host in self.cfg.magic_hosts:
            return
        policy = self._policy()
        if policy is None:
            self._unavailable(flow)
            return
        peer = _peer(flow.client_conn)
        res = policy.evaluate(peer, auth, "CONNECT", host, flow.request.port, "/", "", self.cp.threat, self.grants)
        if not valid_host(host):
            res.block(VERDICT_POLICY, "malformed_host", f"Security Guard: malformed destination host '{printable(host, 255)}'")
        flow.metadata["aegis_connect"] = res.verdict
        # Hard blocks are enforced before any TLS handshake; ordinary default-deny is decided per
        # request inside the tunnel so the user gets an explanatory block page.
        if res.verdict in (VERDICT_THREAT, VERDICT_POLICY):
            self._block(flow, res, peer, auth)

    # ------------------------------------------------------------------ TLS
    @guarded
    async def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        policy = self._policy()
        client = data.context.client
        sni = normalize_host(client.sni or "")
        if policy is None or not sni or not valid_host(sni):
            return
        target = data.context.server.address
        if not target:
            return
        port = int(target[1])
        regular = self._regular_like(client)
        if regular:
            if normalize_host(str(target[0])) != sni:
                return  # SNI spoofing / domain fronting attempt: never pass through, intercept instead
        else:
            # The connection goes to the original destination address: the SNI decides nothing unless it
            # resolves to that address (otherwise intercept and evaluate every request).
            problem = await check_binding(sni, str(target[0]), port, self.dns,
                                          bool(policy.policy_value("block_private_destinations", True)), policy.internal_suffixes)
            if problem:
                log.info("no TLS passthrough for SNI %s to %s:%s: %s", printable(sni, 255), target[0], port, problem[0])
                return
        peer = _peer(client)
        auth = self.conn_auth.get(client.id, "")
        res = policy.evaluate(peer, auth, "CONNECT", sni, port, "/", "", self.cp.threat, self.grants)
        if res.verdict == VERDICT_TLS_BYPASS:
            if not regular:
                self._bind(client, str(target[0]), port, sni)
            data.ignore_connection = True
            self.cp.record_flow({
                "id": _trace_id(), "server_ip": peer, "server_id": res.server_id, "server_hostname": res.server_hostname,
                "group_ids": res.group_ids, "proxy_auth_user": printable(auth.split(":", 1)[0], 255) if auth else "", "method": "CONNECT",
                "scheme": "https", "host": sni, "port": port, "path": "/", "full_url": f"https://{sni}/",
                "user_agent": "TLS-SNI-Passthrough", "verdict": VERDICT_TLS_BYPASS, "matched_rule_id": res.matched_rule_id,
                "matched_rule_name": res.matched_rule_name, "status_code": 200, "tls_intercepted": False,
            })

    # ------------------------------------------------------------------ requests
    def _serve_magic(self, flow: http.HTTPFlow) -> None:
        path = flow.request.path.split("?", 1)[0].lower()
        public, _ = self._urls(self._policy())
        flow.metadata["aegis_local"] = True
        routes = {
            "/ca.crt": (self.cp.ca_pem, "application/x-x509-ca-cert"), "/ca.pem": (self.cp.ca_pem, "application/x-x509-ca-cert"),
            "/ca.der": (self.cp.ca_der, "application/pkix-cert"), "/install-linux.sh": (self.cp.install_sh, "text/x-shellscript; charset=utf-8"),
            "/install-windows.ps1": (self.cp.install_ps1, "text/plain; charset=utf-8"),
        }
        if path in routes:
            body, ctype = routes[path]
            if not body:
                flow.response = http.Response.make(503, b"CA not cached yet, retry in a few seconds\n", {"Content-Type": "text/plain"})
            else:
                flow.response = http.Response.make(200, body, {"Content-Type": ctype, "Cache-Control": "no-store"})
            return
        host = printable(flow.request.host, 255)
        page = (f"AegisProxy Root CA portal\n\n  CA (PEM):   http://{host}/ca.crt\n  CA (DER):   http://{host}/ca.der\n"
                f"  Linux:      curl -fsSL http://{host}/install-linux.sh | sudo bash\n"
                f"  Windows:    iwr -UseBasicParsing http://{host}/install-windows.ps1 | iex\n\n"
                f"Control-plane: {public}\n")
        flow.response = http.Response.make(200, page.encode("utf-8", "replace"), {"Content-Type": "text/plain; charset=utf-8"})

    async def _check_destination(self, flow: http.HTTPFlow, policy: Policy, res: EvalResult, host: str, regular: bool) -> None:
        """The destination that is contacted must be the one policy was evaluated for."""
        client = flow.client_conn
        if client is not None and client.id in self._tainted:
            res.block(VERDICT_POLICY, "internal_error", "Security Guard: inspection of this TLS connection failed (fail-closed)")
            return
        header_host = normalize_host(flow.request.host_header or "")
        sni = normalize_host(client.sni or "") if client else ""
        # HTTP/2 and 3 name the destination in :authority (host_header); a Host header next to it is forwarded too
        # (and becomes the Host of an HTTP/1.1 upstream request), so both must name the same destination.
        h2_host = flow.request.headers.get("Host") if (flow.request.is_http2 or flow.request.is_http3) and flow.request.authority else None
        h2_host = normalize_host(h2_host) if h2_host is not None else None
        for value in (host, header_host, sni, h2_host or ""):
            if not valid_host(value):
                res.block(VERDICT_POLICY, "malformed_host", f"Security Guard: malformed destination host '{printable(value, 255)}'")
                return
        if h2_host is not None and h2_host != header_host:
            res.block(VERDICT_POLICY, "host_mismatch", f"Security Guard: Host header '{h2_host}' does not match :authority '{header_host}' (domain fronting)")
        elif regular and header_host and header_host != host:
            # The upstream connection goes to request.host; Host header and SNI must agree with it,
            # otherwise policy would be evaluated for a different destination than the one contacted.
            res.block(VERDICT_POLICY, "host_mismatch", f"Security Guard: Host header '{header_host}' does not match destination '{host}' (domain fronting)")
        elif flow.request.scheme == "https" and sni and sni != host:
            res.block(VERDICT_POLICY, "sni_mismatch", f"Security Guard: TLS SNI '{sni}' does not match destination '{host}' (domain fronting)")
        elif not regular and res.allowed:
            # Transparent/SOCKS/reverse: the connection already goes to request.host (the original destination);
            # the evaluated Host/SNI is only trusted when it resolves to that address.
            problem = await check_binding(host, flow.request.host, flow.request.port, self.dns,
                                          bool(policy.policy_value("block_private_destinations", True)), policy.internal_suffixes)
            if problem:
                res.block(VERDICT_POLICY, *problem)
            else:
                self._bind(client, flow.request.host, flow.request.port, host)

    def _prepare_inspection(self, flow: http.HTTPFlow, res: EvalResult) -> None:
        """Content inspection is active: only ask for codings the worker can decode, and for whole entities."""
        req = flow.request
        accept = req.headers.get("Accept-Encoding")
        if accept is not None:
            rewritten = filter_accept_encoding(accept)
            if rewritten != accept:
                req.headers["Accept-Encoding"] = rewritten
        if "Range" in req.headers or "If-Range" in req.headers:
            # Ranges would be scanned piece by piece (a file split across requests is never seen whole).
            req.headers.pop("Range", None)
            req.headers.pop("If-Range", None)
            res.security_flags.append("RANGE_STRIPPED")

    @guarded
    async def requestheaders(self, flow: http.HTTPFlow) -> None:
        if flow.request.method == "CONNECT":
            return
        if flow.response:
            flow.metadata["aegis_local"] = True  # answered inside the proxy, never sent upstream
            return
        auth = self._identity(flow)
        for h in INTERNAL_HEADERS:
            flow.request.headers.pop(h, None)
        regular = self._regular_like(flow.client_conn)
        host = normalize_host(flow.request.host if regular else flow.request.pretty_host)
        if host in self.cfg.magic_hosts and flow.request.method in ("GET", "HEAD"):
            self._serve_magic(flow)
            return
        policy = self._policy()
        if policy is None:
            if not self._unavailable(flow):
                flow.metadata["aegis_unenforced"] = True  # AEGIS_FAIL_MODE=open before the first policy sync
            return
        peer = _peer(flow.client_conn)
        res = policy.evaluate(peer, auth, flow.request.method, host, flow.request.port, flow.request.path,
                              flow.request.pretty_url, self.cp.threat, self.grants)
        await self._check_destination(flow, policy, res, host, regular)

        max_upload = int(policy.policy_value("max_upload_bytes", 0) or 0)
        clen = flow.request.headers.get("Content-Length", "")
        if res.allowed and max_upload and clen.isdigit() and int(clen) > max_upload:
            res.block(VERDICT_POLICY, "upload_too_large", f"Security Guard: upload of {int(clen)} bytes exceeds the {max_upload}-byte limit")
            self._block(flow, res, peer, auth, status=413)
            return
        if not res.allowed:
            self._block(flow, res, peer, auth)
            return
        inspect_on = self._inspection_enabled(policy, res.group_ids)
        if inspect_on:
            self._prepare_inspection(flow, res)
        meta = flow.metadata["aegis"] = {"res": res, "peer": peer, "auth": auth, "started": time.time(), "inspect": inspect_on}
        self._plan_upload(flow, policy, res, meta)

    def _plan_upload(self, flow: http.HTTPFlow, policy: Policy, res: EvalResult, meta: Dict[str, Any]) -> None:
        """Request bodies are buffered only when DLP, ICAP REQMOD or the max_upload_bytes check of a body of unknown
        length needs them, within a per-flow cap and the worker budget; everything else is streamed."""
        req = flow.request
        clen_raw = req.headers.get("Content-Length", "")
        clen = int(clen_raw) if clen_raw.isdigit() else None
        if clen == 0:
            return
        dlp_on = policy.policy_value("dlp_mode", "monitor") != "off"
        reqmod = bool(policy.policy_value("icap_reqmod_url", ""))
        max_upload = int(policy.policy_value("max_upload_bytes", 0) or 0)
        enforce_size = bool(max_upload) and clen is None  # a known Content-Length was checked above
        if not (dlp_on or reqmod or enforce_size):
            req.stream = True
            return
        cap = STREAM_WITHOUT_INSPECTION
        if dlp_on:
            cap = max(cap, int(policy.policy_value("dlp_max_scan_bytes", 1 << 20)))
        if reqmod:
            cap = max(cap, int(policy.policy_value("icap_max_bytes", 25 << 20) or (25 << 20)))
        if enforce_size:
            cap = max(cap, max_upload)
        strict = (dlp_on or reqmod) and policy.policy_value("dlp_oversize_action", "allow") == "block"

        def exceeded(reason: str, size: int) -> str:
            self.metrics.inc("aegis_dp_buffer_limited_total", (("direction", "request"), ("reason", reason)))
            peer, auth = meta["peer"], meta["auth"]
            if max_upload and size > max_upload:
                res.block(VERDICT_POLICY, "upload_too_large", f"Security Guard: upload exceeds the {max_upload}-byte limit")
                self._block(flow, res, peer, auth, status=413)
                return BLOCK
            if reason == "busy" and (strict or enforce_size):
                res.block(VERDICT_POLICY, "inspection_busy", "Security Guard: the upload inspection capacity of this worker is exhausted; retry shortly")
                self._block(flow, res, peer, auth, status=503)
                return BLOCK
            if strict:
                res.block(VERDICT_POLICY, "dlp_oversize", f"Data Loss Prevention: upload exceeds the {cap}-byte inspection limit")
                self._block(flow, res, peer, auth, status=413)
                return BLOCK
            if dlp_on and self._query_dlp_blocked(flow, policy, res, meta):  # the URL leaves with the streamed request
                return BLOCK
            if dlp_on:
                res.security_flags.append(f"DLP_UNSCANNED:{reason}")
            if reqmod:
                res.security_flags.append(f"ICAP_UNSCANNED:{reason}")
            req.stream = True
            return STREAM

        guard = buffering.attach(flow, "request", BodyGuard(self.budget, cap, exceeded))
        if clen is not None:
            reason = guard.admit(clen)
            if reason:
                guard.exceed(reason, clen)

    def _query_dlp_blocked(self, flow: http.HTTPFlow, policy: Policy, res: EvalResult, meta: Dict[str, Any]) -> bool:
        """DLP of the query string alone, for requests whose body is streamed (never reaches the request hook's scan)."""
        query = urllib.parse.unquote_to_bytes(flow.request.path.split("?", 1)[1]) if "?" in flow.request.path else b""
        findings = scan_dlp([query], policy.policy_value("dlp_detectors", [])) if query else []
        if not findings:
            return False
        meta["dlp"] = findings
        if policy.policy_value("dlp_mode", "monitor") == "block":
            res.block(VERDICT_DLP, "dlp", "Data Loss Prevention: credentials/secrets detected in outbound request (" + ", ".join(findings) + ")")
            self._block(flow, res, meta["peer"], meta["auth"], dlp_findings=findings)
            return True
        res.security_flags.extend(f"DLP:{f}" for f in findings)
        return False

    def _upload_oversize_blocked(self, flow: http.HTTPFlow, policy: Policy, res: EvalResult, meta: Dict[str, Any], what: str) -> bool:
        if policy.policy_value("dlp_oversize_action", "allow") != "block":
            return False
        res.block(VERDICT_POLICY, "dlp_oversize", f"Data Loss Prevention: upload exceeds the {what} scan limit")
        self._block(flow, res, meta["peer"], meta["auth"], status=413)
        return True

    @guarded
    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.response or flow.metadata.get("aegis_unenforced"):
            return
        meta = flow.metadata.get("aegis")
        policy = self._policy()
        if not meta or policy is None:
            self._deny(flow, "request", 403, "unevaluated", "Security Guard: the request was not evaluated (fail-closed)")
            return
        res: EvalResult = meta["res"]
        if flow.request.stream:
            return  # streamed upload: decided (URL scanned, flags set) in requestheaders or at the buffer limit
        body = flow.request.raw_content or b""
        max_upload = int(policy.policy_value("max_upload_bytes", 0) or 0)
        if max_upload and len(body) > max_upload:
            res.block(VERDICT_POLICY, "upload_too_large", f"Security Guard: upload of {len(body)} bytes exceeds the {max_upload}-byte limit")
            self._block(flow, res, meta["peer"], meta["auth"], status=413)
            return
        mode = policy.policy_value("dlp_mode", "monitor")
        reqmod_url = policy.policy_value("icap_reqmod_url", "")
        if mode == "off" and not reqmod_url:
            return
        limit = int(policy.policy_value("dlp_max_scan_bytes", 1 << 20))
        icap_limit = int(policy.policy_value("icap_max_bytes", 25 << 20) or (25 << 20))
        codings = parse_codings(flow.request.headers.get("Content-Encoding")) + transfer_codings(flow.request.headers.get("Transfer-Encoding"))
        try:
            content, truncated = decode_body(body, codings, max(limit, icap_limit if reqmod_url else 0))
        except UndecodableContent as exc:
            # Never forward an upload the scanners could not read: block when any inspection enforces.
            if mode == "block" or (reqmod_url and policy.policy_value("icap_mode", "block") == "block"):
                res.block(VERDICT_POLICY, "undecodable_content", f"Data Loss Prevention: upload with undecodable content coding blocked ({exc})")
                self._block(flow, res, meta["peer"], meta["auth"])
                return
            res.security_flags.append("DLP_UNSCANNED:undecodable")
            return
        findings: List[str] = []
        if mode != "off":  # built-in detectors; ICAP REQMOD (external DLP) runs independently
            detectors = policy.policy_value("dlp_detectors", [])
            query = urllib.parse.unquote_to_bytes(flow.request.path.split("?", 1)[1]) if "?" in flow.request.path else b""
            findings = scan_dlp([query, content[:limit]], detectors)  # the whole decoded body up to the scan limit
        if findings:
            meta["dlp"] = findings
            if mode == "block":
                res.block(VERDICT_DLP, "dlp", "Data Loss Prevention: credentials/secrets detected in outbound request (" + ", ".join(findings) + ")")
                self._block(flow, res, meta["peer"], meta["auth"], dlp_findings=findings)
                return
            res.security_flags.extend(f"DLP:{f}" for f in findings)
        if mode != "off" and (truncated or len(content) > limit):
            # Bytes beyond the scan limit were not inspected: never silently.
            res.security_flags.append("DLP_UNSCANNED:oversize")
            if self._upload_oversize_blocked(flow, policy, res, meta, f"{limit}-byte DLP"):
                return
        if reqmod_url and codings and not buffering.hold(flow, "request", len(content)):
            # The decoded copy would be kept during the ICAP call: it must fit the worker budget.
            self.metrics.inc("aegis_dp_buffer_limited_total", (("direction", "request"), ("reason", "busy")))
            res.security_flags.append("ICAP_UNSCANNED:busy")
            if policy.policy_value("dlp_oversize_action", "allow") == "block":
                res.block(VERDICT_POLICY, "inspection_busy", "Security Guard: the upload inspection capacity of this worker is exhausted; retry shortly")
                self._block(flow, res, meta["peer"], meta["auth"], status=503)
            return
        await self._icap_reqmod(flow, policy, res, meta, content, truncated)

    async def _icap_reqmod(self, flow: http.HTTPFlow, policy: Policy, res: EvalResult, meta: Dict[str, Any], content: bytes,
                           truncated: bool = False) -> None:
        """Hands uploads to an external DLP/AV engine via ICAP REQMOD."""
        url = policy.policy_value("icap_reqmod_url", "")
        if not url or not content or flow.request.method in ("GET", "HEAD", "OPTIONS", "CONNECT"):
            return
        icap_max = int(policy.policy_value("icap_max_bytes", 25 << 20) or (25 << 20))
        if truncated or len(content) > icap_max:
            res.security_flags.append("ICAP_UNSCANNED:oversize")
            self._upload_oversize_blocked(flow, policy, res, meta, f"{icap_max}-byte ICAP")
            return
        started = time.time()
        result = await self._icap_call(url, policy, "reqmod", flow.request.method, printable(flow.request.pretty_url, 8192),
                                       list(flow.request.headers.items(multi=True)), content)
        self.metrics.observe("aegis_dp_icap_seconds", time.time() - started)
        self.metrics.inc("aegis_dp_icap_scans_total", (("mode", "reqmod"), ("result", result.status)))
        block_mode = policy.policy_value("icap_mode", "block") == "block"
        if result.status == "infected":
            meta["dlp"] = (meta.get("dlp") or []) + [f"icap:{result.threat[:60]}"]
            if block_mode:
                res.block(VERDICT_DLP, "icap_dlp", f"Data Loss Prevention (ICAP): {result.threat}")
                self._block(flow, res, meta["peer"], meta["auth"], dlp_findings=meta["dlp"])
                return
            res.security_flags.append(f"DLP:icap:{result.threat[:60]}")
        elif result.status == "modified":
            if policy.policy_value("icap_allow_modified", True) and result.body is not None:
                _replace_body(flow.request, result.body)  # the sanitized upload is sent, never the original
                res.security_flags.append("ICAP_SANITIZED")
            elif block_mode:
                res.block(VERDICT_DLP, "icap_dlp", "Data Loss Prevention (ICAP): the upload would have to be modified")
                self._block(flow, res, meta["peer"], meta["auth"], dlp_findings=meta.get("dlp") or [])
                return
            else:
                res.security_flags.append("DLP:icap:modification_suppressed")
        elif result.status == "error":
            res.security_flags.append(f"AV_ERROR:icap-reqmod:{result.detail[:60]}")
            if policy.policy_value("icap_fail_mode", "open") == "closed":
                res.block(VERDICT_POLICY, "icap_error", f"Upload inspection unavailable ({result.detail}); request blocked (fail-closed)")
                self._block(flow, res, meta["peer"], meta["auth"], status=503)

    # ------------------------------------------------------------------ upstream connect
    @guarded
    async def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        policy = self._policy()
        if policy is None or not data.server.address:
            return
        host, port = str(data.server.address[0]), int(data.server.address[1])
        literal = parse_ip(host)
        if literal is not None:
            addrs = [literal]
        else:
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except (OSError, UnicodeError) as exc:
                data.server.error = f"DNS resolution failed for {printable(host, 255)}: {exc}"
                return
            addrs = []
            for info in infos:
                a = parse_ip(info[4][0])
                if a is not None and a not in addrs:
                    addrs.append(a)
            self.dns.remember(host, addrs)
        if not addrs:
            data.server.error = f"no usable address for {printable(host, 255)}"
            return
        if literal is not None and not self._regular_like(data.client):
            # Transparent/SOCKS/reverse: the address came from the client. It may be internal only when the
            # request/SNI bound to it named an internal destination (which policy then required a rule for).
            name = self._bound_name(data.client, literal, port)
            internal_name = bool(name) and is_internal_host(name, policy.internal_suffixes)
        else:
            internal_name = is_internal_host(host, policy.internal_suffixes)
        block_private = bool(policy.policy_value("block_private_destinations", True))
        ti_mode = policy.policy_value("threat_intel_mode", "block")
        for a in addrs:
            reason = ""
            if is_forbidden_addr(a):
                reason = f"{host} resolves to forbidden address {a} (loopback/link-local/metadata)"
            elif block_private and is_internal_addr(a) and not internal_name:
                reason = f"{host} resolves to internal address {a} (DNS rebinding protection)"
            elif ti_mode == "block":
                m = self.cp.threat.match_ip(a)
                if m:
                    reason = f"{host} resolves to {a} listed by {m.source_name} ({m.category})"
            if reason:
                reason = printable(reason, 512)
                log.warning("blocked upstream connection: %s (client %s)", reason, _peer(data.client))
                data.server.error = "AegisProxy: " + reason
                self.cp.record_flow({
                    "id": _trace_id(), "server_ip": _peer(data.client), "method": "CONNECT", "scheme": "tcp",
                    "host": printable(normalize_host(host), 255), "port": port, "path": "/", "full_url": printable(f"{host}:{port}", 512),
                    "verdict": VERDICT_THREAT if "listed by" in reason else VERDICT_POLICY,
                    "block_reason": "threat_ip" if "listed by" in reason else "dns_rebinding", "matched_rule_name": reason,
                    "resolved_ip": str(a), "status_code": 502,
                })
                return
        if literal is None:
            # Pin the vetted address so a second DNS lookup cannot be rebound (SNI/Host stay unchanged).
            data.server.address = (str(addrs[0]), port)

    # ------------------------------------------------------------------ responses
    def _inspection_enabled(self, policy: Policy, groups: List[str]) -> bool:
        yara_on = policy.policy_value("yara_mode", "off") != "off" and bool(policy.yara_rule_sets)
        return bool((policy.policy_value("av_enabled", False) and self.clamd) or self._blocked_types(policy, groups)
                    or (self.cp.threat.hashes and policy.policy_value("threat_intel_mode", "block") != "off")
                    or yara_on or policy.policy_value("icap_respmod_url", ""))

    @staticmethod
    def _blocked_types(policy: Policy, groups: List[str]) -> set:
        types = set(policy.policy_value("blocked_file_types", []) or [])
        per_group = policy.policy_value("group_blocked_file_types", {}) or {}
        for g in groups:
            types.update(per_group.get(g, []) or [])
        return types

    @staticmethod
    def _has_body(flow: http.HTTPFlow) -> bool:
        status = flow.response.status_code if flow.response else 0
        return flow.request.method != "HEAD" and status >= 200 and status not in (204, 304)

    @staticmethod
    def _response_codings(resp: http.Response) -> List[str]:
        return parse_codings(resp.headers.get("Content-Encoding")) + transfer_codings(resp.headers.get("Transfer-Encoding"))

    @guarded
    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("aegis_local") or flow.metadata.get("aegis_unenforced"):
            return
        meta = flow.metadata.get("aegis")
        policy = self._policy()
        if not meta or policy is None:
            self._deny(flow, "responseheaders", 403, "unevaluated", "Security Guard: the request was not evaluated (fail-closed)")
            return
        if not flow.response:
            return
        res: EvalResult = meta["res"]
        inspect_on = self._inspection_enabled(policy, res.group_ids)
        meta["inspect"] = inspect_on
        resp = flow.response
        if inspect_on and self._has_body(flow):
            if resp.status_code == 206:
                # Range headers were removed; a partial entity can never be scanned as a whole.
                self._block_streamed(flow, meta, "partial_content", "Content inspection: partial content (HTTP 206) cannot be scanned",
                                     "AegisProxy blocked this download: partial content (byte ranges) cannot be scanned.\n")
                return
            codings = self._response_codings(resp)
            if not decodable(codings):
                self._block_streamed(flow, meta, "undecodable_content",
                                     f"Content inspection: unsupported content coding '{printable(', '.join(codings), 120)}'",
                                     "AegisProxy blocked this download: its content coding cannot be inspected.\n")
                return
        ctype = resp.headers.get("Content-Type", "").lower()
        if "text/event-stream" in ctype and not inspect_on:
            resp.stream = True  # event streams are only relayed unbuffered when no inspection applies
            meta["unscanned"] = "stream"
            return
        max_scan = int(policy.policy_value("av_max_scan_bytes", 25 << 20))
        clen_raw = resp.headers.get("Content-Length", "")
        clen = int(clen_raw) if clen_raw.isdigit() else None
        if clen is not None and clen > max_scan and inspect_on:
            if policy.policy_value("av_oversize_action", "allow") == "block":
                self._block_streamed(flow, meta, "av_oversize", f"Antivirus: download of {clen} bytes exceeds the {max_scan}-byte scan limit",
                                     f"AegisProxy blocked this download: {clen} bytes exceed the antivirus scan limit ({max_scan} bytes).\n"
                                     "Contact InfoSec if this file is required.\n")
            else:
                resp.stream = True
                meta["unscanned"] = "oversize"
                res.security_flags.append("AV_UNSCANNED:oversize")
        elif not self._has_body(flow):
            return
        elif not inspect_on:
            # Nothing inspects the body: only small bodies of known size are buffered (within the budget); bodies of
            # unknown length are relayed as they arrive, never accumulated.
            if clen is None or clen > STREAM_WITHOUT_INSPECTION:
                self._relay_unbuffered(flow, meta)
            else:
                guard = buffering.attach(flow, "response", BodyGuard(self.budget, STREAM_WITHOUT_INSPECTION,
                                                                     lambda _reason, _size: self._relay_unbuffered(flow, meta)))
                if guard.admit(clen):
                    guard.exceed("busy", clen)
        else:
            # Inspected: buffered up to the scan limit within the worker budget, a body of unknown length chunk by chunk.
            guard = buffering.attach(flow, "response", BodyGuard(self.budget, max_scan,
                                                                 lambda reason, _size: self._download_exceeded(flow, policy, meta, max_scan, reason)))
            if clen is not None:
                reason = guard.admit(clen)
                if reason:
                    guard.exceed(reason, clen)

    def _relay_unbuffered(self, flow: http.HTTPFlow, meta: Dict[str, Any]) -> str:
        flow.response.stream = True
        meta["unscanned"] = "not_required"
        return STREAM

    def _download_exceeded(self, flow: http.HTTPFlow, policy: Policy, meta: Dict[str, Any], cap: int, reason: str) -> str:
        """A download outgrew the scan limit (no Content-Length) or the worker budget: av_oversize_action decides."""
        self.metrics.inc("aegis_dp_buffer_limited_total", (("direction", "response"), ("reason", reason)))
        if policy.policy_value("av_oversize_action", "allow") == "block":
            if reason == "oversize":
                self._block_streamed(flow, meta, "av_oversize", f"Antivirus: download exceeds the {cap}-byte scan limit",
                                     f"AegisProxy blocked this download: it exceeds the antivirus scan limit ({cap} bytes).\n"
                                     "Contact InfoSec if this file is required.\n")
            else:
                self._block_streamed(flow, meta, "inspection_busy", "Content inspection: the scan capacity of this worker is exhausted",
                                     "AegisProxy could not inspect this download: scan capacity exhausted. Retry shortly.\n", status=503)
            return BLOCK
        meta["res"].security_flags.append(f"AV_UNSCANNED:{reason}")
        meta["unscanned"] = reason
        flow.response.stream = True
        return STREAM

    def _replace_streamed(self, flow: http.HTTPFlow, status: int, msg: bytes, verdict: str) -> None:
        """Turns a response whose headers already arrived into a block: the upstream body is discarded and
        the explanation is sent instead (streamed, so nothing is buffered)."""
        resp = flow.response
        resp.status_code = status
        resp.reason = "Forbidden" if status == 403 else "Service Unavailable"
        for h in _BLOCKED_RESPONSE_HEADERS:
            resp.headers.pop(h, None)
        resp.headers["Content-Type"] = "text/plain; charset=utf-8"
        resp.headers["Content-Length"] = str(len(msg))
        resp.headers["X-Aegis-Verdict"] = verdict
        resp.headers["Cache-Control"] = "no-store"
        sent = {"done": False}

        def swallow(chunk: bytes) -> bytes:
            # Upstream data is discarded; the explanation is emitted once.
            if not sent["done"]:
                sent["done"] = True
                return msg
            return b""

        resp.stream = swallow
        flow.metadata["aegis_pending"] = (sent, msg)  # bodyless upstream responses: sent by the response hook
        flow.metadata["aegis_local"] = True

    def _block_streamed(self, flow: http.HTTPFlow, meta: Dict[str, Any], reason: str, name: str, msg: str, status: int = 403) -> None:
        res: EvalResult = meta["res"]
        res.block(VERDICT_POLICY, reason, name)
        self._replace_streamed(flow, status, msg.encode(), VERDICT_POLICY)
        flow.metadata["aegis_recorded"] = True
        self.cp.record_flow(self._flow_record(flow, res, meta["peer"], meta["auth"], status, VERDICT_POLICY))

    @guarded
    async def response(self, flow: http.HTTPFlow) -> None:
        try:
            await self._respond(flow)
        finally:
            buffering.release(flow)

    async def _respond(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("aegis_local") or flow.metadata.get("aegis_recorded"):
            pending = flow.metadata.pop("aegis_pending", None)
            if pending and not pending[0]["done"] and flow.response is not None:
                pending[0]["done"] = True
                flow.response.raw_content = pending[1]
            return
        if flow.metadata.get("aegis_unenforced"):
            return
        meta = flow.metadata.get("aegis")
        policy = self._policy()
        if not meta or not flow.response or policy is None:
            self._deny(flow, "response", 403, "unevaluated", "Security Guard: the request was not evaluated (fail-closed)")
            return
        res: EvalResult = meta["res"]
        peer, auth = meta["peer"], meta["auth"]
        extra: Dict[str, Any] = {"latency_ms": max(1, int((time.time() - meta["started"]) * 1000))}
        if meta.get("dlp"):
            extra["dlp_findings"] = meta["dlp"]
        ctype = flow.response.headers.get("Content-Type", "")
        extra["content_type"] = printable(ctype, 128)

        if not flow.response.stream:
            blocked = await self._inspect_response(flow, policy, res, meta, extra)
            if blocked:
                verdict, status = blocked
                self._block(flow, res, peer, auth, status=status, **extra)
                return
        else:
            extra["av_result"] = "skipped"

        status = flow.response.status_code
        extra["bytes_sent"] = len(flow.request.raw_content or b"")
        extra["bytes_received"] = len(flow.response.raw_content or b"") if not flow.response.stream else int(flow.response.headers.get("Content-Length", "0") or 0)
        if status in (301, 302, 303, 307, 308):
            loc = flow.response.headers.get("Location", "")
            if loc:
                try:
                    extra["redirect_location"] = printable(urllib.parse.urljoin(printable(flow.request.pretty_url, 4096), printable(loc, 4096)), 4096)
                except ValueError:  # malformed Location: recorded as sent, no grant
                    extra["redirect_location"] = printable(loc, 4096)
                if res.follow_redirects or res.verdict == VERDICT_LEARNING:
                    self.grants.register(peer, loc, flow.request.pretty_url, res.matched_rule_id, res.matched_rule_name,
                                         policy.internal_suffixes, res.redirect_hosts)
        self.cp.record_flow(self._flow_record(flow, res, peer, auth, status, res.verdict, **extra))

    async def _inspect_response(self, flow: http.HTTPFlow, policy: Policy, res: EvalResult, meta: Dict[str, Any], extra: Dict[str, Any]):
        """Decodes the buffered body exactly as a client will (bounded) and runs the inspection pipeline.
        Returns (verdict, status) when the download must be blocked."""
        resp = flow.response
        raw = resp.raw_content or b""
        if not raw or not self._has_body(flow):
            return None
        inspect_on = self._inspection_enabled(policy, res.group_ids)
        if inspect_on and resp.status_code == 206:
            res.block(VERDICT_POLICY, "partial_content", "Content inspection: partial content (HTTP 206) cannot be scanned")
            return VERDICT_POLICY, 403
        codings = self._response_codings(resp)
        max_scan = int(policy.policy_value("av_max_scan_bytes", 25 << 20))
        try:
            body, truncated = decode_body(raw, codings, max_scan)
        except UndecodableContent as exc:
            if inspect_on:  # never deliver bytes the scanners could not read
                res.block(VERDICT_POLICY, "undecodable_content", printable(f"Content inspection: undecodable download ({exc})", 300))
                return VERDICT_POLICY, 403
            return None
        if truncated and inspect_on:
            # Decoded size exceeds the scan limit (decompression bomb or just large): inflating stops at the limit.
            res.security_flags.append("AV_UNSCANNED:oversize")
            if policy.policy_value("av_oversize_action", "allow") == "block":
                res.block(VERDICT_POLICY, "av_oversize", f"Antivirus: decoded download exceeds the {max_scan}-byte scan limit")
                return VERDICT_POLICY, 403
        scanners = True
        if codings and inspect_on and not buffering.hold(flow, "response", len(body)):
            # The decoded copy is kept while the scan engines run, so it must fit the worker budget too. Without room
            # only the synchronous checks (hash IOCs, file type) run.
            self.metrics.inc("aegis_dp_buffer_limited_total", (("direction", "response"), ("reason", "busy")))
            res.security_flags.append("AV_UNSCANNED:busy")
            if policy.policy_value("av_oversize_action", "allow") == "block":
                res.block(VERDICT_POLICY, "inspection_busy", "Content inspection: the scan capacity of this worker is exhausted")
                return VERDICT_POLICY, 503
            scanners = False
        raw_digest = hashlib.sha256(raw).hexdigest() if codings else ""
        return await self._inspect_body(flow, policy, res, body, extra, partial=truncated, raw_digest=raw_digest, scanners=scanners)

    async def _inspect_body(self, flow: http.HTTPFlow, policy: Policy, res: EvalResult, body: bytes, extra: Dict[str, Any],
                            partial: bool = False, raw_digest: str = "", scanners: bool = True):
        """Returns (verdict, status) when the download must be blocked. ``partial``: body is only the first
        av_max_scan_bytes of a larger decoded entity (hash/ClamAV/ICAP are skipped, file type and YARA run).
        ``scanners=False``: only the synchronous checks run (hash IOCs, file type)."""
        if not body:
            return None
        digest = "" if partial else hashlib.sha256(body).hexdigest()
        if digest:
            extra["content_sha256"] = digest
        ti_mode = policy.policy_value("threat_intel_mode", "block")
        if ti_mode != "off":
            for d in dict.fromkeys(x for x in (digest, raw_digest) if x):  # decoded entity and transferred bytes
                m = self.cp.threat.match_hash(d)
                if m:
                    res.threat_category, res.threat_source, res.threat_indicator = m.category, m.source_name, d
                    if ti_mode == "block":
                        res.block(VERDICT_MALWARE, "malware_hash", f"Known-malicious file hash ({m.source_name})")
                        return VERDICT_MALWARE, 403
                    res.security_flags.append(f"THREAT_MONITOR:{m.category}")
                    break

        ftype = detect_file_type(body, flow.request.pretty_url, flow.response.headers.get("Content-Type", ""))
        if ftype:
            extra["file_type"] = ftype
            if ftype in self._blocked_types(policy, res.group_ids):
                res.block(VERDICT_FILETYPE, "file_type", f"Download control: file type '{ftype}' is not permitted for this server group")
                return VERDICT_FILETYPE, 403
        if not scanners:
            extra["av_result"] = "skipped"
            return None

        blocked = await self._yara_check(policy, res, body, digest, extra)
        if blocked:
            return blocked
        blocked = await self._clamav_check(flow, policy, res, body, digest, extra, partial)
        if blocked:
            return blocked
        return await self._icap_respmod(flow, policy, res, body, digest, extra, partial)

    async def _yara_check(self, policy: Policy, res: EvalResult, body: bytes, digest: str, extra: Dict[str, Any]):
        mode = policy.policy_value("yara_mode", "off")
        if mode == "off" or not policy.yara_rule_sets:
            return None
        self._yara_sync(policy)
        limit = int(policy.policy_value("yara_max_bytes", 25 << 20) or (25 << 20))
        started = time.time()
        hits = await asyncio.get_running_loop().run_in_executor(None, self.yara.scan, body[:limit])
        self.metrics.observe("aegis_dp_yara_seconds", time.time() - started)
        if not hits:
            return None
        errors = [h for h in hits if h.startswith("__error__")]
        rules = [h for h in hits if not h.startswith("__error__")]
        if errors and not rules:
            res.security_flags.append(f"AV_ERROR:yara:{errors[0][10:70]}")
            return None
        self.metrics.inc("aegis_dp_yara_matches_total")
        sig = "YARA: " + ", ".join(rules[:5])
        if self.cp.threat.hash_excepted(digest):
            res.security_flags.append(f"AV_SUPPRESSED:{sig[:80]}")
            return None
        extra["av_signature"] = sig[:200]
        if mode == "block":
            res.block(VERDICT_MALWARE, "yara", sig[:200])
            res.threat_source, res.threat_category = "YARA", "malware"
            return VERDICT_MALWARE, 403
        res.security_flags.append(f"AV_FOUND:{sig[:80]}")
        return None

    async def _icap_respmod(self, flow: http.HTTPFlow, policy: Policy, res: EvalResult, body: bytes, digest: str, extra: Dict[str, Any],
                            partial: bool = False):
        url = policy.policy_value("icap_respmod_url", "")
        if not url:
            return None
        if partial or len(body) > int(policy.policy_value("icap_max_bytes", 25 << 20) or (25 << 20)):
            res.security_flags.append("ICAP_UNSCANNED:oversize")
            if policy.policy_value("av_oversize_action", "allow") == "block":
                res.block(VERDICT_POLICY, "av_oversize", "Antivirus (ICAP): download exceeds the scan limit")
                return VERDICT_POLICY, 403
            return None
        started = time.time()
        result = await self._icap_call(url, policy, "respmod", flow.request.method, printable(flow.request.pretty_url, 8192),
                                       list(flow.request.headers.items(multi=True)), flow.response.status_code,
                                       list(flow.response.headers.items(multi=True)), body)
        self.metrics.observe("aegis_dp_icap_seconds", time.time() - started)
        self.metrics.inc("aegis_dp_icap_scans_total", (("mode", "respmod"), ("result", result.status)))
        extra.setdefault("av_result", result.status if result.status != "modified" else "sanitized")
        if result.status == "infected":
            sig = "ICAP: " + (result.threat or "blocked")
            extra["av_signature"], extra["av_result"] = sig[:200], "infected"
            if self.cp.threat.hash_excepted(digest):
                res.security_flags.append(f"AV_SUPPRESSED:{sig[:80]}")
                return None
            if policy.policy_value("icap_mode", "block") == "block":
                res.block(VERDICT_MALWARE, "icap", sig[:200])
                res.threat_source, res.threat_category = "ICAP", "malware"
                return VERDICT_MALWARE, 403
            res.security_flags.append(f"AV_FOUND:{sig[:80]}")
        elif result.status == "modified":
            if policy.policy_value("icap_allow_modified", True) and result.body is not None:
                _replace_body(flow.response, result.body)  # content disarm & reconstruction (sanitized file, identity)
                res.security_flags.append("ICAP_SANITIZED")
            elif policy.policy_value("icap_mode", "block") == "block":
                res.block(VERDICT_MALWARE, "icap", "ICAP: content would have to be modified")
                return VERDICT_MALWARE, 403
        elif result.status == "error":
            res.security_flags.append(f"AV_ERROR:icap:{result.detail[:60]}")
            if policy.policy_value("icap_fail_mode", "open") == "closed":
                res.block(VERDICT_POLICY, "icap_error", f"Antivirus (ICAP) unavailable ({result.detail}); download blocked (fail-closed)")
                return VERDICT_POLICY, 503
        return None

    async def _clamav_check(self, flow: http.HTTPFlow, policy: Policy, res: EvalResult, body: bytes, digest: str, extra: Dict[str, Any],
                            partial: bool = False):
        if not (policy.policy_value("av_enabled", False) and self.clamd):
            return None
        max_scan = int(policy.policy_value("av_max_scan_bytes", 25 << 20))
        if partial or len(body) > max_scan:
            extra["av_result"] = "skipped"
            if policy.policy_value("av_oversize_action", "allow") == "block":
                res.block(VERDICT_POLICY, "av_oversize", f"Antivirus: {len(body)} bytes exceed the {max_scan}-byte scan limit")
                return VERDICT_POLICY, 403
            if "AV_UNSCANNED:oversize" not in res.security_flags:
                res.security_flags.append("AV_UNSCANNED:oversize")
            return None
        started = time.time()
        result = await self.clamd.scan(body)
        self.metrics.observe("aegis_dp_av_scan_seconds", time.time() - started)
        self.metrics.inc("aegis_dp_av_scans_total", (("result", result.status),))
        extra["av_result"] = result.status
        if result.status == "infected":
            extra["av_signature"] = result.signature
            if self.cp.threat.hash_excepted(digest):
                # Known false positive (SHA-256 exception maintained by InfoSec): allow, but keep a trail.
                res.security_flags.append(f"AV_SUPPRESSED:{result.signature}")
                log.warning("antivirus hit %s on %s suppressed by SHA-256 exception %s", result.signature,
                            printable(flow.request.pretty_url, 2048), digest)
                return None
            if policy.policy_value("av_mode", "block") == "block":
                res.block(VERDICT_MALWARE, "malware", f"Antivirus: {result.signature}")
                res.threat_source, res.threat_category = "ClamAV", "malware"
                return VERDICT_MALWARE, 403
            res.security_flags.append(f"AV_FOUND:{result.signature}")
        elif result.status == "error":
            res.security_flags.append(f"AV_ERROR:{result.detail[:80]}")
            if policy.policy_value("av_fail_mode", "open") == "closed":
                res.block(VERDICT_POLICY, "av_error", f"Antivirus scan unavailable ({result.detail}); download blocked (fail-closed)")
                return VERDICT_POLICY, 503
        return None

    # ------------------------------------------------------------------ non-HTTP
    @guarded
    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        # Defence in depth for raw relays created via --tcp-hosts: never forward payload of a rejected flow
        # (mitmproxy 12 keeps relaying TCP flows even after flow.kill()).
        if flow.metadata.get("aegis_rejected") and flow.messages:
            flow.messages[-1].content = b""

    def _kill_raw(self, flow, proto: str) -> None:
        policy = self._policy()
        if policy is not None and not policy.policy_value("block_raw_tcp", True):
            return
        addr = flow.server_conn.address if flow.server_conn and flow.server_conn.address else ("?", 0)
        flow.metadata["aegis_rejected"] = True
        flow.kill()
        self.cp.record_flow({
            "id": _trace_id(), "server_ip": _peer(flow.client_conn), "method": proto.upper(), "scheme": proto,
            "host": printable(normalize_host(str(addr[0])), 255), "port": int(addr[1] or 0),
            "path": "/", "full_url": printable(f"{proto}://{addr[0]}:{addr[1]}", 512),
            "verdict": VERDICT_POLICY, "block_reason": "raw_tcp", "status_code": 0,
            "matched_rule_name": "Security Guard: non-HTTP tunnels are not permitted through the egress proxy",
        })

    @guarded
    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        self._kill_raw(flow, "tcp")

    @guarded
    def udp_start(self, flow: udp.UDPFlow) -> None:
        self._kill_raw(flow, "udp")
