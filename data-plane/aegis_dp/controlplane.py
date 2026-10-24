"""Control-plane client: policy/threat-intel sync, telemetry upload and block tokens.

All network I/O runs in background threads so the mitmproxy event loop is never blocked.

Telemetry delivery: flow records wait in a bounded memory queue (20,000 records) and, with AEGIS_FLOW_SPOOL_DIR, are written to fsync'd spool segments every flush interval (spool.py). A batch is
removed only after the control-plane acknowledged it (2xx, sent after durable storage); 429/503 (backpressure, Retry-After
honoured), 5xx and network errors keep the batch and retry with backoff. Every record that is lost is counted in
aegis_dp_flows_dropped_total{reason} and reported in the heartbeat: overflow (memory queue full), spool_full (spool
size limit), rejected (the control-plane refused the batch as malformed), spool_corrupt (unreadable spool lines).
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import logging
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from . import __version__
from .config import Config
from .policy import Policy
from .redact import normalize_mode, redact_url
from .spool import FlowSpool
from .threatintel import ThreatSnapshot

log = logging.getLogger("aegis.controlplane")

BATCH_SIZE = 500
DROP_REASONS = ("overflow", "spool_full", "rejected", "spool_corrupt")
REDACTED_FIELDS = ("full_url", "redirect_location", "redirect_parent_url")
MAX_RETRY_AFTER = 300.0
MAX_BACKOFF = 30.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sign_block_token(key: str, claims: Dict[str, Any], ttl: int = 24 * 3600) -> str:
    """Identical construction to control-plane/internal/auth/blocktoken.go."""
    claims = dict(claims)
    claims.setdefault("exp", int(time.time()) + ttl)
    payload = json.dumps(claims, separators=(",", ":")).encode()
    body = "v1." + base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    subkey = hmac.new(key.encode(), b"aegis-block-token-v1", hashlib.sha256).digest()
    sig = hmac.new(subkey, body.encode(), hashlib.sha256).digest()
    return body + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


class ControlPlaneClient:
    def __init__(self, cfg: Config, clamav_status: Callable[[], str] = lambda: "",
                 on_flow: Optional[Callable[[Dict[str, Any]], None]] = None,
                 status_headers: Callable[[], Dict[str, str]] = dict,
                 on_policy: Optional[Callable[[], None]] = None) -> None:
        self.cfg = cfg
        self.clamav_status = clamav_status
        self.status_headers = status_headers
        self.on_flow = on_flow
        self.on_policy = on_policy  # called (sync thread) after a new policy bundle or threat-intel snapshot was loaded
        self.policy: Optional[Policy] = None
        self.threat = ThreatSnapshot()
        self.ca_pem: bytes = b""
        self.ca_der: bytes = b""
        self.install_sh: bytes = b""
        self.install_ps1: bytes = b""
        self.last_sync_ok = 0.0
        self._bundle_etag = ""
        self._threat_etag = ""
        self._queue: Deque[Dict[str, Any]] = deque()
        self._inflight: List[Dict[str, Any]] = []  # memory batch being delivered (kept until acknowledged)
        self._qlock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._threat_lock = threading.Lock()
        self._stop = threading.Event()
        self._ssl = ssl.create_default_context(cafile=cfg.control_plane_ca_file or None)
        self._threads = []
        self.dropped: Counter = Counter()
        self.upload_failures = 0
        self.backpressure = 0
        self._retry_at = 0.0
        self._backoff = 0.0
        self.spool: Optional[FlowSpool] = None
        if cfg.flow_spool_dir:
            # A spool that cannot be opened is a configuration error: the operator asked for durable telemetry.
            self.spool = FlowSpool(cfg.flow_spool_dir, cfg.flow_spool_max)

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        for name, target in (("aegis-policy-sync", self._policy_loop), ("aegis-threat-sync", self._threat_loop),
                             ("aegis-telemetry", self._telemetry_loop), ("aegis-ca-cache", self._ca_loop)):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        self._flush(timeout=5.0, force=True)  # whatever cannot be delivered now stays in the spool for the next start

    # -- HTTP ----------------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        h = {
            "X-Aegis-DataPlane-Key": self.cfg.dataplane_key,
            "X-Aegis-DataPlane-ID": self.cfg.worker_id,
            "X-Aegis-DataPlane-Version": __version__,
            "X-Aegis-ClamAV": self.clamav_status(),
            "X-Aegis-Threat-Version": self.threat.version,
            "User-Agent": f"AegisProxy-DataPlane/{__version__}",
        }
        try:
            for k, v in self.status_headers().items():
                h[k] = "".join(ch for ch in v if " " <= ch < "\x7f")[:160]
        except Exception:  # noqa: BLE001 - status reporting must never break syncing
            pass
        return h

    def _request(self, method: str, path: str, body: Optional[bytes] = None, extra: Optional[Dict[str, str]] = None,
                 timeout: float = 10.0):
        headers = self._headers()
        if body is not None:
            headers["Content-Type"] = "application/json"
        headers.update(extra or {})
        req = urllib.request.Request(self.cfg.control_plane_url + path, data=body, headers=headers, method=method)
        ctx = self._ssl if self.cfg.control_plane_url.startswith("https://") else None
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)

    # -- policy bundle -------------------------------------------------------
    def sync_policy(self) -> bool:
        extra = {"If-None-Match": self._bundle_etag} if self._bundle_etag and self.policy else {}
        updated = False
        try:
            with self._request("GET", "/api/dataplane/bundle", extra=extra) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.policy = Policy(data)
                self._bundle_etag = resp.headers.get("ETag", "")
                updated = True
                log.info("policy bundle updated: revision=%s rules=%d", data.get("revision"), len(data.get("rules") or []))
        except urllib.error.HTTPError as e:
            if e.code != 304:
                log.warning("policy sync failed: HTTP %s", e.code)
                return False
        except Exception as exc:  # network errors, JSON errors
            log.warning("policy sync failed: %s", exc)
            return False
        self.last_sync_ok = time.time()
        if self.policy and self.policy.threat_version and self.policy.threat_version != self.threat.version:
            self.sync_threat()
        if updated:
            self._policy_changed()
        return True

    def _policy_changed(self) -> None:
        if self.on_policy is not None:
            try:
                self.on_policy()
            except Exception:  # noqa: BLE001 - re-evaluation is scheduled on the proxy loop; syncing must go on
                log.exception("policy update callback failed")

    def policy_age(self) -> Optional[float]:
        """Seconds since the last successful policy sync (None before the first one)."""
        return (time.time() - self.last_sync_ok) if self.last_sync_ok else None

    def policy_stale(self) -> bool:
        """AEGIS_POLICY_MAX_AGE exceeded: the worker fails closed until a sync succeeds again."""
        age = self.policy_age()
        return bool(self.cfg.policy_max_age) and self.policy is not None and age is not None and age > self.cfg.policy_max_age

    def _policy_loop(self) -> None:
        while not self._stop.is_set():
            self.sync_policy()
            self._stop.wait(self.cfg.sync_interval)

    # -- threat intel --------------------------------------------------------
    def sync_threat(self) -> None:
        if not self._threat_lock.acquire(blocking=False):
            return  # a sync is already running (policy-triggered and periodic syncs can overlap)
        try:
            self._sync_threat()
        finally:
            self._threat_lock.release()

    def _sync_threat(self) -> None:
        extra = {"Accept-Encoding": "gzip"}
        if self._threat_etag and not self.threat.empty:
            extra["If-None-Match"] = self._threat_etag
        try:
            with self._request("GET", "/api/dataplane/threatintel", extra=extra, timeout=60) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                snap = ThreatSnapshot(json.loads(raw.decode("utf-8")))
                self.threat = snap
                self._threat_etag = resp.headers.get("ETag", "")
                d, u, i, c, h = snap.stats()
                log.info("threat intel updated: version=%s domains=%d urls=%d ips=%d cidrs=%d hashes=%d", snap.version, d, u, i, c, h)
            self._policy_changed()
        except urllib.error.HTTPError as e:
            if e.code != 304:
                log.warning("threat-intel sync failed: HTTP %s", e.code)
        except Exception as exc:
            log.warning("threat-intel sync failed: %s", exc)

    def _threat_loop(self) -> None:
        while not self._stop.is_set():
            self.sync_threat()
            self._stop.wait(self.cfg.threat_sync_interval)

    # -- CA cache (served on the magic portal hosts) -------------------------
    def _ca_loop(self) -> None:
        while not self._stop.is_set():
            for path, attr in (("/api/public/ca/aegis-ca.crt", "ca_pem"), ("/api/public/ca/aegis-ca.der", "ca_der"),
                               ("/api/public/ca/install-linux.sh", "install_sh"), ("/api/public/ca/install-windows.ps1", "install_ps1")):
                try:
                    with self._request("GET", path) as resp:
                        setattr(self, attr, resp.read())
                except Exception as exc:
                    log.debug("CA cache refresh failed for %s: %s", path, exc)
            self._stop.wait(600 if self.ca_pem else 15)

    # -- telemetry -----------------------------------------------------------
    def queue_len(self) -> int:
        """Flow records not yet acknowledged by the control-plane (memory and spool)."""
        with self._qlock:
            n = len(self._queue) + len(self._inflight)
        return n + (self.spool.flows if self.spool else 0)

    def dropped_total(self) -> int:
        with self._qlock:
            return sum(self.dropped.values())

    def drop_summary(self) -> str:
        """Heartbeat value: "0" or "overflow=12,rejected=1"."""
        with self._qlock:
            parts = [f"{r}={self.dropped[r]}" for r in DROP_REASONS if self.dropped.get(r)]
        return ",".join(parts) or "0"

    def _drop(self, reason: str, n: int) -> None:
        if n <= 0:
            return
        with self._qlock:
            self.dropped[reason] += n
        log.warning("telemetry: %d flow records lost (%s); %s in total", n, reason, self.drop_summary())

    def redaction_mode(self) -> str:
        pol = self.policy
        return normalize_mode(pol.policy_value("telemetry_query_redaction", "") if pol is not None else "")

    def redact(self, url: str) -> str:
        return redact_url(url, self.redaction_mode())

    def record_flow(self, flow: Dict[str, Any]) -> None:
        flow.setdefault("data_plane_id", self.cfg.worker_id)
        flow.setdefault("timestamp", _now_iso())  # replayed records keep the time they happened
        mode = self.redaction_mode()
        for k in REDACTED_FIELDS:
            if flow.get(k):
                flow[k] = redact_url(str(flow[k]), mode)
        if self.on_flow:
            self.on_flow(flow)
        overflow = 0
        with self._qlock:
            if len(self._queue) >= self.cfg.flow_queue_max:
                self._queue.popleft()
                self.dropped["overflow"] += 1
                overflow = self.dropped["overflow"]
            self._queue.append(flow)
        if overflow and (overflow & (overflow - 1)) == 0:  # 1, 2, 4, 8, ... : never a log line per record
            log.warning("telemetry queue full (%d records): oldest records dropped (%s)", self.cfg.flow_queue_max, self.drop_summary())

    def _take(self, n: int) -> List[Dict[str, Any]]:
        with self._qlock:
            return [self._queue.popleft() for _ in range(min(len(self._queue), n))]

    def _spool_pending(self) -> None:
        """Moves queued records into fsync'd spool segments. If the spool cannot be written they stay in memory
        (and are delivered from there) instead of being lost."""
        while True:
            with self._qlock:
                chunk = list(self._queue)[:BATCH_SIZE]
            if not chunk:
                return
            try:
                discarded = self.spool.append(chunk)
            except OSError as exc:
                log.error("flow spool %s not writable (%s); keeping records in memory", self.cfg.flow_spool_dir, exc)
                return
            with self._qlock:
                for _ in range(min(len(chunk), len(self._queue))):
                    self._queue.popleft()
            self._drop("spool_full", discarded)

    def _next_batch(self) -> Tuple[List[Dict[str, Any]], str]:
        """The oldest undelivered batch and its spool segment ("" = memory)."""
        if self.spool is not None:
            while True:
                seg = self.spool.oldest()
                if seg is None:
                    break
                name, flows, bad = seg
                self._drop("spool_corrupt", bad)
                if flows:
                    return flows, name
                self.spool.remove(name)
        with self._qlock:
            if not self._inflight:
                self._inflight = [self._queue.popleft() for _ in range(min(len(self._queue), BATCH_SIZE))]
            return list(self._inflight), ""

    def _acknowledged(self, segment: str) -> None:
        if segment:
            self.spool.remove(segment)
        else:
            with self._qlock:
                self._inflight = []

    def _flush(self, timeout: float = 30.0, force: bool = False) -> None:
        with self._flush_lock:
            if self.spool is not None:
                self._spool_pending()
            while force or time.time() >= self._retry_at:
                batch, segment = self._next_batch()
                if not batch:
                    return
                outcome = self._upload(batch, timeout)
                if outcome == "ok":
                    self._acknowledged(segment)
                elif outcome == "rejected":
                    self._acknowledged(segment)
                    self._drop("rejected", len(batch))
                else:
                    return

    def _upload(self, batch: List[Dict[str, Any]], timeout: float) -> str:
        """ok | rejected (the control-plane will never accept this batch) | retry."""
        body = json.dumps({"flows": batch}, default=str).encode("utf-8")
        try:
            with self._request("POST", "/api/dataplane/flows/batch", body=body, timeout=timeout) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            e.close()
            if e.code in (400, 413, 422):
                log.error("telemetry batch of %d flows rejected by the control-plane: HTTP %s", len(batch), e.code)
                return "rejected"
            retry_after = None
            if e.code in (429, 503):
                self.backpressure += 1
                try:
                    retry_after = min(max(float(e.headers.get("Retry-After", "") or 0), 1.0), MAX_RETRY_AFTER)
                except ValueError:
                    retry_after = None
            self._defer(f"HTTP {e.code}", len(batch), retry_after)
            return "retry"
        except Exception as exc:  # noqa: BLE001 - network errors: keep the batch
            self._defer(str(exc), len(batch), None)
            return "retry"
        self._backoff = 0.0
        return "ok"

    def _defer(self, why: str, n: int, retry_after: Optional[float]) -> None:
        self.upload_failures += 1
        self._backoff = min(MAX_BACKOFF, self._backoff * 2 if self._backoff else 1.0)
        delay = retry_after if retry_after is not None else self._backoff
        self._retry_at = time.time() + delay
        log.warning("telemetry upload deferred %.0fs (%s); %d flows kept, %d waiting", delay, why, n, self.queue_len())

    def _telemetry_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self.cfg.flush_interval)
            try:
                self._flush()
            except Exception:  # noqa: BLE001 - the loop must survive any bug in one flush
                log.exception("telemetry flush failed")
