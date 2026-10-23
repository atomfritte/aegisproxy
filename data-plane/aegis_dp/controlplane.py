"""Control-plane client: policy/threat-intel sync, telemetry upload and block tokens.

All network I/O runs in background threads so the mitmproxy event loop is never blocked.
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
from collections import deque
from typing import Any, Callable, Deque, Dict, Optional

from . import __version__
from .config import Config
from .policy import Policy
from .threatintel import ThreatSnapshot

log = logging.getLogger("aegis.controlplane")


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
                 status_headers: Callable[[], Dict[str, str]] = dict) -> None:
        self.cfg = cfg
        self.clamav_status = clamav_status
        self.status_headers = status_headers
        self.on_flow = on_flow
        self.policy: Optional[Policy] = None
        self.threat = ThreatSnapshot()
        self.ca_pem: bytes = b""
        self.ca_der: bytes = b""
        self.install_sh: bytes = b""
        self.install_ps1: bytes = b""
        self.last_sync_ok = 0.0
        self._bundle_etag = ""
        self._threat_etag = ""
        self._queue: Deque[Dict[str, Any]] = deque(maxlen=20_000)
        self._qlock = threading.Lock()
        self._threat_lock = threading.Lock()
        self._stop = threading.Event()
        self._ssl = ssl.create_default_context(cafile=cfg.control_plane_ca_file or None)
        self._threads = []

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        for name, target in (("aegis-policy-sync", self._policy_loop), ("aegis-threat-sync", self._threat_loop),
                             ("aegis-telemetry", self._telemetry_loop), ("aegis-ca-cache", self._ca_loop)):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        self._flush()

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
        try:
            with self._request("GET", "/api/dataplane/bundle", extra=extra) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.policy = Policy(data)
                self._bundle_etag = resp.headers.get("ETag", "")
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
        return True

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
        return len(self._queue)

    def record_flow(self, flow: Dict[str, Any]) -> None:
        flow.setdefault("data_plane_id", self.cfg.worker_id)
        if self.on_flow:
            self.on_flow(flow)
        with self._qlock:
            self._queue.append(flow)

    def _flush(self) -> None:
        while True:
            with self._qlock:
                batch = [self._queue.popleft() for _ in range(min(len(self._queue), 500))]
            if not batch:
                return
            try:
                body = json.dumps({"flows": batch}, default=str).encode("utf-8")
                with self._request("POST", "/api/dataplane/flows/batch", body=body) as resp:
                    resp.read()
            except Exception as exc:
                log.warning("telemetry upload failed (%d flows re-queued): %s", len(batch), exc)
                with self._qlock:
                    self._queue.extendleft(reversed(batch))
                return

    def _telemetry_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self.cfg.flush_interval)
            self._flush()
