"""Local proxy access log (Squid native, Common/Combined Log Format or JSON).

Destinations (AEGIS_ACCESS_LOG):
  off (default) · stdout · stderr · /path/to/file · syslog://host:514 (UDP) · syslog+tcp://host:514 ·
  syslog:///dev/log (local socket)
Files are reopened after an external rename (logrotate) or, with AEGIS_ACCESS_LOG_ROTATE_MB > 0 (the
default on Windows, where an open file cannot be renamed by another process), rotated by the worker
itself into AEGIS_ACCESS_LOG_KEEP numbered generations.
Format (AEGIS_ACCESS_LOG_FORMAT): squid (default) · combined · json
The central log export of the control-plane covers SIEM forwarding; this log serves local tooling
(Squid log analyzers, rsyslog on the proxy host, container log collectors).
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import queue
import socket
import sys
import threading
import time
import urllib.parse
from typing import Any, Dict, Optional

from .policy import ALLOWED_VERDICTS, VERDICT_TLS_BYPASS

FORMATS = ("squid", "combined", "json")


def _squid_action(rec: Dict[str, Any]) -> str:
    verdict = rec.get("verdict", "")
    status = int(rec.get("status_code") or 0)
    if verdict == VERDICT_TLS_BYPASS:
        return f"TCP_TUNNEL/{status or 200}"
    if verdict in ALLOWED_VERDICTS:
        return f"TCP_MISS/{status or 200}"
    return f"TCP_DENIED/{status or 403}"


def _clean(v: Any) -> str:
    s = str(v if v is not None else "")
    return "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in s).replace(" ", "%20") or "-"


def format_record(rec: Dict[str, Any], fmt: str, now: Optional[float] = None) -> str:
    ts = now if now is not None else time.time()
    url = rec.get("full_url") or ""
    if (rec.get("method") or "").upper() == "CONNECT":
        url = f"{rec.get('host', '')}:{rec.get('port') or 443}"
    if fmt == "json":
        out = {k: rec.get(k) for k in ("id", "server_ip", "server_id", "server_hostname", "group_ids", "method", "full_url", "host",
                                      "port", "status_code", "verdict", "block_reason", "matched_rule_name", "bytes_sent",
                                      "bytes_received", "latency_ms", "user_agent", "content_type", "resolved_ip",
                                      "threat_category", "threat_indicator", "file_type", "av_result", "data_plane_id")
               if rec.get(k) not in (None, "", [], 0)}
        out["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + f".{int((ts % 1) * 1000):03d}Z"
        out["log_type"] = "aegisproxy.access"
        return json.dumps(out, separators=(",", ":"), default=str)
    size = int(rec.get("bytes_received") or 0) + int(rec.get("bytes_sent") or 0)
    if fmt == "combined":
        when = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(ts))
        ua = str(rec.get("user_agent") or "-").replace('"', "'")
        return (f"{_clean(rec.get('server_ip'))} - {_clean(rec.get('proxy_auth_user') or '-')} [{when}] "
                f"\"{_clean(rec.get('method'))} {_clean(url)} HTTP/1.1\" {int(rec.get('status_code') or 0) or '-'} {size} "
                f"\"-\" \"{ua}\" {_clean(rec.get('verdict'))}")
    # Squid native: time elapsed client action/code size method URL ident hierarchy/peer type
    peer = rec.get("resolved_ip") or "-"
    hierarchy = "HIER_NONE/-" if _squid_action(rec).startswith("TCP_DENIED") else f"HIER_DIRECT/{peer}"
    return (f"{ts:.3f} {int(rec.get('latency_ms') or 0):6d} {_clean(rec.get('server_ip'))} {_squid_action(rec)} {size} "
            f"{_clean(rec.get('method'))} {_clean(url)} {_clean(rec.get('proxy_auth_user') or '-')} {hierarchy} "
            f"{_clean(rec.get('content_type') or '-')}")


class _TCPSyslog:
    """Line-framed TCP syslog sender that connects lazily and reconnects (never raises to callers)."""

    def __init__(self, host: str, port: int, ident: str) -> None:
        self.addr, self.ident, self.sock = (host, port), ident, None
        self.pri = 21 * 8 + 6  # local5.info

    def send(self, line: str) -> None:
        if self.sock is None:
            self.sock = socket.create_connection(self.addr, timeout=3)
        try:
            self.sock.sendall(f"<{self.pri}>{self.ident}{line}\n".encode("utf-8", "replace"))
        except OSError:
            self.sock.close()
            self.sock = None
            raise


class AccessLog:
    """Asynchronous access log: formatting happens on the caller, I/O on a background thread so a slow
    or unreachable destination never blocks the proxy event loop (lines are dropped when the queue is full)."""

    def __init__(self, destination: str, fmt: str = "squid", rotate_bytes: int = 0, keep: int = 10) -> None:
        self.fmt = fmt if fmt in FORMATS else "squid"
        self.logger: Optional[logging.Logger] = None
        self.dropped = 0
        self._emit = None
        dest = (destination or "").strip()
        if not dest or dest.lower() == "off":
            return
        ident = "aegisproxy-access: "
        if dest.startswith("syslog+tcp://"):
            u = urllib.parse.urlparse(dest)
            self._emit = _TCPSyslog(u.hostname or "127.0.0.1", u.port or 514, ident).send
        else:
            handler: logging.Handler
            if dest == "stdout":
                handler = logging.StreamHandler(sys.stdout)
            elif dest == "stderr":
                handler = logging.StreamHandler(sys.stderr)
            elif dest.startswith("syslog://"):
                u = urllib.parse.urlparse(dest)
                address: Any = u.path if (u.path and not u.hostname) else (u.hostname or "127.0.0.1", u.port or 514)
                handler = logging.handlers.SysLogHandler(address=address, facility=logging.handlers.SysLogHandler.LOG_LOCAL5)
                handler.ident = ident
            elif rotate_bytes > 0:
                handler = logging.handlers.RotatingFileHandler(dest, maxBytes=rotate_bytes, backupCount=max(keep, 1), encoding="utf-8")
            else:
                handler = logging.handlers.WatchedFileHandler(dest, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(message)s"))
            lg = logging.getLogger("aegis.access")
            for old in lg.handlers:
                old.close()
            lg.handlers = [handler]
            lg.setLevel(logging.INFO)
            lg.propagate = False
            self.logger = lg
            self._emit = lg.info
        self._q: "queue.Queue[str]" = queue.Queue(maxsize=20_000)
        threading.Thread(target=self._run, name="aegis-access-log", daemon=True).start()

    @property
    def enabled(self) -> bool:
        return self._emit is not None

    def write(self, rec: Dict[str, Any]) -> None:
        if self._emit is None:
            return
        try:
            # Undecodable request bytes (lone surrogates) must not make the line unwritable.
            line = format_record(rec, self.fmt).encode("utf-8", "backslashreplace").decode("utf-8")
            self._q.put_nowait(line)
        except queue.Full:
            self.dropped += 1
        except Exception:  # noqa: BLE001 - logging must never break proxying
            pass

    def flush(self, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        while self._emit is not None and not self._q.empty() and time.time() < deadline:
            time.sleep(0.01)
        time.sleep(0.02)

    def close(self) -> None:
        """Flushes pending lines and closes the file or syslog handler (worker shutdown)."""
        if self._emit is None:
            return
        self.flush()
        if self.logger is not None:
            for h in self.logger.handlers:
                h.close()
            self.logger.handlers = []
        self._emit = None

    def _run(self) -> None:
        backoff_until = 0.0
        while True:
            line = self._q.get()
            if time.time() < backoff_until:
                self.dropped += 1
                continue
            try:
                self._emit(line)
            except Exception:  # noqa: BLE001
                self.dropped += 1
                backoff_until = time.time() + 5
