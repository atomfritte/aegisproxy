"""Operational HTTP endpoint for the data-plane worker (health probes + Prometheus metrics).

Served on AEGIS_OPS_ADDR (default 0.0.0.0:9091), separate from the proxy port:
  /healthz  process alive
  /readyz   a policy bundle has been loaded and is not older than AEGIS_POLICY_MAX_AGE (without a maximum age the
            worker enforces the last known policy however long the control-plane is unreachable; the age is
            exposed as a metric either way)
  /metrics  Prometheus text format
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Tuple


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Counter = Counter()
        self._sums: Dict[str, float] = {}

    def inc(self, name: str, labels: Tuple[Tuple[str, str], ...] = (), value: float = 1.0) -> None:
        with self._lock:
            self._counters[(name, labels)] += value

    def observe(self, name: str, seconds: float) -> None:
        with self._lock:
            self._sums[name + "_sum"] = self._sums.get(name + "_sum", 0.0) + seconds
            self._sums[name + "_count"] = self._sums.get(name + "_count", 0.0) + 1

    def render(self, gauges: Dict[str, float]) -> str:
        lines = []
        with self._lock:
            for (name, labels), v in sorted(self._counters.items()):
                lbl = ",".join(f'{k}="{val}"' for k, val in labels)
                lines.append(f"{name}{{{lbl}}} {v:g}" if lbl else f"{name} {v:g}")
            for name, v in sorted(self._sums.items()):
                lines.append(f"{name} {v:g}")
        for name, v in sorted(gauges.items()):
            lines.append(f"{name} {v:g}")
        return "\n".join(lines) + "\n"


def start_ops_server(addr: str, metrics: Metrics, gauges: Callable[[], Dict[str, float]], ready: Callable[[], str]):
    """``ready`` returns "" when the worker can serve traffic, otherwise why it cannot."""
    host, _, port = addr.rpartition(":")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:  # quiet
            pass

        def _send(self, code: int, body: str, ctype: str = "text/plain; charset=utf-8") -> None:
            data = body.encode()
            try:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass  # load-balancer health checks commonly reset the connection early

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send(200, "ok\n")
            elif self.path == "/readyz":
                reason = ready()
                self._send(503, reason + "\n") if reason else self._send(200, "ready\n")
            elif self.path == "/metrics":
                self._send(200, metrics.render(gauges()), "text/plain; version=0.0.4; charset=utf-8")
            else:
                self._send(404, "not found\n")

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, request, client_address) -> None:
            pass  # never print tracebacks for probe/scrape connection errors

    server = Server((host or "0.0.0.0", int(port)), Handler)
    t = threading.Thread(target=server.serve_forever, name="aegis-ops", daemon=True)
    t.start()
    return server


def now() -> float:
    return time.time()
