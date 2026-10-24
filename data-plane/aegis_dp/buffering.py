"""Bounded buffering of message bodies: a cap per flow and a budget per worker.

mitmproxy keeps every body that is not streamed in memory until it is complete. Its only limit is the global
body_size_limit (AEGIS_BODY_SIZE_LIMIT, default 1g per message), so a handful of concurrent large responses
without Content-Length (or chunked uploads) could exhaust a worker. The addon therefore streams every body that
nothing needs to see, and gives each body it buffers for inspection a BodyGuard: a per-flow cap plus a share of
the worker's budget (AEGIS_BUFFER_BUDGET). Bodies of known size are admitted when the headers arrive, bodies of
unknown size chunk by chunk.

mitmproxy 12 has no addon hook for the chunks of a body it buffers. install() therefore wraps
HttpStream.check_body_size, which mitmproxy runs for exactly these chunks (it enforces body_size_limit and
stream_large_bodies there), and carries out the guard's decision with the primitives mitmproxy uses itself:
switching to streaming (stream_large_bodies) or, if the decision cannot be made, aborting the message
(body_size_limit). Request bodies of flows that were already answered locally (block page) are discarded as they
arrive instead of being buffered.
"""

from __future__ import annotations

import logging
import weakref
from typing import Any, Callable, Dict, Optional

log = logging.getLogger("aegis.dataplane")

GUARDS = "aegis_body_guards"  # flow.metadata key: {"request": BodyGuard, "response": BodyGuard}
STREAM, BLOCK = "stream", "block"


def parse_size(value: str) -> Optional[int]:
    """'512m', '1g', '1048576' -> bytes (k/m/g suffixes like mitmproxy's size options); '' -> None.
    Raises ValueError for anything else."""
    v = (value or "").strip().lower()
    if not v:
        return None
    mult = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}.get(v[-1], 1)
    num = v[:-1] if mult > 1 else v
    if not num.isdigit():
        raise ValueError(f"invalid size {value!r}")
    return int(num) * mult


class BufferBudget:
    """Bytes of message bodies all flows of one worker may hold for inspection at the same time. Used from the
    event loop only; the ops thread reads the counters."""

    def __init__(self, total: int) -> None:
        self.total = max(0, int(total))
        self.used = 0
        self.peak = 0

    def reserve(self, n: int) -> bool:
        if n <= 0:
            return True
        if self.used + n > self.total:
            return False
        self.used += n
        self.peak = max(self.peak, self.used)
        return True

    def release(self, n: int) -> None:
        self.used = max(0, self.used - n)


class BodyGuard:
    """Accounting for one buffered body. ``on_exceed(reason, size)`` runs once when the body outgrows the cap
    ("oversize") or the budget ("busy"). It adjusts the flow and returns STREAM (``message.stream`` is set: the
    rest is relayed unbuffered) or BLOCK (requests: ``flow.response`` holds the block page, the upload is
    discarded; responses: the response was replaced by the block message with a discarding stream)."""

    __slots__ = ("budget", "cap", "on_exceed", "reserved", "exceeded", "__weakref__")

    def __init__(self, budget: BufferBudget, cap: int, on_exceed: Callable[[str, int], str]) -> None:
        self.budget, self.cap, self.on_exceed = budget, max(0, int(cap)), on_exceed
        self.reserved = 0
        self.exceeded = ""

    def admit(self, size: int) -> Optional[str]:
        """None while ``size`` buffered bytes fit the cap and the budget, otherwise "oversize" or "busy"."""
        if size > self.cap:
            return "oversize"
        if size > self.reserved:
            if not self.budget.reserve(size - self.reserved):
                return "busy"
            self.reserved = size
        return None

    def hold(self, n: int) -> bool:
        """Reserves ``n`` more bytes beyond the cap (a decoded copy kept while scanners run) until release()."""
        if not self.budget.reserve(n):
            return False
        self.reserved += max(0, n)
        return True

    def exceed(self, reason: str, size: int) -> str:
        self.exceeded = reason
        self.release()
        return self.on_exceed(reason, size)

    def release(self) -> None:
        if self.reserved:
            self.budget.release(self.reserved)
            self.reserved = 0


def attach(flow: Any, kind: str, guard: BodyGuard) -> BodyGuard:
    guards: Dict[str, BodyGuard] = flow.metadata.setdefault(GUARDS, {})
    old = guards.get(kind)
    if old is not None:
        old.release()
    guards[kind] = guard
    try:
        weakref.finalize(flow, guard.release)  # backstop for flows that end without a response/error hook
    except TypeError:
        pass
    return guard


def hold(flow: Any, kind: str, n: int) -> bool:
    """Adds ``n`` bytes to the share of the flow's guard; True without a guard (nothing is accounted)."""
    guard = (flow.metadata.get(GUARDS) or {}).get(kind)
    return guard is None or n <= 0 or guard.hold(n)


def release(flow: Any) -> None:
    for guard in (flow.metadata.get(GUARDS) or {}).values():
        guard.release()


_installed = False


def install() -> bool:
    """Wraps mitmproxy's HttpStream.check_body_size (idempotent). False when this mitmproxy version lacks the
    internals used here: bodies of unknown length are then limited by body_size_limit only."""
    global _installed
    if _installed:
        return True
    try:
        from mitmproxy import flow as mflow
        from mitmproxy.proxy.layers import http as mhttp

        stream_cls = mhttp.HttpStream
        original = stream_cls.check_body_size
        for name in ("start_request_stream", "start_response_stream", "handle_event", "state_errored"):
            getattr(stream_cls, name)
        ErrorCode, SendHttp, HttpErrorHook = mhttp.ErrorCode, mhttp.SendHttp, mhttp.HttpErrorHook
        RequestData, ResponseData = mhttp.RequestData, mhttp.ResponseData
        RequestProtocolError, ResponseProtocolError = mhttp.RequestProtocolError, mhttp.ResponseProtocolError
    except (ImportError, AttributeError) as exc:
        log.critical("bounded body buffering is not available with this mitmproxy version (%s): bodies of unknown "
                     "length are only limited by body_size_limit", exc)
        return False

    def check_body_size(self, request: bool):
        flow = getattr(self, "flow", None)
        if request and flow is not None and flow.response is not None and self.request_body_buf:
            # Answered locally (block page): the upload is never forwarded, nothing needs to be kept.
            self.request_body_buf.clear()
            return False
        if (yield from original(self, request)):
            return True
        buf = self.request_body_buf if request else self.response_body_buf
        message = flow.request if request else flow.response
        guard = (flow.metadata.get(GUARDS) or {}).get("request" if request else "response")
        if guard is None or guard.exceeded or not buf or message is None or message.stream:
            return False
        reason = guard.admit(len(buf))
        if reason is None:
            return False
        try:
            decision = guard.exceed(reason, len(buf))
        except Exception:  # noqa: BLE001 - the layer must not crash; fail closed below
            log.exception("buffer limit handling failed; aborting the %s", "request" if request else "response")
            decision = ""
        if decision == BLOCK and request and flow.response is not None:
            buf.clear()  # the block page is sent once the client has finished sending (see above)
            return False
        if decision == BLOCK and not request and callable(message.stream):
            buf.clear()
            yield from self.start_response_stream()
            yield from self.handle_event(ResponseData(self.stream_id, b""))  # emits the block message
            return False
        if decision == STREAM:
            if not message.stream:
                message.stream = True
            body = bytes(buf)
            buf.clear()
            if request:
                yield from self.start_request_stream()
                yield from self.handle_event(RequestData(self.stream_id, body))
            else:
                yield from self.start_response_stream()
                yield from self.handle_event(ResponseData(self.stream_id, body))
            return False
        # No usable decision: abort like body_size_limit does.
        msg = "AegisProxy: message body exceeds the inspection buffer limit"
        code = ErrorCode.REQUEST_TOO_LARGE if request else ErrorCode.RESPONSE_TOO_LARGE
        flow.error = mflow.Error(msg)
        yield HttpErrorHook(flow)
        yield SendHttp(ResponseProtocolError(self.stream_id, msg, code), self.context.client)
        self.client_state = self.state_errored
        if not request:
            yield SendHttp(RequestProtocolError(self.stream_id, msg, code), self.context.server)
            self.server_state = self.state_errored
        flow.live = False
        return True

    check_body_size.__wrapped__ = original  # type: ignore[attr-defined]
    stream_cls.check_body_size = check_body_size
    _installed = True
    return True
