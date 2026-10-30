"""ICAP client (RFC 3507) for commercial antivirus, sandbox and DLP engines.

RESPMOD scans downloads (Symantec Protection Engine, Kaspersky Scan Engine, Trend Micro, Sophos SAVDI,
OPSWAT MetaDefender, c-icap + ClamAV, …); REQMOD lets DLP systems (Forcepoint, Symantec DLP) inspect
uploads. Results:
  clean     ICAP 204, or 200 that returns the unmodified message
  infected  the engine reports a threat (X-Infection-Found / X-Virus-ID / X-Violations-Found) or replaces
            the message with a block page (HTTP status >= 400)
  modified  the engine returned sanitized content (content disarm & reconstruction)
  error     connection, protocol or timeout problem
"""

from __future__ import annotations

import asyncio
import re
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

MAX_ICAP_HEADER = 64 * 1024
MAX_ICAP_BODY = 256 * 1024 * 1024


@dataclass
class IcapResult:
    status: str  # clean | infected | modified | error
    threat: str = ""
    detail: str = ""
    body: Optional[bytes] = None  # sanitized content for "modified"
    http_status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)


def parse_icap_url(url: str) -> Tuple[str, int, str, bool]:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("icap", "icaps") or not u.hostname:
        raise ValueError("ICAP URL must look like icap://host:1344/service or icaps://host:11344/service")
    tls = u.scheme == "icaps"
    port = u.port or (11344 if tls else 1344)
    return u.hostname, port, u.path or "/", tls


def _chunked(body: bytes) -> bytes:
    if not body:
        return b"0\r\n\r\n"
    return b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"


async def _read_headers(reader: asyncio.StreamReader) -> bytes:
    data = await reader.readuntil(b"\r\n\r\n")
    if len(data) > MAX_ICAP_HEADER:
        raise ValueError("ICAP header too large")
    return data


async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
    out = bytearray()
    while True:
        line = await reader.readuntil(b"\r\n")
        size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        if size == 0:
            await reader.readuntil(b"\r\n")
            return bytes(out)
        if size < 0 or len(out) + size > MAX_ICAP_BODY:
            raise ValueError("ICAP body too large")
        out += await reader.readexactly(size)
        await reader.readexactly(2)


def _parse_header_block(raw: bytes) -> Tuple[str, Dict[str, str]]:
    lines = raw.decode("iso-8859-1").split("\r\n")
    hdrs: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return lines[0], hdrs


THREAT_HEADERS = ("x-infection-found", "x-virus-id", "x-violations-found", "x-virus-name", "x-blocked-reason")
_threat_re = re.compile(r"Threat=([^;]+)")


def _threat_name(hdrs: Dict[str, str]) -> str:
    for h in THREAT_HEADERS:
        v = hdrs.get(h, "")
        if v:
            m = _threat_re.search(v)
            return (m.group(1) if m else v).strip()[:200]
    return ""


class IcapClient:
    def __init__(self, url: str, timeout: float = 30.0, tls_verify: bool = True, ca_pem: str = "") -> None:
        self.url = url
        self.host, self.port, self.path, self.tls = parse_icap_url(url)
        self.timeout = timeout
        self.ssl_ctx: Optional[ssl.SSLContext] = None
        if self.tls:
            ctx = ssl.create_default_context()
            if ca_pem:
                ctx.load_verify_locations(cadata=ca_pem)
            if not tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self.ssl_ctx = ctx
        self.istag = ""
        self.available: Optional[bool] = None
        self.last_options = 0.0
        # Small per-service keep-alive pool: idle (reader, writer) pairs reusable for the next transaction. Pooled
        # only after a fully-framed response that did not ask to close; a stale pooled connection is dropped and the
        # transaction retried once on a fresh one-shot connection, so reuse never changes a scan result.
        self._pool: List[Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        self._pool_loop: Optional[asyncio.AbstractEventLoop] = None
        self._pool_max = 4

    def _icap_uri(self) -> str:
        scheme = "icaps" if self.tls else "icap"
        return f"{scheme}://{self.host}:{self.port}{self.path}"

    @staticmethod
    def _parse_encapsulated(hdrs: Dict[str, str]) -> Dict[str, int]:
        enc: Dict[str, int] = {}
        for part in hdrs.get("encapsulated", "").split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                try:
                    enc[k.strip()] = int(v.strip())
                except ValueError:
                    pass
        return enc

    async def _send_and_head(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, payload: bytes
                             ) -> Tuple[str, Dict[str, str], Dict[str, int]]:
        """Send one request and read the ICAP response head on an already-open connection (fresh or pooled)."""
        writer.write(payload)
        await writer.drain()  # a service that stops reading must not stall the request beyond the deadline
        raw = await _read_headers(reader)
        status_line, hdrs = _parse_header_block(raw)
        return status_line, hdrs, self._parse_encapsulated(hdrs)

    async def _exchange(self, payload: bytes, conn: Dict[str, asyncio.StreamWriter]
                        ) -> Tuple[str, Dict[str, str], Dict[str, int], asyncio.StreamReader]:
        """Open a fresh connection, send the request and read the response head (OPTIONS probe path). Callers run
        it under one deadline (connect + send + receive) and close ``conn["writer"]`` on every path."""
        reader, writer = await asyncio.open_connection(self.host, self.port, ssl=self.ssl_ctx)
        conn["writer"] = writer
        status_line, hdrs, enc = await self._send_and_head(reader, writer, payload)
        return status_line, hdrs, enc, reader

    @staticmethod
    def _close(conn: Dict[str, asyncio.StreamWriter]) -> None:
        writer = conn.pop("writer", None)
        if writer is not None:
            try:
                writer.close()
            except Exception:  # noqa: BLE001 - already broken transport
                pass

    @staticmethod
    def _safe_close(writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
        except Exception:  # noqa: BLE001 - already broken transport
            pass

    def _drop_pool(self) -> None:
        for _reader, writer in self._pool:
            self._safe_close(writer)
        self._pool.clear()

    def _acquire_pooled(self) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        """A live pooled connection for the running loop, or None. Connections created on another event loop (a
        fresh asyncio.run) are discarded: a pooled transport belongs to the loop that opened it."""
        loop = asyncio.get_running_loop()
        if self._pool_loop is not loop:
            self._drop_pool()
            self._pool_loop = loop
        while self._pool:
            reader, writer = self._pool.pop()
            if writer.is_closing() or reader.at_eof():
                self._safe_close(writer)
                continue
            return reader, writer
        return None

    def _release(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if writer.is_closing() or len(self._pool) >= self._pool_max:
            self._safe_close(writer)
            return
        self._pool.append((reader, writer))

    @staticmethod
    def _wants_close(hdrs: Dict[str, str]) -> bool:
        return "close" in hdrs.get("connection", "").lower()

    async def options(self) -> bool:
        req = (f"OPTIONS {self._icap_uri()} ICAP/1.0\r\nHost: {self.host}\r\nUser-Agent: AegisProxy-ICAP/2.1\r\n"
               "Encapsulated: null-body=0\r\n\r\n").encode("latin-1", "replace")
        conn: Dict[str, asyncio.StreamWriter] = {}
        try:
            status, hdrs, _, _ = await asyncio.wait_for(self._exchange(req, conn), self.timeout)
            ok = status.split(" ")[1:2] == ["200"]
            self.istag = hdrs.get("istag", "").strip('"')
            self.available = ok
        except Exception:  # noqa: BLE001 - availability probe
            self.available = False
        finally:
            self._close(conn)
        self.last_options = time.time()
        return bool(self.available)

    async def _consume(self, method: str, body: bytes, started: float, status: str, hdrs: Dict[str, str],
                       enc: Dict[str, int], reader: asyncio.StreamReader) -> Tuple[IcapResult, bool]:
        """Read the body of a response whose head is already parsed and build the result. Returns
        ``(result, drained)``: ``drained`` is True only when the whole message was consumed deterministically, so
        the connection is safe to return to the keep-alive pool."""
        parts = status.split(" ")
        if len(parts) < 2 or not parts[0].startswith("ICAP/") or not parts[1].isdigit():
            raise ValueError(f"malformed ICAP status line {status[:60]!r}")
        code = int(parts[1])
        self.available = True  # the service answered (status of real traffic beats the last probe)
        if code == 204:
            return IcapResult("clean", detail=f"204 in {time.time() - started:.2f}s"), True
        if code != 200:
            return IcapResult("error", detail=f"ICAP status {code}"), False  # unread body of unknown framing: no reuse
        threat = _threat_name(hdrs)
        # Read the encapsulated sections strictly by their offsets (RFC 3507 section 4.4.1).
        http_status, http_hdrs, new_body = 0, {}, None
        order = sorted(enc.items(), key=lambda kv: kv[1])
        sections: Dict[str, bytes] = {}
        for idx, (key, off) in enumerate(order):
            if key.endswith("-hdr"):
                nxt = order[idx + 1][1] if idx + 1 < len(order) else None
                if nxt is not None and not 0 <= nxt - off <= MAX_ICAP_HEADER:
                    raise ValueError("encapsulated header too large")
                sections[key] = await (reader.readexactly(nxt - off) if nxt is not None else _read_headers(reader))
            elif key in ("res-body", "req-body"):  # "null-body" carries no data
                new_body = await _read_chunked(reader)
        if "res-hdr" in sections:
            line, http_hdrs = _parse_header_block(sections["res-hdr"])
            try:
                http_status = int(line.split(" ")[1])
            except (IndexError, ValueError):
                http_status = 0
        elif "req-hdr" in sections:
            _, http_hdrs = _parse_header_block(sections["req-hdr"])
        threat = threat or _threat_name(http_hdrs)
        # Reusable only when the final declared section was a body terminator we fully consumed; a trailing -hdr
        # read to a blank line could leave undeclared bytes on the wire and corrupt the next transaction.
        drained = not order or not order[-1][0].endswith("-hdr")
        if threat or http_status >= 400 or (method == "REQMOD" and http_status):
            return IcapResult("infected", threat=threat or f"blocked by ICAP service (HTTP {http_status})", body=new_body,
                              http_status=http_status, headers=http_hdrs), drained
        if new_body is not None and new_body != body:
            return IcapResult("modified", body=new_body, http_status=http_status, headers=http_hdrs, detail="content sanitized"), drained
        return IcapResult("clean", detail="200 unmodified"), drained

    async def _run(self, method: str, payload: bytes, body: bytes, started: float,
                   conn: Dict[str, asyncio.StreamWriter]) -> IcapResult:
        """One ICAP transaction with keep-alive reuse. A pooled connection is tried first; if it breaks before a
        response head is read (a stale keep-alive socket) it is dropped and the transaction retried once on a fresh
        one-shot connection, so reuse never changes the result."""
        pooled = self._acquire_pooled()
        if pooled is not None:
            reader, writer = pooled
            conn["writer"] = writer
            try:
                status, hdrs, enc = await self._send_and_head(reader, writer, payload)
            except Exception:  # noqa: BLE001 - stale pooled connection: drop it and fall through to a fresh one
                conn.pop("writer", None)
                self._safe_close(writer)
            else:
                return await self._finish(method, body, started, status, hdrs, enc, reader, writer, conn)
        reader, writer = await asyncio.open_connection(self.host, self.port, ssl=self.ssl_ctx)
        conn["writer"] = writer
        status, hdrs, enc = await self._send_and_head(reader, writer, payload)
        return await self._finish(method, body, started, status, hdrs, enc, reader, writer, conn)

    async def _finish(self, method: str, body: bytes, started: float, status: str, hdrs: Dict[str, str],
                      enc: Dict[str, int], reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      conn: Dict[str, asyncio.StreamWriter]) -> IcapResult:
        result, drained = await self._consume(method, body, started, status, hdrs, enc, reader)
        if drained and not self._wants_close(hdrs) and not reader.at_eof():
            conn.pop("writer", None)  # hand off to the pool; the caller's finally must not close it
            self._release(reader, writer)
        else:
            conn.pop("writer", None)
            self._safe_close(writer)
        return result

    def close(self) -> None:
        """Close every idle pooled connection (worker shutdown)."""
        self._drop_pool()

    async def _modify(self, method: str, req_hdr: bytes, res_hdr: Optional[bytes], body: bytes) -> IcapResult:
        """One ICAP transaction. Every failure (network, timeout, protocol, parsing) is an "error" result, so
        the caller's fail mode decides; the whole exchange shares one deadline."""
        started = time.time()
        conn: Dict[str, asyncio.StreamWriter] = {}
        try:
            offsets = []
            pos = 0
            parts = []
            if req_hdr:
                offsets.append(f"req-hdr={pos}")
                parts.append(req_hdr)
                pos += len(req_hdr)
            if res_hdr is not None:
                offsets.append(f"res-hdr={pos}")
                parts.append(res_hdr)
                pos += len(res_hdr)
            body_key = "res-body" if method == "RESPMOD" else "req-body"
            offsets.append(f"{body_key}={pos}" if body else f"null-body={pos}")
            head = (f"{method} {self._icap_uri()} ICAP/1.0\r\nHost: {self.host}\r\nUser-Agent: AegisProxy-ICAP/2.1\r\n"
                    f"Allow: 204\r\nConnection: keep-alive\r\nEncapsulated: {', '.join(offsets)}\r\n\r\n").encode("latin-1", "replace")
            payload = head + b"".join(parts) + (_chunked(body) if body else b"")
            return await asyncio.wait_for(self._run(method, payload, body, started, conn), self.timeout)
        except (asyncio.TimeoutError, TimeoutError):
            return IcapResult("error", detail=f"ICAP timeout after {self.timeout:.0f}s")
        except OSError as exc:
            self.available = False
            return IcapResult("error", detail=f"ICAP error: {exc}"[:200])
        except Exception as exc:  # noqa: BLE001 - protocol/parse errors must never bypass the fail mode
            return IcapResult("error", detail=f"ICAP error: {type(exc).__name__}: {exc}"[:200])
        finally:
            self._close(conn)

    @staticmethod
    def _http_header_lines(headers: List[Tuple[str, str]], skip: Tuple[str, ...]) -> bytes:
        out = b""
        for k, v in headers:
            if k.lower() not in skip:
                out += f"{k}: {v}\r\n".encode("latin-1", "replace")
        return out

    async def respmod(self, method: str, url: str, req_headers: List[Tuple[str, str]], status: int,
                      resp_headers: List[Tuple[str, str]], body: bytes) -> IcapResult:
        try:
            u = urllib.parse.urlsplit(url)
            target = (u.path or "/") + (("?" + u.query) if u.query else "")
            req_hdr = f"{method} {target} HTTP/1.1\r\nHost: {u.netloc}\r\n".encode("latin-1", "replace")
            # credentials never leave the proxy
            req_hdr += self._http_header_lines(req_headers, ("host", "proxy-authorization", "authorization", "cookie")) + b"\r\n"
            # The body is sent decoded and with exactly one (computed) Content-Length.
            res_hdr = f"HTTP/1.1 {int(status)} OK\r\n".encode()
            res_hdr += self._http_header_lines(resp_headers, ("transfer-encoding", "content-encoding", "content-length", "set-cookie"))
            res_hdr += f"Content-Length: {len(body)}\r\n\r\n".encode()
        except Exception as exc:  # noqa: BLE001 - malformed URL/headers: an error result, never an exception
            return IcapResult("error", detail=f"ICAP error: {type(exc).__name__}: {exc}"[:200])
        return await self._modify("RESPMOD", req_hdr, res_hdr, body)

    async def reqmod(self, method: str, url: str, req_headers: List[Tuple[str, str]], body: bytes) -> IcapResult:
        try:
            u = urllib.parse.urlsplit(url)
            target = (u.path or "/") + (("?" + u.query) if u.query else "")
            req_hdr = f"{method} {url if u.scheme == 'http' else target} HTTP/1.1\r\nHost: {u.netloc}\r\n".encode("latin-1", "replace")
            req_hdr += self._http_header_lines(req_headers, ("host", "proxy-authorization", "authorization", "cookie",
                                                            "transfer-encoding", "content-encoding", "content-length"))
            req_hdr += f"Content-Length: {len(body)}\r\n\r\n".encode()
        except Exception as exc:  # noqa: BLE001
            return IcapResult("error", detail=f"ICAP error: {type(exc).__name__}: {exc}"[:200])
        return await self._modify("REQMOD", req_hdr, None, body)
