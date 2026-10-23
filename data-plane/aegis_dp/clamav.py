"""Asynchronous ClamAV (clamd) client using the INSTREAM protocol."""

from __future__ import annotations

import asyncio
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

CHUNK = 64 * 1024


@dataclass
class ScanResult:
    status: str  # clean | infected | error
    signature: str = ""
    detail: str = ""


def parse_address(address: str) -> Tuple[str, Optional[str], int]:
    """'tcp://host:3310' | 'host:3310' | 'unix:///run/clamav/clamd.ctl' -> (kind, host_or_path, port)."""
    a = address.strip()
    if a.startswith("unix://"):
        return "unix", a[len("unix://"):], 0
    if a.startswith("tcp://"):
        a = a[len("tcp://"):]
    host, _, port = a.rpartition(":")
    if not host:
        host, port = a, "3310"
    return "tcp", host.strip("[]"), int(port)


class ClamdClient:
    def __init__(self, address: str, timeout: float = 60.0) -> None:
        self.kind, self.target, self.port = parse_address(address)
        self.timeout = timeout
        self.available: Optional[bool] = None
        self.last_check = 0.0

    async def _open(self):
        if self.kind == "unix":
            return await asyncio.wait_for(asyncio.open_unix_connection(self.target), timeout=5)
        return await asyncio.wait_for(asyncio.open_connection(self.target, self.port), timeout=5)

    async def ping(self) -> bool:
        try:
            reader, writer = await self._open()
            try:
                writer.write(b"zPING\0")
                await writer.drain()
                reply = await asyncio.wait_for(reader.readuntil(b"\0"), timeout=5)
                ok = reply.rstrip(b"\0") == b"PONG"
            finally:
                writer.close()
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            ok = False
        self.available, self.last_check = ok, time.time()
        return ok

    async def scan(self, data: bytes) -> ScanResult:
        try:
            return await asyncio.wait_for(self._scan(data), timeout=self.timeout)
        except asyncio.TimeoutError:
            return ScanResult("error", detail="scan timeout")
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            self.available = False
            return ScanResult("error", detail=f"clamd unavailable: {exc}")

    async def _scan(self, data: bytes) -> ScanResult:
        reader, writer = await self._open()
        try:
            writer.write(b"zINSTREAM\0")
            view = memoryview(data)
            for off in range(0, len(view), CHUNK):
                chunk = view[off: off + CHUNK]
                writer.write(struct.pack("!I", len(chunk)))
                writer.write(chunk)
                await writer.drain()
            writer.write(struct.pack("!I", 0))
            await writer.drain()
            reply = (await reader.readuntil(b"\0")).rstrip(b"\0").decode("utf-8", "replace")
        finally:
            writer.close()
        self.available = True
        return parse_reply(reply)


def parse_reply(reply: str) -> ScanResult:
    # "stream: OK" | "stream: Eicar-Test-Signature FOUND" | "INSTREAM size limit exceeded. ERROR"
    body = reply.split(":", 1)[1].strip() if reply.startswith("stream:") else reply.strip()
    if body == "OK":
        return ScanResult("clean")
    if body.endswith(" FOUND"):
        return ScanResult("infected", signature=body[: -len(" FOUND")].strip())
    return ScanResult("error", detail=body or "empty clamd reply")
