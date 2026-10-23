"""Bounded HTTP content decoding for inspection.

Scanners must see exactly what a client will see after it removes the content codings, so the worker
decodes bodies itself instead of relying on lenient library helpers:
  * coding chains (``Content-Encoding: gzip, br``) are undone in reverse order (at most MAX_CODINGS),
  * every gzip member and every zstd frame is decoded (clients concatenate them),
  * output is capped while inflating: a decompression bomb never allocates more than ``limit`` bytes,
  * unknown codings, corrupt data and trailing bytes after the compressed stream raise UndecodableContent.

Supported: identity, gzip/x-gzip, deflate (zlib or raw), br (brotli >= 1.2 with bounded output, shipped
with mitmproxy) and zstd (Python 3.14 ``compression.zstd`` or ``backports.zstd``). Standard library only;
brotli and zstd are optional.
"""

from __future__ import annotations

import zlib
from typing import List, Optional, Tuple

try:  # pragma: no cover - depends on the installation (mitmproxy depends on brotli)
    import brotli  # type: ignore

    brotli.Decompressor().process(b"", output_buffer_limit=1)  # bounded output needs brotli >= 1.2
except Exception:  # noqa: BLE001 - missing or too old: "br" is neither requested nor decoded
    brotli = None
try:  # pragma: no cover
    from compression import zstd  # type: ignore  # Python >= 3.14
except Exception:  # noqa: BLE001
    try:
        from backports import zstd  # type: ignore
    except Exception:  # noqa: BLE001
        zstd = None

MAX_CODINGS = 4
_ALIASES = {"x-gzip": "gzip"}
_IDENTITY = ("", "identity")


class UndecodableContent(ValueError):
    """Unknown content coding, corrupt compressed data or trailing garbage."""


class _Overflow(Exception):
    pass


def supported_codings() -> List[str]:
    codings = ["gzip", "deflate"]
    if brotli is not None:
        codings.append("br")
    if zstd is not None:
        codings.append("zstd")
    return codings


def parse_codings(*headers: Optional[str]) -> List[str]:
    """Content codings in the order they were applied (identity dropped, aliases resolved)."""
    out: List[str] = []
    for header in headers:
        for token in (header or "").split(","):
            c = token.strip().lower()
            if c not in _IDENTITY:
                out.append(_ALIASES.get(c, c))
    return out


def transfer_codings(header: Optional[str]) -> List[str]:
    """Transfer codings other than chunked (mitmproxy removes the chunked framing itself)."""
    return [c for c in parse_codings(header) if c != "chunked"]


def filter_accept_encoding(value: Optional[str]) -> Optional[str]:
    """Rewrites an Accept-Encoding request header to the codings the worker can decode.

    Only codings the client offered are kept ("*" expands to the supported ones), so the client is never
    sent a coding it did not ask for. Returns None when the header is absent (servers then answer identity
    or a coding we decode anyway) and "identity" when nothing decodable remains.
    """
    if value is None:
        return None
    supported = supported_codings()
    kept: List[str] = []
    for part in value.split(","):
        token, _, params = part.strip().partition(";")
        coding = token.strip().lower()
        if not coding:
            continue
        if coding == "*":
            names = supported
        elif _ALIASES.get(coding, coding) in supported or coding == "identity":
            names = [coding]
        else:
            continue
        suffix = (";" + params.strip()) if params.strip() else ""
        for name in names:
            entry = name + suffix
            if not any(k.split(";", 1)[0] == name for k in kept):
                kept.append(entry)
    return ", ".join(kept) if kept else "identity"


def decodable(codings: List[str]) -> bool:
    supported = supported_codings()
    return len(codings) <= MAX_CODINGS and all(c in supported for c in codings)


def decode_body(data: bytes, codings: List[str], limit: int) -> Tuple[bytes, bool]:
    """Undoes ``codings`` (given in the order they were applied). Returns (decoded, truncated): when the
    decoded body would exceed ``limit`` bytes, the first ``limit`` bytes are returned with truncated=True and
    nothing beyond that is ever inflated. Raises UndecodableContent."""
    if len(codings) > MAX_CODINGS:
        raise UndecodableContent(f"more than {MAX_CODINGS} stacked content codings")
    if not codings:
        return data, False  # identity: nothing is inflated, the caller applies its size limits
    limit = max(0, int(limit))
    truncated = False
    out = data
    for coding in reversed(codings):
        decoder = _DECODERS.get(coding)
        if decoder is None or (coding == "br" and brotli is None) or (coding == "zstd" and zstd is None):
            raise UndecodableContent(f"unsupported content coding {coding!r}")
        buf = bytearray()
        try:
            decoder(out, buf, limit)
        except _Overflow:
            truncated = True
        except UndecodableContent:
            raise
        except Exception as exc:  # noqa: BLE001 - zlib.error, brotli.error, ZstdError, EOFError ...
            if not truncated:  # (input cut at the cap by an outer stage may end mid-stream: keep the prefix)
                raise UndecodableContent(f"corrupt {coding} data: {exc}") from exc
        out = bytes(buf)
    return out, truncated


def _check(out: bytearray, limit: int) -> None:
    if len(out) > limit:
        del out[limit:]
        raise _Overflow()


def _inflate(d, data: bytes, out: bytearray, limit: int) -> None:
    buf = data
    while True:
        chunk = d.decompress(buf, limit + 1 - len(out))
        out += chunk
        _check(out, limit)
        buf = d.unconsumed_tail
        if d.eof or (not chunk and not buf):
            return


def _trailing(rest: bytes, magic: bytes, coding: str) -> bytes:
    """Returns the next member or b""; zero padding is ignored, any other trailing data is refused."""
    rest = rest.lstrip(b"\0")
    if rest and not rest.startswith(magic):
        raise UndecodableContent(f"unexpected data after the {coding} stream")
    return rest


def _gunzip(data: bytes, out: bytearray, limit: int) -> None:
    rest = data
    while rest:
        d = zlib.decompressobj(32 + zlib.MAX_WBITS)  # gzip or zlib header (as browsers and mitmproxy accept)
        _inflate(d, rest, out, limit)
        if not d.eof:
            return  # truncated final member: the decoded prefix is what a client would see
        rest = _trailing(d.unused_data, b"\x1f\x8b", "gzip")


def _inflate_deflate(data: bytes, out: bytearray, limit: int) -> None:
    if not data:
        return
    wbits = zlib.MAX_WBITS
    try:
        zlib.decompressobj(wbits).decompress(data[:2])  # validates the zlib header, produces no output
    except zlib.error:
        wbits = -zlib.MAX_WBITS  # raw deflate without zlib wrapper, as sent by some servers (browsers accept it)
    d = zlib.decompressobj(wbits)
    _inflate(d, data, out, limit)
    if d.eof and d.unused_data.strip(b"\0"):
        raise UndecodableContent("unexpected data after the deflate stream")


def _unbrotli(data: bytes, out: bytearray, limit: int) -> None:
    if not data:
        return
    d = brotli.Decompressor()
    out += d.process(data, output_buffer_limit=limit + 1 - len(out))
    _check(out, limit)
    while not d.can_accept_more_data():
        chunk = d.process(b"", output_buffer_limit=limit + 1 - len(out))
        out += chunk
        _check(out, limit)
        if not chunk:
            break


def _unzstd(data: bytes, out: bytearray, limit: int) -> None:
    rest = data
    while rest:  # every frame (clients decode concatenated frames); garbage makes the next frame fail
        d = zstd.ZstdDecompressor()
        buf = rest
        while True:
            out += d.decompress(buf, limit + 1 - len(out))
            _check(out, limit)
            if d.eof or d.needs_input:
                break
            buf = b""
        if not d.eof:
            return  # truncated final frame
        rest = d.unused_data


_DECODERS = {"gzip": _gunzip, "deflate": _inflate_deflate, "br": _unbrotli, "zstd": _unzstd}
