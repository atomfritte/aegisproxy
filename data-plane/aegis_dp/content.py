"""Content inspection: DLP secret detectors and file-type (magic byte) classification."""

from __future__ import annotations

import re
import struct
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# DLP — credentials / secrets in outbound requests
# ---------------------------------------------------------------------------

_DETECTORS = {
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    "aws_access_key": re.compile(rb"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(rb"(?i)aws_?secret_?access_?key[\"'\s:=]+[A-Za-z0-9/+]{40}\b"),
    "github_token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    "gitlab_token": re.compile(rb"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    "slack_token": re.compile(rb"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    "slack_webhook": re.compile(rb"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    "google_api_key": re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe_key": re.compile(rb"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"),
    "azure_storage_key": re.compile(rb"AccountKey=[A-Za-z0-9+/=]{86,88}"),
    "npm_token": re.compile(rb"\bnpm_[A-Za-z0-9]{36}\b"),
    "pypi_token": re.compile(rb"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"),
    "unix_shadow": re.compile(rb"(?m)^[a-z_][a-z0-9_-]{0,31}:\$(?:1|2[aby]?|5|6|y|7)\$[^:\s]{8,}:\d*:"),
}
_PAN = re.compile(rb"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _has_card_number(data: bytes) -> bool:
    for m in _PAN.finditer(data):
        digits = re.sub(rb"[ -]", b"", m.group(0)).decode()
        if 13 <= len(digits) <= 19 and digits[0] in "3456" and _luhn_ok(digits) and len(set(digits)) > 1:
            return True
    return False


def scan_dlp(chunks: Iterable[bytes], enabled: Iterable[str]) -> List[str]:
    """Return the IDs of detectors that matched any of the given byte strings."""
    enabled = set(enabled)
    found: List[str] = []
    for data in chunks:
        if not data:
            continue
        for name, rx in _DETECTORS.items():
            if name in enabled and name not in found and rx.search(data):
                found.append(name)
        if "credit_card" in enabled and "credit_card" not in found and _has_card_number(data):
            found.append("credit_card")
    return found


# ---------------------------------------------------------------------------
# File-type detection (magic bytes + URL extension)
# ---------------------------------------------------------------------------

_SCRIPT_EXT = {".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py", ".pl"}
_EXT_TYPES = {".exe": "pe", ".dll": "pe", ".scr": "pe", ".sys": "pe", ".msi": "msi_ole", ".jar": "jar", ".apk": "apk",
              ".iso": "iso", ".docm": "office_macro", ".xlsm": "office_macro", ".pptm": "office_macro"}


def detect_file_type(body: bytes, url: str = "", content_type: str = "") -> Optional[str]:
    head = body[:4096]
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if head.startswith(b"\xca\xfe\xba\xbe") and len(head) >= 8:
        # Shared magic: Mach-O fat binary (small arch count) vs. Java class (major version >= 45).
        return "macho" if struct.unpack(">I", head[4:8])[0] < 40 else "java_class"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "msi_ole"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith(b"PK\x03\x04"):
        sample = body[: 2 * 1024 * 1024]
        if b"vbaProject.bin" in sample:
            return "office_macro"
        if b"AndroidManifest.xml" in sample or b"classes.dex" in sample:
            return "apk"
        if b"META-INF/MANIFEST.MF" in sample:
            return "jar"
        return "zip"
    if head.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")):
        return "archive"
    if len(body) > 0x8006 and body[0x8001:0x8006] == b"CD001":
        return "iso"
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        path = ""
    ext = path[path.rfind("."):] if "." in path.rsplit("/", 1)[-1] else ""
    if ext in _EXT_TYPES:
        return _EXT_TYPES[ext]
    if ext in _SCRIPT_EXT and not content_type.lower().startswith("text/html"):
        return "script"
    return None
