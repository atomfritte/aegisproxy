"""Query-string redaction for telemetry, the access log and block pages (policy setting telemetry_query_redaction).

  none       URLs are recorded as requested
  sensitive  values of credential-like parameters are replaced by REDACTED (default, also after an upgrade)
  all        the query string is dropped

Policy evaluation always sees the full URL; only what is recorded or displayed is redacted. The control-plane
applies the same function on ingest (store.RedactURL); both are tested against testdata/redaction_vectors.json.
"""

from __future__ import annotations

import re
import urllib.parse

MODES = ("none", "sensitive", "all")
DEFAULT_MODE = "sensitive"
REDACTED = "REDACTED"

# Parameter names (lowercased, percent-decoded) whose value is always redacted.
SENSITIVE_NAMES = frozenset({
    "token", "access_token", "id_token", "refresh_token", "code", "sig", "signature", "key", "apikey", "api_key",
    "password", "passwd", "pwd", "secret", "client_secret", "session", "sessionid", "session_id", "auth",
    "x-amz-signature", "x-amz-credential", "x-amz-security-token", "x-goog-signature", "x-goog-credential",
    "assertion", "jwt",
})
# A name made of several words (snake_case, kebab-case, camelCase) is redacted when one word is one of these.
SENSITIVE_WORDS = frozenset({"token", "key", "apikey", "secret", "password", "passwd", "signature", "sig", "auth",
                             "session", "sessionid", "credential", "credentials"})
# Redacted only next to the parameter that makes them part of a signed URL: Azure SAS (sig) and CloudFront (Signature
# / Key-Pair-Id).
SAS_NAMES = frozenset({"sv", "se", "sig"})
CLOUDFRONT_NAMES = frozenset({"expires", "key-pair-id", "keypair-id", "policy", "signature"})
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def normalize_mode(mode: object) -> str:
    m = str(mode or "").strip().lower()
    return m if m in MODES else DEFAULT_MODE


def _words(name: str):
    """ASCII words of a parameter name: split at every non-alphanumeric character and at lower→upper case changes."""
    out, cur, prev_lower = [], [], False
    for ch in name:
        if ch.isascii() and ch.isalnum():
            if ch.isupper() and prev_lower and cur:
                out.append("".join(cur))
                cur = []
            cur.append(ch.lower())
            prev_lower = ch.islower() or ch.isdigit()
        else:
            if cur:
                out.append("".join(cur))
            cur, prev_lower = [], False
    if cur:
        out.append("".join(cur))
    return out


def _decoded(raw: str) -> str:
    # Like Go's url.QueryUnescape: a malformed escape leaves the whole name undecoded.
    if _BAD_ESCAPE.search(raw):
        return raw
    return urllib.parse.unquote_plus(raw, errors="replace")


def _lower_ascii(s: str) -> str:
    return "".join(ch.lower() if ch.isascii() else ch for ch in s)


def sensitive_param(name: str, names_present: frozenset = frozenset()) -> bool:
    lname = _lower_ascii(_decoded(name))
    if lname in SENSITIVE_NAMES:
        return True
    if lname in SAS_NAMES and "sig" in names_present:
        return True
    if lname in CLOUDFRONT_NAMES and ({"signature", "key-pair-id", "keypair-id"} & names_present):
        return True
    words = _words(_decoded(name))
    return len(words) > 1 and any(w in SENSITIVE_WORDS for w in words)


def redact_url(url: str, mode: str = DEFAULT_MODE) -> str:
    """Returns ``url`` with its query redacted per ``mode`` (and any user:password@ credentials removed)."""
    mode = normalize_mode(mode)
    if mode == "none" or not url:
        return url
    base, sep, query = url.partition("?")
    base = _strip_userinfo(base)
    if not sep:
        return base
    if mode == "all":
        return base
    parts = query.split("&")
    present = frozenset(_lower_ascii(_decoded(p.partition("=")[0])) for p in parts)
    out = []
    for part in parts:
        name, eq, _value = part.partition("=")
        out.append(f"{name}={REDACTED}" if eq and sensitive_param(name, present) else part)
    return base + "?" + "&".join(out)


def _strip_userinfo(base: str) -> str:
    scheme, sep, rest = base.partition("://")
    if not sep:
        return base
    authority, slash, path = rest.partition("/")
    if "@" not in authority:
        return base
    return f"{scheme}://{REDACTED}@{authority.rpartition('@')[2]}{slash}{path}"
