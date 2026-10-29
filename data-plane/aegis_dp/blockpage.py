"""Block responses: browser HTML page and terminal (CLI) message."""

from __future__ import annotations

import html
import json
import re
import secrets
import shlex
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .policy import VERDICT_AUTH_FAILED, VERDICT_POLICY, SECURITY_VERDICTS

CLI_USER_AGENTS = ("curl/", "wget/", "git/", "apt-http/", "pip/", "python-requests/", "python-urllib/", "go-http-client/",
                   "containerd/", "docker/", "helm/", "npm/", "yarn/", "maven/", "gradle/", "powershell", "winhttp", "libwww-perl")


def is_cli_client(user_agent: str, accept: str) -> bool:
    ua = (user_agent or "").lower()
    if any(t in ua for t in CLI_USER_AGENTS):
        return True
    return "text/html" not in (accept or "").lower()


def _clean(v: str) -> str:
    # Control characters are dropped; lone surrogates (undecodable request bytes) become U+FFFD so the page
    # can always be encoded.
    return "".join(ch if not "\ud800" <= ch <= "\udfff" else "�" for ch in (v or "") if ch >= " " and ch != "\x7f")


def _csp(nonce: str, public_url: str) -> str:
    origin = public_url or "'none'"
    return (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src {origin}; "
            f"img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")


def self_service_allowed(verdict: str) -> bool:
    """Threat-protection blocks (malware, C2, DLP...) and failed proxy authentication are not eligible for
    self-service whitelisting."""
    return verdict not in SECURITY_VERDICTS or verdict == VERDICT_POLICY


AUTH_FAILED_HELP = (
    "The proxy credentials sent by this client (Proxy-Authorization) are not valid: the token is unknown, was\n"
    "    rotated or is mistyped, the username does not belong to it, or this server's group requires the proxy\n"
    "    token. The request was not attributed to the source address. Set the proxy URL of this server to\n"
    "    http://<proxy-user>:<proxy-token>@<proxy-host>:<port> with the token shown when the server was onboarded\n"
    "    (console: Servers -> server -> Rotate token issues a new one), or remove the credentials if this server\n"
    "    is identified by its address."
)


def ca_install_steps(base: str, prefix: str = "/api/public/ca") -> str:
    """CA installer steps of the terminal messages (the control-plane's blockpage.CLICAInstallSteps). The installer is
    downloaded into a fresh private directory and exactly that file runs after the SHA-256 comparison: never a fixed
    name in a shared or the current directory, where another local user could swap it between the check and the run."""
    return (
        f"    Linux:   d=$(mktemp -d); curl -fsSLo \"$d/aegis-ca-install.sh\" {base}{prefix}/install-linux.sh"
        " && sha256sum \"$d/aegis-ca-install.sh\"\n"
        "             sudo bash \"$d/aegis-ca-install.sh\"; rm -rf \"$d\"\n"
        "    Windows: $d = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('aegis-ca-' + [guid]::NewGuid()));"
        " $f = Join-Path $d.FullName 'aegis-ca-install.ps1'\n"
        f"             iwr -UseBasicParsing {base}{prefix}/install-windows.ps1 -OutFile $f; Get-FileHash $f -Algorithm SHA256\n"
        "             powershell -NoProfile -ExecutionPolicy Bypass -File $f; Remove-Item -Recurse $d.FullName\n"
    )


def render_cli(ctx: Dict[str, str], groups: List[str]) -> str:
    public = ctx["public_url"]
    payload = json.dumps({"block_token": ctx["block_token"], "requester": f"root@{_clean(ctx['server_hostname'])}",
                          "reason": "ENTER_REASON_HERE", "requested_scope": "prefix_with_objects", "duration": "24h"})
    if ctx["verdict"] == VERDICT_AUTH_FAILED:
        action = f" 🔑 {AUTH_FAILED_HELP}\n"
    elif self_service_allowed(ctx["verdict"]):
        action = (
            " 🚀 1. REQUEST ACCESS IN BROWSER (Self-Service Block Portal):\n"
            f"    {ctx['dashboard_url']}/?portal=block&bt={urllib.parse.quote(ctx['block_token'])}\n\n"
            " 💻 2. REQUEST ACCESS DIRECTLY VIA CLI (Headless Server One-Liner):\n"
            f"    curl -sX POST {public}/api/public/requests \\\n"
            "      -H \"Content-Type: application/json\" \\\n"
            f"      -d {shlex.quote(payload)}\n"
        )
    else:
        action = (" ⛔ This destination was blocked by threat protection. Self-service requests are disabled;\n"
                  "    contact InfoSec with the Trace ID above if you believe this is a false positive.\n")
    return (
        "================================================================================\n"
        f" 🛡️  AEGISPROXY ENTERPRISE ZERO-TRUST GATEWAY — ACCESS BLOCKED (HTTP {ctx['status']})\n"
        "================================================================================\n"
        f" Server Hostname : {_clean(ctx['server_hostname'])} ({_clean(ctx['server_ip'])})\n"
        f" Server Groups   : {', '.join(groups) if groups else 'unassigned'}\n"
        f" Blocked URL     : [{_clean(ctx['method'])}] {_clean(ctx['url'])}\n"
        f" Trace ID        : {_clean(ctx['trace_id'])}\n"
        f" Policy Verdict  : {_clean(ctx['verdict'])} — {_clean(ctx['reason'])}\n"
        "--------------------------------------------------------------------------------\n"
        f"{action}\n"
        " 🔐 3. INSTALL SSL/TLS ROOT CA CERTIFICATE ON THIS SERVER (compare the installer's SHA-256 with\n"
        "    the AegisProxy console, TLS & CA, before running it):\n"
        f"{ca_install_steps(public)}"
        "================================================================================\n"
    )


def render_stale(ctx: Dict[str, str], cli: bool) -> Tuple[str, str]:
    """503 while the worker's policy is older than AEGIS_POLICY_MAX_AGE: (body, csp). Nothing to request — the
    worker blocks every destination until it can sync with the control-plane again."""
    text = (f"The security policy of this proxy worker is out of date (last successful update {ctx['age']} ago, "
            f"maximum {ctx['max_age']}). Every request is blocked until it can reach the control-plane again "
            "(fail-closed). Retry in a few minutes; if this persists, contact the proxy operators with the trace ID.")
    if cli:
        return (
            "================================================================================\n"
            " 🛡️  AEGISPROXY — POLICY STALE, REQUEST BLOCKED (HTTP 503)\n"
            "================================================================================\n"
            f" {text}\n"
            f" Blocked URL : [{_clean(ctx['method'])}] {_clean(ctx['url'])}\n"
            f" Trace ID    : {_clean(ctx['trace_id'])}\n"
            "================================================================================\n"
        ), ""
    nonce = secrets.token_urlsafe(16)
    e = {k: html.escape(_clean(str(v))) for k, v in ctx.items()}
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>AegisProxy: policy out of date</title><style nonce="{nonce}">{_STYLE}</style></head>
<body><div class="c"><div class="card">
<span class="badge">🛡️ AEGISPROXY • HTTP 503 POLICY STALE</span>
<h1>Outbound access temporarily blocked</h1>
<p>{html.escape(text)}</p>
<div class="grid">
<div><label>Blocked URL</label><span>[{e['method']}] {e['url']}</span></div>
<div><label>Trace ID</label><span>{e['trace_id']}</span></div>
</div></div></div></body></html>"""
    return page, _csp(nonce, "")


_STYLE = """
:root{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--accent:#2563eb;--danger:#dc2626;--text:#0f172a;--muted:#64748b}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#111a2e;--border:#24324d;--text:#e2e8f0;--muted:#94a3b8}}
*{box-sizing:border-box;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
body{margin:0;background:var(--bg);color:var(--text);padding:32px 16px}
.c{max-width:860px;margin:0 auto}.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:24px;margin-bottom:18px}
.badge{display:inline-block;padding:6px 12px;border-radius:999px;background:#fef2f2;color:var(--danger);font-weight:600;font-size:12px;border:1px solid #fecaca}
h1{font-size:21px;margin:14px 0 6px}p{color:var(--muted);font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:16px 0;padding:14px;border:1px solid var(--border);border-radius:10px}
.grid label{display:block;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:600;margin-bottom:4px}
.grid span{font-family:ui-monospace,Menlo,monospace;font-size:13px;word-break:break-all}
.f{display:block;font-size:13px;font-weight:600;margin:14px 0 6px}
input,select,textarea{width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font-size:14px}
button{margin-top:16px;width:100%;padding:12px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-weight:600;cursor:pointer}
pre{background:#0f172a;color:#f8fafc;padding:12px;border-radius:8px;overflow-x:auto;font-size:12px}
.h2{font-size:17px;margin-top:0}a{color:var(--accent)}#st{display:none;margin-top:14px;padding:12px;border-radius:8px;border:1px solid var(--border)}
"""


def render_html(ctx: Dict[str, str], groups: List[str]) -> Tuple[str, str]:
    """Returns (html, content-security-policy). Untrusted values are HTML-escaped; data for the
    script is passed through a JSON data island, never interpolated into JavaScript."""
    nonce = secrets.token_urlsafe(16)
    e = {k: html.escape(_clean(str(v))) for k, v in ctx.items()}
    data = json.dumps({"endpoint": ctx["public_url"] + "/api/public/requests", "block_token": ctx["block_token"]}).replace("<", "\\u003c")
    portal = html.escape(f"{ctx['dashboard_url']}/?portal=block&bt={urllib.parse.quote(ctx['block_token'])}")
    if ctx["verdict"] == VERDICT_AUTH_FAILED:
        form = f"<p><strong>Proxy authentication failed.</strong> {html.escape(' '.join(AUTH_FAILED_HELP.split()))}</p>"
        script = ""
    elif self_service_allowed(ctx["verdict"]):
        form = f"""
      <form id="rq">
        <label class="f" for="requester">Your name / email / change ticket</label>
        <input id="requester" required maxlength="200" placeholder="alex.miller@corp.example (CHG-10492)">
        <label class="f" for="scope">Requested scope</label>
        <select id="scope">
          <option value="prefix_with_objects">Path prefix + linked redirect objects ({e['suggested']})</option>
          <option value="exact_path">Exact URL path only</option>
          <option value="domain">Entire domain ({e['suggested_host']})</option>
          <option value="learning_session_15m">15-minute learning session for this server</option>
        </select>
        <label class="f" for="duration">Duration</label>
        <select id="duration"><option value="24h">24 hours</option><option value="1h">1 hour</option><option value="7d">7 days</option><option value="permanent">Permanent</option></select>
        <label class="f" for="reason">Business / technical justification</label>
        <textarea id="reason" rows="3" required maxlength="2000"></textarea>
        <button type="submit">Submit access request</button>
      </form>
      <div id="st" role="status"></div>
      <p>Prefer the console? <a href="{portal}" rel="noopener noreferrer">Open the self-service portal</a>.</p>"""
        script = f"""<script nonce="{nonce}">
(function(){{var d=JSON.parse(document.getElementById('aegis-data').textContent);var f=document.getElementById('rq'),s=document.getElementById('st');
f.addEventListener('submit',function(ev){{ev.preventDefault();s.style.display='block';s.textContent='Submitting…';
fetch(d.endpoint,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{block_token:d.block_token,
requester:document.getElementById('requester').value,requested_scope:document.getElementById('scope').value,
duration:document.getElementById('duration').value,reason:document.getElementById('reason').value}})}})
.then(function(r){{return r.json().then(function(j){{s.textContent=(r.ok?'✅ ':'❌ ')+(j.message||j.error||'')+(j.request?' (Request ID: '+j.request.id+')':'');}});}})
.catch(function(err){{s.textContent='❌ '+err.message;}});}});}})();
</script>"""
    else:
        form = "<p><strong>This destination was blocked by threat protection.</strong> Self-service whitelisting is not available. Contact InfoSec and quote the trace ID if you believe this is a false positive.</p>"
        script = ""
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Blocked by AegisProxy</title><style nonce="{nonce}">{_STYLE}</style></head>
<body><div class="c"><div class="card">
<span class="badge">🛡️ AEGISPROXY • HTTP {e['status']} {e['verdict']}</span>
<h1>{'Proxy authentication failed' if ctx['verdict'] == VERDICT_AUTH_FAILED else 'Outbound access blocked by policy'}</h1>
<p>{e['reason']}</p>
<div class="grid">
<div><label>Server</label><span>{e['server_hostname']} ({e['server_ip']})</span></div>
<div><label>Server groups</label><span>{html.escape(', '.join(groups) or 'unassigned')}</span></div>
<div><label>Blocked URL</label><span>[{e['method']}] {e['url']}</span></div>
<div><label>Trace ID</label><span>{e['trace_id']}</span></div>
</div>{form}
</div>
<div class="card"><h2 class="h2">Enterprise Root CA</h2>
<p>Install the AegisProxy root certificate to avoid TLS errors on this server. Compare the installer's SHA-256
with the AegisProxy console (TLS &amp; CA) before running it:</p>
<pre>d=$(mktemp -d)
curl -fsSLo "$d/aegis-ca-install.sh" {e['public_url']}/api/public/ca/install-linux.sh
sha256sum "$d/aegis-ca-install.sh"
sudo bash "$d/aegis-ca-install.sh"; rm -rf "$d"

# Windows (admin)
$d = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('aegis-ca-' + [guid]::NewGuid())); $f = Join-Path $d.FullName 'aegis-ca-install.ps1'
iwr -UseBasicParsing {e['public_url']}/api/public/ca/install-windows.ps1 -OutFile $f
Get-FileHash $f -Algorithm SHA256
powershell -NoProfile -ExecutionPolicy Bypass -File $f; Remove-Item -Recurse $d.FullName</pre>
<p><a href="{e['public_url']}/api/public/ca/aegis-ca.crt">Download CA (PEM)</a> · <a href="{e['public_url']}/api/public/ca/aegis-ca.der">Download CA (DER)</a></p>
</div></div>
<script type="application/json" id="aegis-data">{data}</script>
{script}
</body></html>"""
    return page, _csp(nonce, ctx["public_url"])


# ---------------------------------------------------------------------------
# Branded templates (rendered by the control-plane into shells, see internal/blockpage)
# ---------------------------------------------------------------------------

_PH_RE = re.compile(r"%%AEGIS:([a-z_]+)%%")
_LOGO_RE = re.compile(r"^data:image/(png|jpeg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/]+={0,2}$")
_RAW_KEYS = {"nonce", "data_json", "logo"}


def pick_locale(accept_language: str, available: Iterable[str], default: str) -> str:
    """Best supported language from an Accept-Language header (q-values honoured)."""
    avail = list(available)
    prefs = []
    for i, part in enumerate((accept_language or "").split(",")[:20]):
        tag, _, params = part.strip().partition(";")
        q = 1.0
        for p in params.split(";"):
            k, _, v = p.strip().partition("=")
            if k == "q":
                try:
                    q = float(v)
                except ValueError:
                    q = 0.0
        lang = tag.strip().lower().split("-")[0]
        if lang and q > 0:
            prefs.append((-q, i, lang))
    for _, _, lang in sorted(prefs):
        if lang in avail:
            return lang
    if default in avail:
        return default
    return avail[0] if avail else "en"


def select_template(block_pages: Dict[str, Any], groups: List[str]) -> Optional[Dict[str, Any]]:
    templates = block_pages.get("templates") or {}
    mapping = block_pages.get("group_templates") or {}
    for g in groups:
        tid = mapping.get(g)
        if tid and tid in templates:
            return templates[tid]
    return templates.get(block_pages.get("default_template_id") or "")


def fill(shell: str, values: Dict[str, str], html_mode: bool) -> str:
    """Single-pass placeholder substitution (substituted values are never re-scanned)."""
    def sub(m: "re.Match[str]") -> str:
        key = m.group(1)
        val = values.get(key, "")
        if html_mode and key in _RAW_KEYS:
            return val
        val = _clean(val)
        return html.escape(val, quote=True) if html_mode else val
    return _PH_RE.sub(sub, shell)


def render_branded(block_pages: Dict[str, Any], ctx: Dict[str, str], groups: List[str], accept_language: str,
                   cli: bool) -> Optional[Tuple[str, str]]:
    """Returns (body, csp) from the bundle's template shells, or None to use the built-in page."""
    if ctx["verdict"] == VERDICT_AUTH_FAILED:
        return None  # templates explain blocks; a 407 needs the built-in credentials help
    tpl = select_template(block_pages or {}, groups)
    if not tpl:
        return None
    by_locale = tpl.get("shells") or {}
    if not by_locale:
        return None
    locale = pick_locale(accept_language, by_locale.keys(), tpl.get("default_locale") or "en")
    variant = "request" if self_service_allowed(ctx["verdict"]) else "threat"
    shell = (by_locale.get(locale) or {}).get(f"{variant}_{'cli' if cli else 'html'}")
    if not shell:
        return None
    token = ctx["block_token"]
    scopes = tpl.get("allowed_scopes") or ["prefix_with_objects"]
    durations = tpl.get("allowed_durations") or ["24h"]
    payload = json.dumps({"block_token": token, "requester": f"root@{_clean(ctx['server_hostname'])}", "reason": "ENTER_REASON_HERE",
                          "requested_scope": scopes[0], "duration": durations[0]})
    nonce = secrets.token_urlsafe(16)
    logo = tpl.get("logo") or ""
    if logo and not _LOGO_RE.match(logo):
        logo = ""
    values = {k: str(v) for k, v in ctx.items()}
    values.update({
        "groups": ", ".join(groups) or "unassigned",
        "portal_url": f"{ctx['dashboard_url']}/?portal=block&bt={urllib.parse.quote(token)}",
        "nonce": nonce,
        "data_json": json.dumps({"endpoint": ctx["public_url"] + "/api/public/requests", "block_token": token}).replace("<", "\\u003c"),
        "logo": logo,
        "cli_payload": shlex.quote(payload),
    })
    body = fill(shell, values, not cli)
    return body, ("" if cli else _csp(nonce, ctx["public_url"]))
