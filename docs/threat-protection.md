# Threat protection

AegisProxy combines the default-deny whitelist with layered threat protection that also covers
**whitelisted** destinations (a compromised allowed site, a malicious package, a leaked credential).
All settings live in the console under **Threat Protection** and are enforced by every data-plane worker
within seconds.

| Layer | Where | What it stops |
|---|---|---|
| Threat intelligence | control-plane + data-plane | Malware distribution sites, phishing, botnet C2, hijacked netblocks, compromised hosts, known-bad file hashes, custom IOCs, your TIP (TAXII 2.1, MISP) and Microsoft Defender indicators |
| Destination hygiene | both | Cloud metadata / loopback, internal networks, DNS rebinding, IP-literal destinations, non-standard ports, punycode homographs |
| YARA | data-plane | Malware families, droppers, webshells, in-house detections written as YARA rules |
| Antivirus (ClamAV) | data-plane | Malware in downloads (packages, archives, scripts, binaries) |
| Antivirus / sandbox / DLP via ICAP | data-plane → your engine | Downloads scanned by a commercial engine (RESPMOD), uploads inspected by your DLP (REQMOD) |
| Download control | data-plane | Executables, scripts, Office macros, archives … per server group |
| DLP | data-plane | Private keys, cloud/API tokens, card numbers, `/etc/shadow` in outbound requests |
| Protocol guard | data-plane | Raw TCP / SSH tunnels through CONNECT, domain fronting, SNI spoofing, oversized uploads |
| Anomaly detection | control-plane | Bursts of blocked requests (malware beaconing, scanning, misconfiguration) |
| Endpoint signal | control-plane ← Defender | Servers that Defender for Endpoint rates high-risk or isolates are quarantined at the proxy |

Every hit creates a **security event** (deduplicated within 15 minutes, with a counter). High and critical
events are sent to Teams/Slack when *notify security events* is enabled. Events are acknowledged in the
console (audited).

## Threat intelligence

### Built-in feed catalog

| Feed | Type | Default | Notes |
|---|---|---|---|
| URLhaus malware domains (malware-filter mirror) | domains | **on** | CC0, derived from abuse.ch URLhaus |
| abuse.ch Feodo Tracker | IPs | **on** | Botnet C2 (Emotet, QakBot, …) |
| abuse.ch SSLBL | IPs | **on** | C2 servers identified by malicious certificates |
| Spamhaus DROP | CIDRs | **on** | Hijacked netblocks |
| Emerging Threats compromised IPs | IPs | **on** | Proofpoint ET Open |
| Block List Project ransomware | hosts | **on** | Unlicense |
| Phishing domains (malware-filter) | domains | off | Upstream terms (OpenPhish/PhishTank) apply |
| CERT Polska phishing | domains | off | CERT.PL terms |
| Phishing Army | domains | off | CC BY-NC 4.0 (non-commercial) |
| HaGeZi Threat Intelligence Feeds | domains | off | Very large (millions of entries, memory) |
| StevenBlack unified hosts | hosts | off | Ads/tracking — usually too broad for servers |

abuse.ch retired its unauthenticated bulk exports (URLhaus/ThreatFox/MalwareBazaar answer HTTP 410). With an
abuse.ch account they can be added as custom feeds using the `Auth-Key` header option; the key is stored
write-only.

Feeds are downloaded by the control-plane (HTTPS only, conditional GET with ETag/Last-Modified, 96 MiB limit,
HTML error pages rejected, last good copy kept on failure) and compiled into an immutable snapshot that the
workers fetch as gzip with ETag. Supported formats: `domains` (incl. adblock `||domain^`), `hosts`, `urls`,
`ips` (IP/CIDR, Spamhaus format) and `sha256`.

Matching:

- Domains: exact, or domain + subdomains per feed (`match_subdomains`).
- URLs: canonical exact match (lower-case scheme/host, default port removed, fragment dropped).
- IPs/CIDRs: destination IP literals **and every resolved address** of a hostname (checked at connect time).
- SHA-256: every downloaded body that is buffered for inspection.

Modes: `block` (default), `monitor` (allow + event) or `off`.

### TAXII 2.1 and MISP

Connect your threat-intelligence platform (OpenCTI, MISP, Anomali, ThreatConnect, EclecticIQ, a national CERT's
TAXII server, …) as a custom feed in the console (**Threat Protection**, feeds) or with `POST /api/security/feeds`:

| Field | TAXII 2.1 (`format: "taxii21"`) | MISP (`format: "misp"`) |
|---|---|---|
| `url` | collection URL `https://taxii.corp.example/api1/collections/<id>/` (the `objects/` endpoint is appended) | MISP base URL `https://misp.corp.example` |
| `auth_header_name` / `auth_header_value` | e.g. `Authorization` / `Basic …` or `Bearer …` (sent only when a name is set) | default header `Authorization`, value = MISP automation key |
| `lookback_days` | indicators added within this window (default 90, max 3650) | attributes of the last N days (`last`) |
| `ca_cert_pem` | private CA of the server (added to the system trust store) | same |
| `refresh_minutes` | 15 – 10080 | same |
| `match_subdomains` | domain indicators also match subdomains | same |

What is imported:

- **TAXII**: STIX 2.1 `indicator` objects with `pattern_type: stix` that are not revoked and not past
  `valid_until`; equality comparisons on `domain-name:value`, `url:value`, `ipv4-addr:value`, `ipv6-addr:value`
  and `file:hashes.'SHA-256'`. Pagination via `next` or `X-TAXII-Date-Added-Last`.
- **MISP**: `POST /attributes/restSearch` for `to_ids` attributes of the types `domain`, `hostname`, `url`, `uri`,
  `ip-dst`, `ip-src`, `ip-dst|port`, `domain|ip`, `sha256`, `filename|sha256`, with MISP warninglists enforced
  (known-good values are excluded by MISP). Deleted attributes are skipped.
- At most 500,000 indicators per source.

Security: the URL must be `https://` and must not embed credentials. Unlike public feeds, structured sources may
live on **private networks** (on-premises TIPs), but loopback, link-local (cloud metadata), unspecified and
multicast addresses are refused — when saving and again when connecting (DNS rebinding). Redirects are not
followed. The auth value is write-only and encrypted at rest.

Feed downloads (all feeds, including list feeds with an auth header):

- List feeds follow up to five `https://` redirects. The auth header (and any other credential header) is sent
  only to the configured host: a redirect to another host or port carries only `User-Agent`, `Accept`,
  `Accept-Encoding` and the cache validators, so a CDN hand-off works but a compromised or hostile feed server
  cannot pull the key elsewhere. Changing the feed URL to another origin drops the stored auth value.
- Through a forward proxy (`AEGIS_FEED_HTTP_PROXY` or `HTTPS_PROXY`), the proxy resolves the feed host, so the
  connect-time address check cannot run. Before handing a request to the proxy the control plane therefore checks
  the host itself: IP literals and names that resolve (from the control plane) to refused addresses are blocked.
  A name the control plane cannot resolve is left to the proxy — enforce egress rules (no link-local, no internal
  ranges for public feeds) on the proxy as well. The proxy address itself is trusted and may be internal. The same
  rule applies to Teams/Slack notification webhooks behind `HTTPS_PROXY`.

### Microsoft Defender indicators

With the [Defender integration](#microsoft-defender-for-endpoint) and *Import indicators* enabled, the built-in
feed **Microsoft Defender for Endpoint indicators** (`microsoft-defender-indicators`) imports the tenant's custom
indicators whose action is one of `indicator_actions` (default `Block`, `AlertAndBlock`, `BlockAndRemediate`) and
that have not expired: `DomainName`, `Url`, `IpAddress` and `FileSha256`. What the SOC blocks on endpoints is
blocked at the proxy too. Refresh interval: the sync interval, at least 15 minutes.

### Custom IOCs and false positives

- **Indicators**: domain, URL, IP, CIDR or SHA-256 with category, reason and optional expiry.
- **Exceptions**: suppress matches for a domain (incl. subdomains), URL, IP or SHA-256. A SHA-256 exception
  also overrides an antivirus verdict for exactly that file (the event trail is kept as `AV_SUPPRESSED`).
- **Lookup**: check any URL/domain/IP/hash against all active sources.

## Download inspection pipeline

When at least one inspection is active, the worker buffers the response body (up to `av_max_scan_bytes`, which
is therefore the size limit for every engine — compressed and decoded; larger downloads are streamed unscanned
with the flag `AV_UNSCANNED:oversize`, or blocked with `av_oversize_action: block`). A download without
`Content-Length` is buffered chunk by chunk and handled the same way once it outgrows the limit; buffering is
also bounded per worker ([memory sizing](configuration.md#data-plane-memory-sizing), flag `AV_UNSCANNED:busy`
or 503 `inspection_busy` with `block`). The worker decodes the body as described under
[content decoding](#content-decoding) and runs, in this order, stopping at the first block:

1. **Hash** — SHA-256 against threat intelligence (feeds, TAXII/MISP, Defender, custom IOCs).
2. **File type** — magic bytes + URL extension against `blocked_file_types` / `group_blocked_file_types`.
3. **YARA** — the enabled rule sets (first `yara_max_bytes` of the body).
4. **ClamAV** — `INSTREAM` to clamd.
5. **ICAP RESPMOD** — your antivirus / sandbox engine.

A SHA-256 **exception** suppresses YARA, ClamAV and ICAP verdicts for exactly that file (recorded as
`AV_SUPPRESSED`). Verdicts: `MALWARE_BLOCKED` (YARA, ClamAV, ICAP), `FILETYPE_BLOCKED`, `THREAT_BLOCKED`; the
flow records `av_signature` and `av_result`.

### Content decoding

Engines always see the body exactly as the client will after removing its content codings; the bytes on the
wire are delivered unchanged.

- **Request rewriting**: while an inspection applies, the worker reduces the client's `Accept-Encoding` to
  the codings it can decode (`identity`, `gzip`/`x-gzip`, `deflate`, `br`, `zstd`; only codings the client
  offered are kept) and removes `Range` / `If-Range` (flag `RANGE_STRIPPED`), so downloads arrive whole.
- **Decoding**: coding chains (`Content-Encoding: gzip, br`, at most 4) are undone in reverse order, every
  gzip member and zstd frame is decoded, plus non-chunked `Transfer-Encoding` codings. The SHA-256 IOC check
  covers the decoded file and the transferred bytes.
- **Bounded output**: decompression stops at `av_max_scan_bytes`. A larger decoded body (or a
  decompression bomb) is handled like any oversized download: `av_oversize_action: block` blocks it
  (`av_oversize`), `allow` delivers it flagged `AV_UNSCANNED:oversize` after file-type and YARA checks of
  the decoded first `av_max_scan_bytes`. Inflating never allocates more than the limit.
- **Undecodable content is blocked**: an unknown coding (e.g. `compress`), corrupt data or bytes after the
  end of the compressed stream → `POLICY_BLOCKED` with reason `undecodable_content`. Raw bytes are never
  passed to the client unscanned.
- **Partial content**: a `206 Partial Content` response (despite the removed `Range`) is blocked with reason
  `partial_content`: a file split across range requests could never be scanned as a whole.
- **Event streams** (`text/event-stream`) are relayed unbuffered only when no inspection applies to the flow.
  Otherwise they are buffered and scanned like any other response, so a long-lived stream reaches the client
  only when it ends. Destinations that need live, unbounded streams require an explicit decision: a TLS
  passthrough entry for that host (no inspection) instead of a scanning exemption that any allowed site
  could abuse by labelling a download `text/event-stream`.

Without any active inspection nothing is rewritten or blocked; bodies are still decoded (bounded) for the
`content_sha256` / `file_type` telemetry.

## YARA

Write or paste YARA rules in the console (**Threat Protection**, YARA rule sets) or through
`/api/security/yara` (changes: InfoSec and Super Admins; listing: every role). Each rule set has a name, description, source and an enabled switch. Limits: 256 KiB per
set, 2 MiB in total, 100 sets; `include` statements are not supported (paste the included rules).

| Setting | Values | Meaning |
|---|---|---|
| `yara_mode` | `off` (default) · `monitor` · `block` | `monitor` records `AV_FOUND:YARA: <rules>` and a security event, `block` stops the download |
| `yara_max_bytes` | 1 MiB – 2 GiB (default 25 MiB) | bytes of each body that are scanned |

Engine: **YARA-X** (VirusTotal's Rust re-implementation and the official successor of YARA), falling back to
`yara-python`. The data-plane image contains YARA-X, and the Linux and Windows installers install it
(`yara-x==1.22.0` binary wheel) unless `--no-yara` / `-NoYara` is given; with a hash-pinned requirements file
(`--requirements` / `-RequirementsFile`) add `yara-x` to it. Without an engine the status is `unavailable`.

Every rule set is compiled on its own: the console rejects structural errors (missing name or condition,
unbalanced braces, unterminated strings, duplicate rule names) when you save, and if a set still fails on the
data-plane, that set keeps its last working version (or is skipped when it never compiled) while all other
sets stay active. The heartbeat then reports `error:<n> of <m> rule sets failed: <set>: <compiler message>`.

Rules are delivered with the policy bundle and compiled once per change, each set in its own namespace. If a
rule set does not compile, the worker **keeps the previously compiled rules** and reports the error. Each worker
reports its state in the heartbeat (**Settings → Data planes**, `yara_status`): `idle` (no rules), `ok`,
`unavailable` or `error:<compiler message>`. Scan timeouts (10 s) and engine errors are flagged as
`AV_ERROR:yara:…` and do not block. Metrics: `aegis_dp_yara_seconds`, `aegis_dp_yara_matches_total`.

## ICAP (external antivirus, sandbox and DLP engines)

AegisProxy speaks ICAP (RFC 3507) to the engines you already license: Symantec Protection Engine, Kaspersky Scan
Engine, Trend Micro, Sophos SAVDI, ESET, McAfee/Trellix, OPSWAT MetaDefender, Forcepoint and Symantec DLP, or
c-icap with ClamAV.

| Setting (`/api/security/policy`) | Default | Meaning |
|---|---|---|
| `icap_respmod_url` | – (off) | `icap://av.corp.example:1344/<service>` or `icaps://…:11344/<service>`: downloads (step 5 of the pipeline) |
| `icap_reqmod_url` | – (off) | uploads (request bodies of non-GET requests) for DLP / upload scanning |
| `icap_mode` | `block` | `block` or `monitor` (flag + security event only) |
| `icap_fail_mode` | `open` | `open`: allow and flag `AV_ERROR:icap…`; `closed`: answer 503 when the engine is unreachable, times out, answers with an error or a malformed response, or the URL is invalid |
| `icap_timeout_seconds` | 30 | 1 – 600; one deadline for the whole exchange (connect, sending the body, response) |
| `icap_max_bytes` | 25 MiB | larger bodies are not sent (`ICAP_UNSCANNED:oversize`; downloads are blocked when `av_oversize_action` is `block`, uploads when `dlp_oversize_action` is `block`) |
| `icap_allow_modified` | `true` | deliver content the engine sanitized (content disarm and reconstruction) — for downloads and for uploads (REQMOD: the sanitized body is sent upstream with a recomputed `Content-Length`, never the original); otherwise such content is blocked in `block` mode |
| `icap_tls_skip_verify` / `icap_ca_cert_pem` | `false` / – | TLS verification for `icaps://` |

How results are interpreted: ICAP `204` or an unmodified `200` = clean; a threat header (`X-Infection-Found`,
`X-Virus-ID`, `X-Violations-Found`, `X-Virus-Name`, `X-Blocked-Reason`) or an encapsulated HTTP status ≥ 400 =
infected (for REQMOD any encapsulated HTTP response means the engine blocked the upload); a changed body =
sanitized. The threat name becomes the signature of the flow and security event.

Privacy: requests sent to the engine never contain `Authorization`, `Proxy-Authorization` or `Cookie` headers,
and responses never contain `Set-Cookie`. Bodies are sent decoded (see [content decoding](#content-decoding))
with exactly one, recomputed `Content-Length`.

REQMOD runs for every upload whenever `icap_reqmod_url` is set, independently of the built-in detectors
(`dlp_mode`); infected uploads are recorded as DLP findings (`icap:<threat>`, verdict `DLP_BLOCKED` in `block`
mode, event source `ICAP DLP`).

Each worker probes a newly configured service with `OPTIONS` within seconds and then every 60 seconds; real
scans update the state as well (a refused connection marks the service `down` immediately). It reports `icap_status`
(`disabled`, or e.g. `respmod=ok,reqmod=down`) in its heartbeat (**Settings → Data planes**). Metrics:
`aegis_dp_icap_seconds`, `aegis_dp_icap_scans_total{mode,result}`.

Quick test: c-icap with its `virus_scan` module and ClamAV (`icap://c-icap.corp.example:1344/avscan`), then
download the EICAR test file through the proxy.

## Antivirus (ClamAV)

The worker streams buffered response bodies to clamd via `INSTREAM`. Configure:

- `av_max_scan_bytes` (default 25 MiB) — keep in line with clamd `StreamMaxLength`.
- `av_oversize_action` — `allow` (stream unscanned, flagged) or `block`.
- `av_fail_mode` — `open` (allow, `AV_ERROR` event) or `closed` (503) when clamd is unavailable or times out.
- `av_mode` — `block` or `monitor`.

Large archives can take a while to scan (≈ 25 s for a 6 MB source tarball in our tests); the client waits for
the verdict. Tune `AEGIS_CLAMD_TIMEOUT_SECONDS` and clamd's `MaxScanTime` accordingly.

## Download control

`blocked_file_types` (global) and `group_blocked_file_types` (per server group) use magic-byte detection plus
URL extensions: `pe`, `elf`, `macho`, `java_class`, `msi_ole`, `script`, `jar`, `apk`, `zip`, `archive`,
`office_macro`, `iso`. Example: block `pe`, `elf`, `script` for the database tier, allow `archive` for CI.

## Data loss prevention

Scans URL query strings and the complete decoded request body up to `dlp_max_scan_bytes` (default 1 MiB).
Bytes beyond the limit are never skipped silently: the upload is flagged `DLP_UNSCANNED:oversize` and, with
`dlp_oversize_action: block`, rejected with 413 (`dlp_oversize`). The same applies to uploads above
`icap_max_bytes` when ICAP REQMOD is configured (`ICAP_UNSCANNED:oversize`). Uploads larger than the worker's
upload buffer (see [memory sizing](configuration.md#data-plane-memory-sizing)) are either rejected
(`dlp_oversize_action: block`) or streamed unscanned with the same flags; their query string is still scanned
before anything is sent. Compressed uploads (`Content-Encoding`) are decoded first, bounded like downloads; an
upload with an undecodable coding is blocked (`undecodable_content`) when `dlp_mode` or the ICAP REQMOD
`icap_mode` is `block`, otherwise flagged `DLP_UNSCANNED:undecodable`. Authorization headers are deliberately not scanned — servers legitimately
authenticate to APIs. Start in `monitor` mode, review events,
then switch to `block`. An enterprise DLP engine can additionally inspect uploads through
[ICAP REQMOD](#icap-external-antivirus-sandbox-and-dlp-engines).

## Protocol and destination hygiene

- `block_raw_tcp`: no non-HTTP protocols through CONNECT.
- `allowed_ports` (default 80/443).
- `block_ip_literals`: IP destinations need an explicit rule.
- `block_private_destinations`: internal ranges/suffixes need an explicit, non-wildcard rule; resolved
  addresses are vetted and pinned (DNS rebinding). Loopback, link-local and metadata addresses are always
  blocked.
- `punycode_mode`: monitor or block IDN host names.
- `max_upload_bytes`: hard cap for request bodies.
- `Host` header and TLS SNI must match the real destination (domain fronting); host names must be DNS names
  or IP literals (`malformed_host` otherwise).
- **Destination binding in transparent, SOCKS5 and reverse modes**: there the connection already goes to an
  address chosen by the client, while policy is evaluated for its `Host` header / SNI. The worker trusts the
  name only if the original destination IP is one of the name's DNS answers (same resolver as for upstream
  connections; answers are cached and merged for 30 s, a miss is re-resolved once). Otherwise the request is
  blocked (`host_mismatch`, `sni_mismatch`). A public name bound to an internal address is blocked as DNS
  rebinding (`dns_rebinding`), and loopback/link-local destinations are always refused — also for literal
  IP destinations. TLS passthrough is granted only after the SNI is bound to the destination IP; otherwise
  the connection is intercepted and every request is evaluated. The mode is taken from the listener the
  client connected to (`--mode`), `AEGIS_PROXY_MODE` is the fallback. Split-horizon DNS between clients and
  workers can cause false `host_mismatch` blocks: point both at the same resolvers.

### Fail-closed enforcement

Every mitmproxy hook of the worker fails closed. If the policy code raises an exception (a bug, hostile
input), the request is answered with `403` (`503` for infrastructure errors such as an unreachable engine),
the CONNECT is refused, the upstream connection is not opened, a TLS connection is intercepted instead of
passed through (its requests are then blocked), or a raw relay is killed. The flow is recorded with
`block_reason: internal_error`, the traceback is logged and `aegis_dp_hook_errors_total{hook}` is
incremented — alert on it. A request that reaches the body, response-header or response stage without a
completed evaluation is blocked as `unevaluated`. Untrusted bytes in credentials, `Host` and URLs are
hashed and rendered safely (percent-encoded in pages, logs and telemetry).

## Anomaly detection

`blocked_burst_threshold` (default 30/min per server) raises a `BLOCK_BURST` event — typical for malware
beaconing to C2 domains, worm-like scanning or broken deployments.

## Quarantine (incident response)

A server suspected to be compromised can be **quarantined** from the console (Servers → server → Quarantine)
or the API. Every request of that server is then denied with the verdict `QUARANTINED` before any other check —
including whitelisted destinations, TLS exceptions and learning sessions. The block page offers no
self-service, each attempt is recorded as a `QUARANTINE` security event, and Teams/Slack are notified. Team
Leads may quarantine servers of their groups; releasing requires InfoSec. Combine it with the
`BLOCK_BURST` anomaly events and the threat-intelligence hits to contain beaconing malware within seconds.

Automation:

- **SOAR / EDR playbooks** quarantine by host name or IP without knowing AegisProxy server IDs:
  `POST /api/servers/quarantine {"hostname": "web-17.corp.example", "reason": "INC-4711"}` (or `"ip"`;
  `"quarantined": false` releases). Authenticate with a [service account](identity.md#service-accounts); the
  Sentinel package ships a Logic App playbook for it (`deploy/sentinel/playbooks/quarantine-host.json`).
- **Microsoft Defender for Endpoint** quarantines automatically by device risk or isolation (next section).

## Microsoft Defender for Endpoint

**Settings → Integrations → Microsoft Defender** (`/api/integrations/defender`; Super Admins edit, InfoSec can
view, test and trigger a sync).

Setup:

1. Entra ID **app registration** (single tenant) with a client secret.
2. **API permissions → APIs my organization uses → WindowsDefenderATP → Application permissions**, then grant
   admin consent:

   | Permission | Needed for |
   |---|---|
   | `Ti.ReadWrite.All` | indicator import. The List Indicators API has no read-only permission; with `Ti.ReadWrite` an app only sees the indicators it created. AegisProxy only reads. |
   | `Machine.Read.All` | device sync (risk score, exposure, health) |
   | `Machine.ReadWrite.All` | only for `quarantine_on_isolation`: List MachineActions requires it. AegisProxy never starts machine actions; leave the option off to stay with `Machine.Read.All`. |

3. In AegisProxy: tenant ID, client ID, client secret (write-only, encrypted at rest) and the cloud. The stored
   secret stays with its tenant, client ID and endpoints: a save that changes any of them without a new secret is
   refused (*re-enter the client secret for the new destination*); clearing tenant or client ID drops it.

   | Cloud | `api_base_url` | `authority_url` | Token scope (set automatically) |
   |---|---|---|---|
   | Commercial (default) | `https://api.security.microsoft.com` or a regional host (`eu.`, `us.`, `uk.`, `au.api.security.microsoft.com` …); `https://api.securitycenter.microsoft.com` keeps working | `https://login.microsoftonline.com` | `https://api.securitycenter.microsoft.com/.default` (Microsoft requires this legacy audience for every commercial host) |
   | US Government GCC | `https://api-gcc.securitycenter.microsoft.us` | `https://login.microsoftonline.com` | `https://api-gcc.securitycenter.microsoft.us/.default` |
   | US Government GCC High / DoD | `https://api-gov.securitycenter.microsoft.us` | `https://login.microsoftonline.us` (default for this host) | `https://api-gov.securitycenter.microsoft.us/.default` |

   **Test** reports the number of indicators and devices or the permission error. Collections are read in pages
   of 10,000 (`$top`/`$skip`, the documented maximum); throttling (HTTP 429, 100 calls per minute and 1,500 per
   hour per API) is waited out according to `Retry-After`; a tenant without recent devices (HTTP 404) counts as
   zero devices.

| Option | Meaning |
|---|---|
| `import_indicators` + `indicator_actions` | import custom indicators as a threat-intel feed ([above](#microsoft-defender-indicators)) |
| `device_sync`, `sync_minutes` (default 5) | match Defender devices to registered servers by FQDN, unique short name or last IP; the server page shows risk score, exposure level, health, isolation and last seen. In a cluster one replica syncs per interval. |
| `quarantine_on_risk` | `off` (default), `high` or `medium` (= medium and above): quarantine matching servers automatically |
| `quarantine_on_isolation` | quarantine servers whose latest Defender action is a successful *Isolate* |
| `auto_release` | release the quarantine when the condition clears — **only** quarantines that the integration set itself (`quarantined_by: microsoft-defender`); manual quarantines are never released automatically |

Automatic actions are audited with the actor `microsoft-defender` (`SERVER_QUARANTINED` / `SERVER_RELEASED`) and
notified like manual quarantines. The client only follows pagination links on the configured API host, so the
bearer token cannot leak to other hosts. Last sync time, device and match counts and errors are shown on the
settings page.

## Block pages

Blocks are explained to people and tools with a block page (browsers) or a plain-text message (CLI
clients such as `curl`, `apt`, `pip`, `git`). Both are customizable per server group with **block page
templates** (branding, texts in English/German, support contacts, links, offered self-service scopes and
durations) — see [policy-management.md](policy-management.md#block-pages). Threat-protection and quarantine
blocks always use the variant without a request form. Pages are served with a strict per-response nonce
CSP and `X-Content-Type-Options: nosniff`; all request values are HTML-escaped by the worker.
