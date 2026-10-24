# Threat model

STRIDE-based threat model of AegisProxy 2.1. It lists what an attacker would target, the trust boundaries, the
implemented mitigations and the risks that remain with the operator. Review it when you change the deployment
topology or add integrations.

## Assets

| Asset | Why it matters |
|---|---|
| Interception CA private key | Anyone holding it can impersonate every TLS site to servers that trust the CA |
| Egress policy (policy sets, groups, TLS exceptions, quarantine state) | Decides what servers may reach; a malicious change opens exfiltration paths |
| Credentials: user passwords, sessions, service-account keys, proxy tokens, `AEGIS_JWT_SECRET`, `AEGIS_DATAPLANE_KEY`, `AEGIS_ENCRYPTION_KEY`, integration secrets (SSO, Defender, feeds, SIEM) | Grant control over the console, the workers or connected systems |
| Audit trail | Accountability and forensic evidence |
| Traffic content and metadata | URLs, headers and bodies of server traffic (may contain secrets and personal data) |
| Availability of the egress path | Servers depend on it for updates, package installs and APIs |

## Trust boundaries

```
 servers ──(1)──▶ data-plane ──(2)──▶ internet / ICAP engines
                     │ (3)
 console users ─(4)─▶ control-plane ──(5)──▶ IdP · SIEM · Defender · TAXII/MISP · feeds · webhooks
 automation ───(4)──▶      │ (6)
                       file storage / PostgreSQL
```

| # | Boundary | Authentication / protection |
|---|---|---|
| 1 | Servers → data-plane | Source IP/CIDR or per-server proxy token (SHA-256 stored); unregistered sources get no group membership; default deny |
| 2 | Data-plane → internet / ICAP | Upstream certificate validation always on, TLS ≥ 1.2, DNS-rebinding protection with IP pinning; `icaps://` with verification; credentials stripped before ICAP |
| 3 | Data-plane ↔ control-plane | Shared data-plane key (≥ 32 characters, constant-time comparison), HTTPS recommended (`AEGIS_CONTROL_PLANE_CA_FILE`) |
| 4 | Users and automation → control-plane | Session cookie (HttpOnly, SameSite=Strict, revocable JWT) or service-account key; CSRF header + Origin check; RBAC on every request |
| 5 | Control-plane → external services | HTTPS, SSRF guards, optional private CA, write-only encrypted credentials |
| 6 | Control-plane → storage | File mode: 0600 files, atomic writes; cluster: PostgreSQL credentials, TLS (`sslmode=verify-full` recommended) |

## Threats and mitigations

### Spoofing

| Threat | Mitigation |
|---|---|
| A server impersonates another server to inherit its allow list | Identity from the TCP source or a per-server proxy token; `Proxy-Authorization` stripped before forwarding; access requests carry data-plane–signed block tokens instead of trusting client-supplied IPs |
| Rogue worker joins and pulls policy or pushes fake telemetry | Data-plane key required for every data-plane API call; bundles contain token hashes only |
| Forged console session | HS256 tokens with a per-installation secret (known defaults rejected), `jti` revocation, live re-check of user and role |
| Forged SSO login / token replay / IdP mix-up | PKCE S256, `state` in an HMAC-signed cookie, `nonce`, issuer pinned (configuration and discovery), audience and `azp` checks, RS/PS/ES signatures only, HTTPS-only endpoints |
| Stolen service-account key | Shown once, stored as SHA-256, mandatory expiry, optional source CIDR allowlist, last-use tracking, immediate rotation; cannot hold Super Admin or approve changes |
| Credential guessing | Login throttling per account and source IP; password policy; SSO for people |
| Spoofed TLS sites via the CA | CA key only on the data-plane (control-plane needs the certificate only in Kubernetes), RSA-3072 with path length 0 (`gen-ca`) or issued by the corporate PKI (`gen-csr` / `import-ca`) |

### Tampering

| Threat | Mitigation |
|---|---|
| Unreviewed policy change | Drafts, impact simulation, optional four-eyes review (author and last editor cannot approve), immutable versions, rollback |
| Privilege escalation through configuration | User management, SSO mapping, service accounts, log export and Defender settings are Super Admin only; Team Leads cannot create BLOCK rules, catch-all hosts or baseline sets, nor change other roles' BLOCK guardrails |
| Manipulated audit history | Keyed hash chain (HMAC-SHA256, audit chain key encrypted with `AEGIS_ENCRYPTION_KEY`) that is never recomputed; sealed anchor (start, pre-2.1 prefix) and head checkpoint (newest event, event count, configuration revision) saved atomically with the configuration; append-only JSONL sink and database table; verification endpoint; removed seals, cut-off starts or ends and hash downgrades are sticky integrity violations with high-severity alerts; unkeyed prefixes stay untrusted until a Super Admin accepts them; real-time SIEM forwarding with checkpoint records ([details](#audit-trail-against-insiders)) |
| Request smuggling past the policy (`Host`/SNI mismatch, domain fronting) | Destination = real connection target; mismatching `Host`/SNI blocked; HTTP/2 and HTTP/3: a `Host` header that differs from `:authority` is blocked (it would be forwarded, and becomes the `Host` of an HTTP/1.1 upstream request) |
| Inspection bypass by exhausting the worker's buffer budget (idle connections announcing large bodies, one client holding the budget) or by padding content beyond the scan limits | Only bytes that have arrived are accounted (a `Content-Length` reserves nothing); one client may hold at most `AEGIS_BUFFER_CLIENT_SHARE` (25 %) of the budget; a busy worker answers 503 `inspection_busy` instead of skipping an enforcing DLP/AV/file-type/ICAP inspection, whatever the oversize actions say; padding beyond `dlp_max_scan_bytes` / `av_max_scan_bytes` is governed by `dlp_oversize_action` / `av_oversize_action`, and the security posture warns while an enforcing inspection uses `allow` |
| Policy bypass through protocol upgrades | A WebSocket upgrade is an ordinary HTTP request: host, path, method, identity and `Host`/SNI binding are evaluated before the upgrade; frames after it are relayed without content inspection (no DLP/AV on WebSocket messages). Non-HTTP payloads inside tunnels are refused (`block_raw_tcp`) |
| Tampering with stored secrets | AES-256-GCM with authenticated key id; tampered values fail to decrypt and stop the start-up |
| Injection into block pages, notifications or CSV exports | Contextual escaping (`html/template`), single-pass placeholder substitution, nonce CSP; Slack/Teams markup escaped; CSV formula injection defused |

### Repudiation

| Threat | Mitigation |
|---|---|
| Administrator denies a change | Every change audited with actor, role, before/after state; service accounts audited as `sa:<name>`; integrations as `microsoft-defender` |
| Emergency access used silently | `BREAK_GLASS_LOGIN` audit event and high-severity alert — the sign-in is refused (503) when the event cannot be written; emergency publishes flagged with justification |
| Audit trail quietly reset or re-based | Retention points, anchors sealed for existing installations and acceptances of legacy events are audited and raise high-severity alerts |
| Server owner denies traffic | Traffic records with server identity, URL, verdict, rule and trace id; data-plane access logs |

### Information disclosure

| Threat | Mitigation |
|---|---|
| Secrets in the configuration leak through backups or database access | Encrypted at rest; write-only in the API (masked / `has_…` flags) |
| Server tokens leak upstream | `Proxy-Authorization` stripped; tokens never in bundles or exports |
| Credentials of servers leak to scanning engines | `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` never sent to ICAP |
| SSRF from the control-plane (feeds, webhooks, TAXII/MISP, exports) to cloud metadata or internal admin interfaces | HTTPS only; public feeds and webhooks: internal ranges refused with resolved-IP pinning; TAXII/MISP: loopback and link-local refused at save and dial time; exports: link-local refused at dial time; Defender pagination restricted to the API host |
| Servers read cloud instance credentials or VM configuration through the proxy | Loopback, link-local (`169.254.169.254`), unspecified, multicast and the cloud metadata endpoints outside link-local (Azure WireServer `168.63.129.16`, AWS IMDS IPv6 `fd00:ec2::254`, Alibaba Cloud `100.100.100.200`) are never reachable through the data-plane, whatever the rules say; checked for IP literals and for every resolved address, identically in the control-plane simulator (shared test vectors) |
| Session theft through XSS or URLs | HttpOnly cookie, no tokens in URLs or JavaScript storage, strict CSP |
| Open redirect after SSO | `next` restricted to local console paths |
| Personal data in traffic logs | `redact_query` per export destination; retention settings (`AEGIS_FLOW_RETENTION`); Auditor role read-only |

### Denial of service

| Threat | Mitigation |
|---|---|
| Flooding public endpoints (access requests, CA downloads) | Per-IP rate limits, body size limits, duplicate-request detection, cap on pending requests |
| Memory exhaustion through large bodies | Bodies are streamed unless an inspection needs them; buffered bodies are capped per flow (scan limits), per client (`AEGIS_BUFFER_CLIENT_SHARE`) and per worker (`AEGIS_BUFFER_BUDGET`), counting only bytes that have arrived, also without `Content-Length` (chunked); uploads of blocked requests are discarded; `AEGIS_BODY_SIZE_LIMIT` caps any single message. Several cooperating clients can still fill the budget: other clients' enforcing inspections then get 503 `inspection_busy` with `Retry-After` (availability, not a bypass); see the `aegis_dp_buffered_bytes_top_client` and `aegis_dp_buffer_limited_total` metrics |
| Control-plane outage stops egress | Workers enforce the last known policy; fail-closed only before the first sync; active-active control-plane on PostgreSQL |
| Slow or failing scan engines | Timeouts per engine, `icap_fail_mode` / `av_fail_mode` per policy, health status in heartbeats |
| SIEM outage blocks the control-plane | Durable spool per export destination, bounded queues, drops counted in metrics |

### Elevation of privilege

| Threat | Mitigation |
|---|---|
| InfoSec user grants themselves Super Admin through the IdP mapping | SSO configuration is Super Admin only |
| Team Lead widens scope | Scope checks on every policy, request and session operation (effective groups incl. label-selected); no catch-all or TLD wildcard hosts; permanent grants not allowed |
| Automation obtains admin rights | Service accounts cannot be Super Admin, cannot manage identities or integrations |
| Learning session opens a zero-internet tier | `record_and_allow` refused for strict-isolation groups; learning sessions and redirect grants never apply to members of strict-isolation groups; internal destinations never opened by learning or redirect grants |
| Allowed site redirects to an arbitrary host (open redirect, user-controlled links) | Redirect grants only for rules with *Follow redirects* (and learning sessions); one object (exact path), GET/HEAD, two minutes, single hop, same server identity (not source address), never internal destinations; optional per-rule `redirect_hosts` allowlist |
| Servers behind one NAT address use each other's grants or identity | Learning sessions and redirect grants keyed by server ID; invalid proxy credentials refused (407) instead of falling back to the address; groups with `require_proxy_token` are never identified by address |
| Compromised server keeps communicating | Quarantine overrides every allow rule, TLS exception and learning session; Defender risk/isolation and SOAR playbooks can quarantine automatically |

### Audit trail against insiders

The audit trail has to hold up against people with access to the storage (`DATA_DIR`, the database, backups),
not only against console users.

| Attacker | Can | Cannot |
|---|---|---|
| Write access to `DATA_DIR` or the database, **without** the encryption key | destroy or corrupt the data (detected, restore from backup); roll state and trail back together to an older consistent copy; discard key, seals and trail and present a re-hashed unkeyed trail | change, insert, reorder or delete events (also at the start or the end), remove or forge the anchor or checkpoint, hide a recorded violation, or make a re-hashed trail trusted — each is an integrity violation or a pending legacy prefix, with a high-severity alert and a failing posture check |
| The same **with** the encryption key (key stored in `DATA_DIR`, root on the host, database plus secret store) | recompute the keyed chain and all seals: any change is undetectable locally | change what the SIEM already received |
| Super Admin (console/API) | accept a pending legacy prefix (count and last hash must match), apply a retention point — both audited and alerted | delete or change events, clear a violation |

Residual risk: a complete rollback, and anything done with the encryption key, can only be detected against an
independent copy. Keep the encryption key outside `DATA_DIR` (posture check warns otherwise), forward the audit
stream including its `AUDIT_CHECKPOINT` records to a SIEM in real time (the posture check fails in production
otherwise), alert there when checkpoints stop or their event count decreases, and accept a legacy prefix only after
comparing it with an archived copy ([operations.md](operations.md#audit-trail)).

## Residual risks and operator responsibilities

- **Bypass of the proxy**: AegisProxy only controls traffic that passes through it. Block direct egress at the
  network layer (firewalls, security groups, routing) so the proxy is the only path to the internet.
- **TLS no-break exceptions and pinned clients**: traffic in exceptions is not inspected (policy still applies to
  the host name). Keep exceptions few, scoped and reviewed.
- **Allowed destinations can be abused** (e.g. a whitelisted code-hosting or storage service used for
  exfiltration). Prefer path-level rules, enable DLP and ICAP REQMOD, and monitor traffic volumes.
- **Follow redirects trusts the allowed site's redirects**: without `redirect_hosts`, a rule with *Follow
  redirects* lets the allowed site (or anyone who can make it redirect — open redirects, user-supplied links)
  grant the requesting server one public object anywhere for two minutes (GET/HEAD only; threat intelligence, file
  type, AV and DLP checks still apply; never internal destinations). Enable it only where needed and list the
  expected CDN hosts in `redirect_hosts` for sites whose redirects third parties can steer.
- **CA key compromise** is critical: protect `CERTS_DIR` / the CA secret, prefer a subordinate CA with path length
  0 from the corporate PKI, and have a revocation and re-issuance plan.
- **Shared secrets**: `AEGIS_DATAPLANE_KEY`, `AEGIS_JWT_SECRET` and `AEGIS_ENCRYPTION_KEY` must come from a secret
  store, be identical on all replicas and be rotated after personnel changes or suspected exposure
  ([operations.md](operations.md#rotating-secrets-and-the-ca)).
- **IdP trust**: whoever administers the IdP groups mapped to roles controls console access. Protect those groups
  (privileged identity management, MFA, access reviews) and keep break-glass accounts.
- **Scan coverage**: content above the scan limits, streamed responses (server-sent events) and encrypted archives
  cannot be inspected; signature-based engines miss unknown malware.
- **Data protection**: traffic records can contain personal data. Define retention, access and redaction according
  to your legal requirements.
- **Availability**: run at least two data-plane workers and two control-plane replicas for production; monitor
  the metrics listed in [operations.md](operations.md#monitoring).
- **Audit trail rollback**: state and audit trail replaced together by an older consistent copy, or rewritten by
  somebody holding the encryption key, verify locally; only the SIEM copy reveals it
  ([above](#audit-trail-against-insiders)).
- **Monitoring**: mitigations that alert (break-glass logins, emergency publishes, quarantines, security events)
  only help when someone reviews them — forward them to the SIEM and define response procedures.
