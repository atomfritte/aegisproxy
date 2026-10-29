# Security model

## Trust boundaries

| Boundary | Protection |
|---|---|
| Servers → data-plane | Default deny. Server identity by per-server proxy token (SHA-256 stored) or registered IP/CIDR. Unregistered sources get no group membership. |
| Data-plane → internet | Policy evaluation before any upstream connection (`connection_strategy=lazy`), upstream certificate validation always on, TLS ≥ 1.2, DNS-rebinding protection with IP pinning, threat-intel checks on names, URLs, resolved IPs and file hashes. |
| Data-plane ↔ control-plane | `X-Aegis-DataPlane-Key` (≥ 32 random characters, constant-time comparison). Bundles contain token **hashes** only. Use HTTPS (`CONTROL_PLANE_URL=https://…`, `AEGIS_CONTROL_PLANE_CA_FILE`). |
| Browser → control-plane | HttpOnly + SameSite=Strict session cookie (JWT HS256 with fixed header, `jti`, server-side revocation), CSRF protection (custom header + Origin check), strict CSP, HSTS on HTTPS, login throttling, RBAC re-validated against the live user on every request. |
| Control-plane ↔ identity provider | OIDC authorization code flow with PKCE (S256), HMAC-signed state cookie, ID-token signature (RS/PS/ES only) and `iss`/`aud`/`azp`/`exp`/`nonce` validation, HTTPS-only issuer and endpoints ([identity.md](identity.md#single-sign-on)). |
| Automation → control-plane | Service-account API keys (SHA-256 at rest, mandatory expiry, optional source CIDRs, never Super Admin, cannot approve changes) ([identity.md](identity.md#service-accounts)). |
| Anonymous → control-plane | Only `/api/public/*` (CA download, install scripts, access requests) — rate limited, size limited, server identity only from data-plane–signed block tokens. |
| Control-plane → internet | Feed downloads and webhooks: HTTPS only, SSRF guard (DNS resolution checked against internal ranges, dialed IP pinned), size limits, timeouts, no redirects to http. |
| Control-plane → internal services | TAXII/MISP: HTTPS, private hosts allowed, loopback and link-local refused when saving and when dialing. Log export: link-local (cloud metadata) refused at dial time — private and loopback addresses are allowed for collectors and sidecars — TLS verification on by default, optional private CA and mutual TLS. Defender API and Entra token endpoint: HTTPS only, pagination restricted to the API host. All credentials are stored encrypted and never returned by the API. |
| Data-plane → ICAP engines | `icaps://` with certificate verification (optional private CA); `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` are never forwarded to the engine. |

## Roles (RBAC)

| Role | Permissions |
|---|---|
| `SUPER_ADMIN` | Everything, including users, service accounts, single sign-on, log export and the Defender integration. |
| `INFOSEC_APPROVER` | All groups; BLOCK rules, TLS bypass, threat protection (feeds, YARA, ICAP), fleet, quarantine and release, webhooks. |
| `TEAM_LEAD_APPROVER` | ALLOW rules, approvals and learning sessions for the assigned groups only. Cannot create BLOCK rules, catch-all (`*`) or TLD wildcard hosts, or target servers outside the assigned groups. |
| `OPERATOR_AUDITOR` | Read-only. Webhook URLs are masked. |

Guard rails: the last active Super Admin cannot be deleted, disabled or demoted; users cannot demote
themselves; role/group/password changes revoke the user's existing sessions. Service accounts can hold
InfoSec, Team Lead or Auditor roles only and can never approve change requests. Identity details:
[identity.md](identity.md).

## Encryption at rest

Secrets that the control-plane must use in clear text are encrypted with **AES-256-GCM** whenever the
configuration is persisted (state file or PostgreSQL document) and decrypted when it is loaded. The value format is
`enc:v1:<key id>:<base64(nonce ‖ ciphertext)>`; the prefix and key id are authenticated as additional data, so a
value cannot be moved to another key or tampered with unnoticed. The AES key is derived with SHA-256 from
`AEGIS_ENCRYPTION_KEY` (≥ 32 characters, required in cluster mode, generated per installation in file mode);
`AEGIS_ENCRYPTION_KEY_PREVIOUS` allows rotation ([operations.md](operations.md#encryption-key)).

| Encrypted field | Where |
|---|---|
| `client_secret` of the single sign-on configuration | Settings → Identity |
| Private keys of the `private_key_jwt` client keys (PKCS#8; erased when a key is retired) | Settings → Single sign-on |
| `client_secret` of the Defender integration | Settings → Integrations |
| `auth_header_value` of threat feeds (incl. TAXII/MISP) | Threat Protection → Feeds |
| `secret`, `client_key_pem` and header values of log export destinations | Settings → Integrations → Log export |
| Teams and Slack webhook URLs | Settings → Notifications |

All of them are write-only in the API (empty or masked values keep the stored secret; responses contain only
`has_…` flags or masked URLs). One-way hashes are used where no clear text is needed: passwords (PBKDF2-HMAC-SHA256,
600,000 iterations), server proxy tokens, service-account keys and SCIM provisioning tokens (SHA-256). The interception CA private key is not
part of the configuration; it lives in `CERTS_DIR` / the Kubernetes CA secret (0600) and should be issued by your
corporate PKI or generated with `gen-ca`. A wrong or missing encryption key stops the start-up instead of
overwriting data.

## Findings fixed in this release (2.0)

The 1.x code base contained the following security defects, all fixed and covered by tests:

| Severity | Finding | Fix |
|---|---|---|
| Critical | Hard-coded default JWT secret and data-plane key → anyone could forge admin sessions or act as a proxy worker. | Secrets required / generated per installation; known defaults are rejected. |
| Critical | Policy evaluated on the `Host` header while mitmproxy connects to the real destination (`request.host`) → whitelist bypass (`GET http://evil/` with `Host: allowed`). | Destination = `request.host`; mismatching `Host`/SNI is blocked. |
| Critical | TLS passthrough set `data.ignore_conn` (attribute does not exist in mitmproxy ≥ 10, correct: `ignore_connection`) → no-break exceptions never worked. | Fixed; additionally the SNI must equal the CONNECT target, otherwise no passthrough (prevents tunnelling arbitrary hosts behind a bypassed SNI). |
| Critical | Non-HTTP traffic through CONNECT tunnels was relayed as raw TCP (SSH/exfiltration through the proxy). | `rawtcp=false` enforced; mitmproxy never opens an upstream connection for such tunnels. |
| Critical | Addon errors (e.g. control-plane unreachable before first sync) failed **open**; an `ImportError` silently disabled the whole addon. | Fail-closed (503) before the first policy sync; import errors abort start-up. |
| High | `Proxy-Authorization` (server token) forwarded to upstream servers; token authentication never applied to HTTPS (header is only sent on CONNECT). | Header stripped; credentials captured per client connection in `http_connect`. |
| High | Proxy tokens stored in plaintext in the state file (0644). | SHA-256 only, automatic migration, state file 0600. |
| High | Password hashes were never persisted (`json:"-"`) → after a restart nobody could log in; weak custom PBKDF2 (10k iterations). | Stdlib PBKDF2-HMAC-SHA256, 600k iterations, transparent re-hash, bootstrap admin. |
| High | Unauthenticated access requests trusted the `server_ip` from the JSON body (request on behalf of any server). | Data-plane–signed block tokens; otherwise TCP source + "UNVERIFIED". |
| High | Session token accepted in the URL (`?token=`, leaks into logs/history) and stored in `localStorage` (XSS exfiltration). | HttpOnly cookie, no token in URLs or JavaScript. |
| High | Rule/TLS-bypass input not validated (e.g. TLS bypass for `*`, TeamLead catch-all via session publish). | Central validation of host/path patterns, methods, scopes; catch-all and TLD wildcards restricted. |
| Medium | Policy simulator mutated production state (flows, hit counts, redirect grants) for every role. | Side-effect-free dry run (mutations only in demo mode). |
| Medium | Synthetic traffic generator and fabricated bandwidth statistics in production. | Demo mode only; real rolling 24 h aggregation. |
| Medium | Audit hash chain recomputed on trimming (tampering undetectable). | Chain never recomputed; append-only JSONL sink; verify endpoint. |
| Medium | Approved requests created `GET/HEAD/POST` rules and could be approved twice. | Least privilege (`GET/HEAD` + requested method), single review. |
| Medium | Webhook notifications vulnerable to Slack/Teams markup injection (mentions, spoofed links) and sent synchronously. | Escaping + asynchronous bounded queue. |
| Medium | Groups beyond the 63rd were silently ignored by the rule index (bitmask). | Set-based matching. |
| Low | Install script URL derived from the attacker-controlled `Host` header. | Always `AEGIS_PUBLIC_URL`. |
| Low | No security headers, request size limits or server timeouts. | Added (CSP, HSTS, nosniff, frame-deny, body limits, read/header timeouts, graceful shutdown). |

## Changes in 2.1

| Area | Change |
|---|---|
| Change management | Optional **four-eyes review** for every policy change (author ≠ approver, last editor ≠ approver); emergency publishes only by Super Admins with a justification, flagged in history and audit. Every publish creates an immutable version. |
| Least privilege | Team Leads cannot modify or remove BLOCK guardrails even inside sets of their own groups, cannot create baseline sets, and can grant temporary access only (governance cap, default 30 days). |
| Scope semantics | `*` scopes no longer apply to unregistered sources (previously a `*` ALLOW rule also opened egress for unknown machines). Python and Go evaluators implement the same rule. |
| Incident response | Server quarantine enforced first in the evaluation order on both control-plane and data-plane. |
| Recertification | Policy sets carry a review interval; overdue sets are surfaced on the overview page. |
| Block pages | Admin-defined templates are rendered with contextual escaping (Go `html/template`); placeholder syntax in admin text is neutralized; workers substitute HTML-escaped values in a single pass; logo restricted to image data URLs; links restricted to http(s); nonce CSP per response. |
| Log export | Destinations managed by Super Admins only (audited); secrets write-only; TLS verification on by default with optional private CA and mutual TLS; link-local (metadata) destinations refused; optional removal of URL query strings; `file` sinks restricted to file names in `AEGIS_EXPORT_DIR`; webhooks signed with HMAC-SHA256. |
| Data handling | Server CSV export defuses spreadsheet formula injection and never contains token digests; client-supplied rule bookkeeping (`access_request_id`, `source_session_id`) is ignored. |
| Single sign-on | OIDC (Entra ID and generic) with PKCE, `client_secret_post` or `client_secret_basic`, strict ID-token validation, group-based roles and scopes, just-in-time provisioning and deprovisioning on unmapped sign-in; configurable by Super Admins only (an InfoSec user could otherwise grant themselves Super Admin through the group mapping). |
| Break-glass | Password login can be restricted to designated break-glass Super Admins; every such login is audited and alerted (`BREAK_GLASS_LOGIN`). |
| Service accounts | API keys for automation instead of shared user passwords: hashed, expiring (≤ 730 days), CIDR-restricted, no Super Admin role, no change approvals. |
| SSO client authentication | `private_key_jwt` (RFC 7523): the control-plane signs token requests with its own RSA-3072/P-256 key (sealed at rest, never exported) instead of sending a client secret; public keys via JWKS URL or certificate upload; staged rotation with a 7-day grace period, retired private keys erased. |
| SCIM provisioning | Entra ID / Okta deactivate and delete accounts over SCIM 2.0 with immediate session revocation; dedicated hashed, expiring bearer tokens accepted only on `/api/scim/v2` (and nowhere else); SCIM can never read or change local/break-glass accounts; Super Admin only through an explicit group mapping; every change audited. |
| Encryption at rest | AES-256-GCM for all stored integration secrets and webhook URLs, key rotation without downtime; every node re-encrypts values of the previous key at start-up, so the old key can be retired after one rolling restart. |
| Threat intelligence | TAXII 2.1 / MISP collectors (private hosts allowed, loopback and link-local refused at save and dial time); Defender indicator import; Defender device risk/isolation can quarantine servers (auto-release only for its own quarantines; pagination links restricted to the API host). |
| Content inspection | YARA (YARA-X) and ICAP RESPMOD/REQMOD; credentials and cookies are stripped before content leaves for an ICAP engine; fail-open/closed per policy; YARA rule sets are linted on save and compiled one by one on the workers (a broken set never disables the others); ICAP REQMOD runs independently of the built-in DLP detectors. |
| Data-plane enforcement | Every worker hook fails closed (403/503, `aegis_dp_hook_errors_total`; unevaluated flows blocked; hostile credential/Host bytes handled); bodies decoded like clients do (coding chains, all gzip members, bounded against decompression bombs, undecodable → blocked) with `Accept-Encoding`/`Range` rewriting and `206` blocking; event streams scanned whenever inspection applies; transparent/SOCKS/reverse modes bind Host/SNI to the destination IP (also for TLS passthrough); ICAP: one deadline per exchange, every error honours `icap_fail_mode`, sanitized uploads applied, single `Content-Length`. See [threat-protection.md](threat-protection.md#content-decoding). |
| Audit | `GET /api/audit/export` returns the complete trail (database or all rotated `audit.jsonl` generations); log rotation by rename instead of `copytruncate` (no lost lines). |
| Posture | `GET /api/system/posture` scores the installation against this checklist. |
| PKI | `gen-csr` / `import-ca`: interception CA issued by the corporate PKI (chain and key match validated, root never served). |
| Independent security review | All findings of the 2.1 review fixed with regression tests: data-plane hooks fail closed on any internal error; content is decoded (all codings, all gzip members, capped against decompression bombs) or blocked before scanning; event streams and byte ranges no longer bypass inspection; transparent mode binds Host/SNI to the real destination; Team Leads can neither open learning sessions for foreign or zero-internet servers nor withdraw guardrails by disabling or re-scoping a set; "test connection" endpoints never send stored credentials to a new destination; SSO users cannot get local passwords and an admin lock-out survives the next SSO login; Team Leads see only data of their groups; audit chain keyed with HMAC; bounded login throttle, request quotas and stream limits; control characters stripped from SIEM formats; Defender endpoints restricted to Microsoft clouds; public-suffix-aware wildcard checks. |
| Adversarial review (2.1) | Four attacker models (egress bypass, control-plane authorization, audit integrity, deployment/supply chain); every finding fixed with a regression test, then reviewed again. **Audit**: a sealed anchor (encrypted, keyed with the audit chain key) records the trail's origin and the end of the unkeyed pre-2.1 prefix, so a downgrade to unkeyed hashes, a missing start or tail and a rolled-back head fail verification (`starts_at_genesis`, `head_matches`); deleting old generations needs `POST /api/audit/retention`; audit files are opened without following symlinks or blocking on FIFOs, events are flushed before a change is acknowledged, torn writes are cut back, an unwritable log refuses changes (503) instead of losing events, crash leftovers are reconciled at start, generations are ordered by chain content, export and verification no longer block rotation, and the file→cluster migration imports the complete trail. **Authorization**: Team Leads see policy sets, versions, diffs, simulations and effective policies of their own groups only; managed/workload identity tokens go only to Azure Monitor / Entra ID hosts; export and notification errors never contain URLs or webhook paths. **Export**: rejected batches of audit/security sinks go to `dead-letter.jsonl`, a full queue spools instead of dropping, Splunk acknowledgements are polled across attempts instead of resending. **Data-plane**: bodies are streamed unless inspected, buffered bodies share a bounded per-worker budget (`AEGIS_BUFFER_BUDGET`); uploads are DLP-scanned completely (`dlp_oversize_action`); identical Go/Python normalization with shared vectors; `redirect_hosts`; HTTP/2 `Host` ≠ `:authority` blocked. **Deployment**: Windows installers take ownership of and verify the ACLs of pre-existing directories and refuse planted secrets (`-AdoptExistingSecrets`), refuse a base Python writable by users, hash WinSW after copying it, require SMB encryption for secret imports; Helm trusts no proxy ranges by default (`trustedProxyHosts`), IPv6 egress rules, digest-pinned images, hash-pinned data-plane packages, non-root ClamAV; the control-plane container gets only the public CA certificate; CA installers are downloaded and checked against their SHA-256 instead of piped into a shell. See [testing.md](testing.md#adversarial-review-21). |
| Supply chain | CI runs `govulncheck`, `staticcheck`, `pip-audit` (lock files and the packages copied out of the built data-plane image), `npm audit` (including the build toolchain) and Trivy; the image build contexts allowlist the tracked files and the Go builds use only `go.sum`-verified modules; release images are signed with cosign (keyless) and carry SBOM and build-provenance attestations. The data-plane image patches vulnerable packages of the mitmproxy base image (and, where mitmproxy's version bounds would exclude the fix, Brotli 1.2.1 for the decoder out-of-bounds write CVE-2026-111497 and tornado 6.6 for CVE-2026-116577/-115927/-116578) and ships without pip/setuptools; the console image is upgraded from its Alpine base and drops curl. See `SECURITY.md`. |

## Threat protection

See [threat-protection.md](threat-protection.md) for threat intelligence, antivirus, YARA, ICAP, DLP, download
control, anomaly detection and the Defender integration. The threat model is in [threat-model.md](threat-model.md),
the control mapping for ISO 27001, NIST SP 800-53, BSI IT-Grundschutz and SOC 2 in [compliance.md](compliance.md).

## Hardening checklist

- [ ] `AEGIS_PUBLIC_URL` uses `https://`; TLS terminated by the control-plane or a trusted reverse proxy
      listed in `AEGIS_TRUSTED_PROXIES`.
- [ ] Secrets come from a secret store (`*_FILE`, Kubernetes Secrets, systemd credentials); `.env` is not
      committed.
- [ ] Root CA created with `aegis-control-plane gen-ca` (RSA-3072, path length 0); private key only on the
      data-plane, never on servers; fingerprint verified when distributing.
- [ ] The bootstrap admin password was changed; people sign in with SSO; password login is limited to one or two
      break-glass accounts whose use is alerted.
- [ ] `AEGIS_ENCRYPTION_KEY` comes from the secret store and is backed up separately from the data.
- [ ] Automation uses service accounts with source-CIDR restrictions; keys are rotated before they expire.
- [ ] SSO uses `private_key_jwt` (no client secret in the IdP); client-key certificates are rotated before
      `not_after`.
- [ ] Offboarding is automated with SCIM provisioning; the SCIM token has an expiry, `/api/scim/` is reachable only
      from the IdP's provisioning ranges, and no broad IdP group is mapped to Super Admin.
- [ ] Each server group has an owner team; Team Leads are scoped to their groups.
- [ ] Server proxy tokens are issued (`Rotate token`) for servers without a stable IP.
- [ ] `AEGIS_CONTROL_PLANE_CA_FILE` / HTTPS between data-plane and control-plane.
- [ ] The proxy port is reachable only from server networks (firewall / `loadBalancerSourceRanges` /
      `networkPolicy.proxyClientCIDRs`); the console only from admin networks.
- [ ] ClamAV deployed; `StreamMaxLength` ≥ `av_max_scan_bytes`; signature updates monitored.
- [ ] DLP switched from `monitor` to `block` after a review period.
- [ ] `/metrics` protected (`AEGIS_METRICS_TOKEN`) or reachable only from the monitoring network.
- [ ] Audit JSONL / `aegis_audit` shipped to the SIEM; the complete verification runs in the background
      (`AEGIS_AUDIT_VERIFY_INTERVAL`) and is alerted on (`aegis_audit_full_verify_ok`,
      `AUDIT_INTEGRITY_VIOLATION`/`AUDIT_VERIFICATION_FAILED` security events); old generations removed only
      together with `POST /api/audit/retention`.
- [ ] `AEGIS_TRUSTED_PROXIES` / `trustedProxyHosts` list only the reverse proxies in front of the control-plane;
      loopback or a shared gateway only together with `AEGIS_TRUSTED_PROXY_SECRET`.
- [ ] The edge proxy replaces `X-Forwarded-For` with the address it sees (nginx
      `proxy_set_header X-Forwarded-For $remote_addr;`, or the realip module for exactly the load balancer's
      addresses) instead of appending to the client's header
      ([trusted proxies](configuration.md#trusted-proxies-and-sign-in-throttling)).
- [ ] Self-built images come from a clean checkout nobody else can write to, built with `make images` (committed
      tree only) or in CI; `git status` is clean before `docker compose build` ([SECURITY.md](../SECURITY.md)).
- [ ] CA installers are distributed with their SHA-256 (console, **TLS & CA**), never piped into a shell.
- [ ] The security posture page shows no `fail` items.
- [ ] Backups (state file or PostgreSQL) tested by restoring.
- [ ] `AEGIS_DEMO_MODE` is **false**.

## Reporting vulnerabilities

Report security issues privately to the platform security team; do not open public issues.
