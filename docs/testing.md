# Testing

## Automated tests

```bash
make test            # all of the below
```

| Suite | Command | Covers |
|---|---|---|
| Go unit + API tests | `go -C control-plane test -race ./...` | log export (CEF/LEEF/ECS formats and escaping, filters, syslog over TCP and UDP, OTLP, Splunk HEC, Elasticsearch bulk incl. partial rejections, Sentinel token flow, Datadog, Loki, signed webhooks, files, permanent vs. transient errors, ordered spool replay across a restart, link-local refusal, API secret redaction and metrics), policy sets (draft/publish, four-eyes review, emergency publish, versions, rollback, withdraw), Team Lead guardrail protection inside sets, baseline scope never matching unregistered sources, approvals sets with extend/revoke and governance caps, quarantine, dynamic label groups and effective policy, impact simulation, schema-v3 migration, atomic CSV import with dry run, block page template validation, renderer escaping/localization, policy/fleet/block-page API flows, password hashing (incl. legacy migration), JWT tampering / `alg=none` / revocation, block tokens, login throttling, RBAC (Team Lead restrictions), feed parsing and matching, policy evaluation order, TLS-bypass scoping and strict isolation, rule validation, request de-duplication and single review, user-management guard rails, security events and burst detection, legacy state migration, cookie sessions, CSRF, data-plane auth/ETags, block-token attestation, install-script host pinning, built-in audit log rotation (timestamped generations, delayed compression, no rotation while an export or verification reads, complete chain across generations, crash leftovers) |
| PostgreSQL cluster tests | `AEGIS_TEST_DATABASE_URL=postgres://… go -C control-plane test ./internal/store/` | two nodes on one database: replication via LISTEN/NOTIFY, 20 concurrent writes across nodes (no lost updates, linear audit chain), duplicate detection across nodes, telemetry and session-revocation replication, import of a 1.x state file, change request submitted on one node and approved on the other, rule-hit and quarantine replication, migration of a 2.0 cluster document by a joining 2.1 node |
| Data-plane unit tests | `python3 -I data-plane/tests/test_dataplane.py` | access log formats (Squid/combined/JSON), file and TCP-syslog destinations incl. unreachable server, size-based file rotation (Windows default) and its configuration, quarantine, `*`-scope semantics, branded block pages (locale negotiation, group template selection, escaping, single-pass substitution, logo validation, threat variant), path canonicalization, evaluation order (mirrors the Go cases), identity resolution, TLS bypass scope, CONNECT semantics, redirect grants, learning sessions, threat-intel matching, block-token format, DLP detectors, file-type detection, clamd INSTREAM against a fake clamd |
| Windows builds under Wine | `scripts/wine/run-go-tests.sh <dir> --cluster`, `exe_e2e.py`, `dp_e2e.py` (see [`scripts/wine/README.md`](../scripts/wine/README.md)) | the Go suites compiled for `windows/amd64` incl. PostgreSQL cluster tests; `aegis-control-plane.exe` as console process and as SCM service; the data-plane on python.org's Windows CPython with the `win_amd64` wheels, HTTPS through the proxy |
| Integration conformance | `scripts/conformance/run.sh <dir>` (see [`scripts/conformance/README.md`](../scripts/conformance/README.md)) | Splunk HEC against the OpenTelemetry Collector and Vector (indexer acknowledgement), Sentinel against the official Azure SDKs and API definition, public Entra ID / Defender / Datadog endpoints (`-tags live`) - no license, no tenant |
| Cross-language block token | `AEGIS_XLANG_BLOCK_TOKEN=$(python3 …) go test -run TestCrossLanguage ./internal/auth/` | Python-signed token verified by Go |
| Frontend | `npm --prefix frontend run build` | TypeScript type check + production build |
| Helm | `helm lint deploy/helm/aegisproxy` + `kubeconform -strict` | all value combinations render valid manifests |

A disposable database for the cluster tests:

```bash
docker run -d --rm --name aegis-pg -e POSTGRES_PASSWORD=test -e POSTGRES_USER=aegis -p 55432:5432 postgres:17-alpine
export AEGIS_TEST_DATABASE_URL='postgres://aegis:test@127.0.0.1:55432/aegis?sslmode=disable'
```

## End-to-end verification performed for 2.0

Against real mitmproxy 12.3.0, ClamAV 1.5.4 and live internet destinations:

| Scenario | Result |
|---|---|
| Unknown destination (HTTP) | 403 block page with signed token; CLI one-liner creates a **verified** access request |
| Whitelisted destination (HTTP/HTTPS) | 200, TLS intercepted with the enterprise CA, upstream IP pinned |
| `Host` header spoofing | 403 `host_mismatch` |
| TLS no-break exception | 200 with the **real** upstream certificate (was broken in 1.x) |
| SNI spoofing towards a bypassed name | intercepted, upstream certificate validation fails — no passthrough |
| CONNECT to port 22 | 403 at CONNECT |
| Raw/SSH data through CONNECT :443 | no upstream connection, nothing relayed |
| IP literal / explicit IP rule / metadata IP | 403 / allowed / 403 |
| Custom IOC and live feed hit (a URLhaus-listed domain) | `THREAT_BLOCKED`, no self-service |
| EICAR download from an allowed host | `MALWARE_BLOCKED` (ClamAV `Eicar-Test-Signature`) |
| PE download with `blocked_file_types=[pe]` | `FILETYPE_BLOCKED` |
| Hash IOC | `MALWARE_BLOCKED` |
| AWS key in POST body (monitor) / private key (block) | flagged / `DLP_BLOCKED` |
| Redirect lineage (github.com → codeload.github.com) | follow-up object allowed as `REDIRECT_OBJECT_ALLOWED` |
| Proxy token in `Proxy-Authorization` | never forwarded upstream |
| Worker without reachable control-plane | 503 fail-closed; leaked 1.x default key refused at start |
| Console in a real browser (Chromium) | login, Threat Protection view, verified block portal |
| Docker Compose single host | healthy with read-only, non-root containers |
| Docker Compose HA | 2 replicas + PostgreSQL + HAProxy: consistent revisions, writes during replica outage, rejoin |
| Kubernetes (Helm, CloudNativePG) | see [kubernetes.md](deployment/kubernetes.md#verification-performed) |
| Linux (systemd) | units pass `systemd-analyze verify` (security score 1.2 / 1.3); both services ran under the unit hardening (allowed HTTPS 200, default deny 403); `install-linux.sh` tested on Ubuntu 24.04 and Rocky 9 containers, idempotent re-run |
| Windows Server | PowerShell scripts parsed and analysed (PSScriptAnalyzer, PS 5.1/7 compatibility), XML/`web.config` well-formed, Windows binary cross-compiled; from 2.1 the CI job `windows` installs both services on Windows Server 2022 and 2025 runners, rolls out the CA with the product's script, proxies allowed/denied HTTPS through the data-plane service and uninstalls (runs on every push) |

## End-to-end verification performed for 2.1

Against real mitmproxy 12.3.0 with the 2.0 end-to-end state directory (schema 2, five flat rules):

| Scenario | Result |
|---|---|
| Upgrade of a 2.0 state file | 5 rules migrated into 1 published policy set; enforcement unchanged |
| Branded template assigned to the group | browser block page in German (`Accept-Language: de`), custom title with `{hostname}`, logo, support e-mail, only the offered scopes; nonce CSP header; no unfilled placeholders |
| CLI client (`curl`) | branded plain-text message with the template's first scope/duration in the one-liner |
| Self-service request with a scope the template does not offer | rejected (`scope … is not offered for this server`) |
| Approval | rule added to `approvals-<group>`, request allowed through the proxy within one bundle sync |
| Quarantine | `QUARANTINED` for the same destination, threat variant without request form; release restores access |
| Revocation | access removed again (403) |

### Log export against real systems (2.1)

| Destination | Result |
|---|---|
| rsyslog 8 (Alpine) — syslog TCP, RFC 5424, JSON | audit, traffic and security records received with `app=aegisproxy`, `msgid=AUDIT/TRAFFIC/SECURITY`, correct facility/severity |
| rsyslog — syslog UDP, CEF, `local3`, blocked traffic only | only blocked flows, valid CEF with escaping |
| OpenTelemetry Collector contrib 0.115 — OTLP/HTTP | records in the file exporter with resource attributes and ECS attributes |
| Grafana Loki 3.3 | streams `audit`, `traffic/BLOCKED`, `traffic/QUARANTINED` queryable via LogQL |
| OpenSearch 2.18 — bulk, `aegis-{stream}` indices, query redaction on | documents in `aegis-audit`, `aegis-traffic`, `aegis-security`; no document contains the query-string token |
| file sink, LEEF | LEEF 2.0 lines in `DATA_DIR/export` |
| Data-plane access log → rsyslog over TCP (Squid format) | `TCP_DENIED/403` lines with tag `aegisproxy-access` |

### Identity, content inspection and threat intelligence against real systems (2.1)

| System | Scenario | Result |
|---|---|---|
| Keycloak 26.0 (OIDC, PKCE S256, group mapper), Chrome via Playwright; IdP and console on different sites | SSO test endpoint, browser login, redirect to the requested page | 24/24 checks: session valid after the cross-site redirect, `aegis_sso` cookie cleared, HttpOnly session cookie |
| | group → role / scope mapping | `aegis-infosec` → InfoSec, `aegis-ci-leads` → Team Lead with scope `grp-ci` |
| | user without mapped group; user removed from the group in Keycloak | `sso_error=not_authorized`; existing account disabled, sessions revoked, `USER_DEPROVISIONED_SSO` audited |
| | password login with local login disabled | refused for a normal local user; the break-glass admin works and raises `BREAK_GLASS_LOGIN` |
| | forged callback without state cookie | `sso_error=session` |
| c-icap 0.5.10 + `virus_scan` module 0.5.7 (Debian 13) + ClamAV 1.5 (clamd over a shared socket) | ICAP client: OPTIONS/ISTag, RESPMOD clean / EICAR / 3 MB ZIP containing EICAR, REQMOD clean / EICAR upload, empty body, unreachable service | 10/10 |
| mitmproxy data-plane (`aegisproxy/data-plane:2.1.0`) → internet, with YARA (block) and ICAP (RESPMOD + REQMOD) | clean download (pypi.org) | 200, scanned by YARA and ICAP |
| | file matching a YARA rule (raw.githubusercontent.com) | 403 block page, `MALWARE_BLOCKED` / `yara`, security event source `YARA` |
| | EICAR from secure.eicar.org | 403, `MALWARE_BLOCKED` / `icap` (ClamAV via c-icap) |
| | EICAR uploaded with POST (built-in DLP **off**) | 403 via ICAP REQMOD; clean upload passes |
| | ICAP service stopped: fail-open / fail-closed | download allowed and flagged / 503; heartbeat `respmod=down` |
| | invalid YARA rule set | rejected by the console with the line and reason; heartbeat reports YARA `ok` and ICAP `ok` within seconds of configuration (19/19) |
| OASIS TAXII 2.1 reference server (medallion 3.0, TLS with a private CA, Basic auth, page size 3) | feed import with pagination | 21/21: 7 active indicators (domain, URL, IPv4, SHA-256, OR-pattern) imported; revoked, expired, too old and non-STIX indicators skipped |
| | TLS without / with `ca_cert_pem`; `http://`, loopback and link-local URLs | verification error / success; all three URLs rejected |
| | TAXII domain through the proxy | 403 at CONNECT, flow `THREAT_BLOCKED` with the feed as source |
| Trivy (HIGH/CRITICAL, fixable) | all four images (`control-plane`, `control-plane-api`, `data-plane`, `console`) | 0 findings (mitmproxy base packages patched, pip/setuptools removed; console Alpine base upgraded) |
| pip-audit | installed data-plane environment | 0 findings after the Brotli 1.2.1 override (CVE-2026-111497) |
| Independent security review (1 critical, 8 high, 9 medium, ~14 low) | re-run of every proof of concept after the fixes | all blocked; regression tests added for each finding (Go and Python) |

| MISP 2.5.50 (official misp-docker image, MariaDB, Valkey, TLS with a private CA) | MISP feed: wrong API key reported; IDS attributes imported via `/attributes/restSearch`; `domain|ip` split; non-IDS and deleted attributes skipped; lookups | 14/14 |
| Splunk HEC protocol (Vector 0.43 `splunk_hec` receiver) | wrong token reported by the test button; test and live audit events accepted; index and sourcetype per event; structured event body | 6/6 |
| Datadog log intake protocol (Vector 0.43 `datadog_agent` receiver, TLS) | untrusted certificate refused; test and live events accepted; reserved attributes (`ddsource`, `service`, `hostname`, `ddtags`, `status`, `timestamp`) plus ECS attributes as JSON message | 6/6 (+1 delivery status) |

| Live test harness (`scripts/integration-tests/live_microsoft.py`) self-test against local stand-ins for Entra ID, the Defender API and the Logs Ingestion API | 9/9 (configuration, token, permissions, device sync, indicator import, Sentinel test record and live delivery) — the same script runs against real tenants via `.github/workflows/live-integration.yml` |

| Backup/restore drill (file mode and PostgreSQL `pg_dump`/`pg_restore`) | 13/13: credentials, policy sets, CA, encrypted secrets (valid webhook HMAC after restore) and audit chain restored; missing or wrong encryption key refuses to start |
| Load test (hey through the release data-plane image, local origin with TLS) | ~230 req/s HTTP and ~205 req/s intercepted HTTPS per worker (mitmproxy alone ~250 req/s), see the sizing table in operations.md; the profile led to a fix: the state file is no longer rewritten every second under traffic (control-plane CPU at 556 req/s: 107 % → 16 % of a core) |

The Splunk and Datadog runs use Vector's protocol implementations, not Splunk or Datadog themselves (running
Splunk Enterprise requires accepting its license terms). They found one incompatibility that is fixed: extra
top-level attributes were rejected by agent-schema intakes such as Datadog Observability Pipelines.

Not executed against real tenants (covered by protocol-level mock tests and by the live test harness
`scripts/integration-tests/`, which customers and QA can run with their own credentials): Microsoft Defender
for Endpoint / Microsoft Graph and Microsoft Sentinel / Azure Monitor Logs Ingestion.

### Deployments and console (2.1, final build)

| Target | Result |
|---|---|
| Docker Compose single host (`docker-compose.yml`) | 8/8: console + API on one origin, OpenAPI served, encryption at rest active, worker heartbeat with YARA engine, allowed HTTPS through the proxy, default deny |
| Kubernetes 1.37 (kind, Cilium eBPF without kube-proxy) + CloudNativePG 1.30 (2 instances), 2 control-plane replicas, 2 workers, separate console | 9/9: login through the console's nginx `/api` proxy, replica-to-replica consistency, encryption active in postgres mode, both workers reporting, allowed/denied traffic through the NodePort, **100/100 writes** while a control-plane pod was deleted, complete audit trail verified from the database |
| Linux installer (`install-linux.sh --component data-plane`) in Ubuntu 24.04 | venv with mitmproxy 12.3.0, YARA-X 1.22.0 and Brotli 1.2.1, addon import check, unit installed |
| Console end-to-end (Playwright, Chrome) | 18/18 fleet/groups/requests/learning and 16/16 identity/security pages against the final backend; Team Lead need-to-know verified |
| Helm | `helm lint` for all value combinations; the `PrometheusRule` alerts pass `promtool check rules` (9 rules) |
| NetworkPolicy enforcement (Cilium 1.20 eBPF, all policies on, `probes.mode=exec`) | 17/17 connectivity checks as intended (control-plane, ClamAV, PostgreSQL, console unreachable from other namespaces and unlabelled pods; proxy port open; data-plane egress to cluster ranges and cloud metadata blocked, internet open); `scripts/verify-networkpolicies.sh` 16/16; functional test 9/9 with policies enforced |


### Integrations without vendor licenses or tenants (2.1, final)

Splunk Enterprise was not started (license terms) and no Microsoft tenant was available, so the integrations
were checked against independent implementations of the same protocols, the vendors' own SDKs and API
definitions, and the public vendor endpoints (`scripts/conformance/`):

| Scope | Result |
|---|---|
| Splunk HEC: OpenTelemetry Collector contrib 0.162.0 (`splunk_hec`, TLS) and Vector 0.59.0 (indexer acknowledgement) | 23/23 |
| Sentinel: AegisProxy vs. `azure-identity` 1.26.0 / `azure-monitor-ingestion` 1.1.0 / `msal` 1.39.0 and the official OpenAPI definition (azure-rest-api-specs `625f626`) | 16/16: identical token requests (client secret, workload identity), upload path/version/headers/body as specified, 1 MB limit |
| Public endpoints (no credentials): Entra ID discovery/JWKS/token errors, Defender API (current, regional, legacy host), Datadog EU intake | 5/5 |
| Defender client against Microsoft's API documentation (unit tests) | 3/3 |
| Console: Sentinel authentication choice, Defender cloud presets and permissions (Playwright) | 11/11 |

Defects found this way and fixed (each with a regression test):

* **Splunk HEC tokens with indexer acknowledgement were not supported** (Splunk answers `400 Data channel is
  missing`): requests now carry a stable request channel, acknowledgements are polled, a missing confirmation
  keeps the batch in the spool; load-balancer stickiness cookies are kept.
* The shortened error shown to non-administrators cut every URL after its scheme (`HTTP 401 from https`).
* **Sentinel in Azure Government / Azure China used the commercial token audience and authority**: both now
  follow the data collection endpoint (`monitor.azure.us` / `login.microsoftonline.us`, `monitor.azure.cn` /
  `login.chinacloudapi.cn`), as the Azure SDKs do. Uploads carry `x-ms-client-request-id` for Microsoft support.
* Managed identity and workload identity were only reachable through the API: the console now offers them,
  workload identity takes tenant and client from the pod environment injected by the AKS webhook, and the Helm
  chart can create an annotated ServiceAccount and pod labels.
* **Defender for Endpoint**: the documented permissions were wrong (List Indicators needs `Ti.ReadWrite.All`,
  there is no read-only permission; List MachineActions needs `Machine.ReadWrite.All`); the token scope followed
  the API host, so the current `api.security.microsoft.com` and the regional hosts would have been rejected with
  403 (Microsoft requires the legacy audience); `$select` on List machines is undocumented; a tenant without
  recent devices (404) failed the sync; more than 10,000 devices or indicators were silently truncated without
  `@odata.nextLink` (now `$top`/`$skip`); throttling (429) is waited out per `Retry-After`; the GCC High / DoD
  API defaults to the `.us` authority.

### Windows builds and installers (2.1, final)

Without a Windows host: the Windows builds under Wine 9 (`scripts/wine/`) and the installers against an
in-memory Windows model (Pester). The CI job `windows` repeats all of it on Windows Server 2022/2025.

| Scope | Result |
|---|---|
| Control-plane Go suites built for `windows/amd64` (Wine) | 123 passed, 0 failed, incl. the 6 PostgreSQL cluster tests; skipped: UDP syslog (Wine lacks `SIO_UDP_CONNRESET`), the logrotate rename test (impossible on Windows by design), the cross-language token test |
| `aegis-control-plane.exe` as console process | 19/19: bootstrap, policy set publish, data-plane bundle (key accepted/refused), enterprise CA on Windows paths, built-in audit rotation at 1 MB with delayed gzip compression, complete chain verification and export across generations, JSON log file, restart durability |
| `aegis-control-plane.exe` as service under Wine's SCM | 10/10: `sc create` with the `service` argument, `net start` → `RUNNING`, login, `net stop` with drain and state flush, persistence, restart, exit code 0, invalid setting → `STOPPED` with exit code 1 |
| Data-plane on python.org Windows CPython 3.12.10 (`win_amd64` wheels: mitmproxy 12.3.0, Brotli 1.2.1, YARA-X 1.22.0) | unit tests 51/51; proxy end to end 11/11 with the WinSW arguments: allowed HTTPS with a certificate issued by the enterprise CA, default deny with block page, method restriction, access log on a Windows path, heartbeat with YARA-X, flows at the control-plane |
| Installers (Pester 5.9.1, PowerShell 7.5) | 183/183; PSScriptAnalyzer 1.25.0: 0 findings |

Defects found this way and fixed (each with a regression test):

* `audit.jsonl` could never be rotated on Windows (an open file cannot be renamed by another process: sharing
  violation) → built-in size rotation (`AEGIS_AUDIT_ROTATE_MB`); the same for the data-plane's file access log
  (`AEGIS_ACCESS_LOG_ROTATE_MB`, Windows default 100 MB).
* The service relied on Go's `IsWindowsService` heuristic (parent `services.exe` in session 0) → explicit
  `service` argument in the ImagePath.
* Configuration errors of the service were invisible (no console under the SCM) → Application event log, source
  `AegisControlPlane`, registered by the installer.
* A missing `AEGIS_LOG_FILE` directory stopped the start → created on demand.
* Installers: the master encryption key could be written into the registry service environment via
  `-ExtraEnvironment`; the program directory did not get its own ACL (a custom `-InstallDir` let users plant
  files executed as SYSTEM); the WinSW hash was printed but not enforced; a `[::1]` listener was probed on
  127.0.0.1; `-WhatIf` left a temp file; duplicate variables via `-ExtraEnvironment`; a staged CA could be
  deleted before copying; hash-pinned installs (Windows and Linux) installed the security overrides without
  hashes and could not install a baseline-compliant lock at all (pip `ResolutionImpossible`) → `--require-hashes
  --no-deps`, baseline check and `pip check` (verified on Ubuntu 24.04 with a complete, an outdated and an
  incomplete lock file).