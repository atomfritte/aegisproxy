# Architecture

AegisProxy consists of three independently scalable components plus optional services:

| Component | Technology | Responsibility | State |
|---|---|---|---|
| **Control-plane** | Go (static binary, distroless image) | API, policy management, RBAC, approval workflow, threat-intel feeds, audit, telemetry, console (optionally bundled) | file (single node) **or** PostgreSQL (active-active cluster) |
| **Data-plane** | mitmproxy 12 + Python addon | Explicit HTTP(S) proxy for servers: TLS inspection, policy enforcement, DLP, antivirus, download control | stateless (local cache of the policy) |
| **Console** | React/TypeScript (static SPA) | Administration and SOC user interface | none |
| ClamAV (optional) | clamd | Malware scanning of downloaded content (INSTREAM) | signatures |
| PostgreSQL (optional) | ≥ 14 | Shared state for HA operation | – |

```mermaid
flowchart LR
  subgraph Fleet["Server fleet (Linux / Windows / K8s nodes)"]
    S1[Server] & S2[Server]
  end
  subgraph DP["Data-plane (N stateless workers)"]
    W1[mitmproxy + Aegis addon]
    W2[mitmproxy + Aegis addon]
  end
  subgraph CP["Control-plane (1..N replicas)"]
    API[REST API / SSE / console]
    TI[Threat-intel manager]
  end
  DB[(PostgreSQL\nor file)]
  AV[ClamAV clamd]
  NET((Internet))
  FEEDS[(Threat feeds\nabuse.ch, Spamhaus, ...)]
  SOC[InfoSec / admins] -->|HTTPS + session cookie| API
  S1 & S2 -->|http_proxy / https_proxy| LB{{L4 load balancer\nsource-IP affinity}}
  LB --> W1 & W2
  W1 & W2 -->|bundle sync (ETag), threat intel (gzip), telemetry (batched)| API
  W1 & W2 -->|INSTREAM| AV
  W1 & W2 -->|authorized traffic only| NET
  API <--> DB
  TI -->|HTTPS, size limit, SSRF guard| FEEDS
  API -->|webhooks| TEAMS[Teams / Slack]
```

## Policy model

Rules are managed in **policy sets** (see [policy-management.md](policy-management.md)): versioned collections
with an owner, an assignment (baseline = all registered servers, standard = groups and/or servers, approvals =
one group, maintained by the request workflow) and a draft → review → publish lifecycle. On every configuration
change the store derives:

1. **Effective group memberships** of every server: static `group_ids` plus every group whose `match_labels`
   selector matches the server's labels.
2. **Effective rules**: the published rules of all enabled sets, each stamped with the scope of its set and
   `policy_set_id`/`policy_set_name`, ordered by set priority.
3. The **compiled index** used by the evaluator (exact-host map, wildcard list, BLOCK first).

The data-plane bundle carries the effective rules, servers with effective groups and the quarantine flag, and
the rendered block page shells; workers therefore never need to understand policy sets.

`*` scopes (baseline sets) cover every source with at least one group membership and every registered
server — never unknown sources, so even a catch-all baseline rule cannot open egress for unregistered machines.

## Policy evaluation

The control-plane (`control-plane/internal/store/evaluate.go`) and the data-plane
(`data-plane/aegis_dp/policy.py`) implement the **same** evaluation order; unit tests on both sides cover
identical cases.

```mermaid
flowchart TD
  A[Request] --> Q{Server quarantined?}
  Q -- yes --> X0[QUARANTINED]
  Q -- no --> B{Path canonicalizable?}
  B -- no --> X1[POLICY_BLOCKED malformed_path]
  B -- yes --> C{Threat intelligence\ndomain / URL / IP / CIDR}
  C -- hit & block --> X2[THREAT_BLOCKED]
  C -- otherwise --> D{Destination hygiene\nloopback/metadata · port · IP literal · internal · punycode}
  D -- forbidden --> X3[POLICY_BLOCKED]
  D --> E{Explicit BLOCK rule?}
  E -- yes --> X4[BLOCKED block_rule]
  E -- no --> F{TLS passthrough rule\n(scoped, never strict isolation)}
  F -- yes --> Y1[TLS_BYPASS]
  F -- no --> G{Learning session active?\n(never internal/IP)}
  G -- yes --> Y2[LEARNING_ALLOWED]
  G -- no --> H{Redirect-object grant?\n(GET/HEAD, 2 min, single hop)}
  H -- yes --> Y3[REDIRECT_OBJECT_ALLOWED]
  H -- no --> I{ALLOW rule\n(internal/IP only explicit)}
  I -- yes --> Y4[ALLOWED]
  I -- no --> X5[BLOCKED default_deny]
```

After a request has been authorized, the data-plane applies **content inspection**:

1. **DLP** (request): secrets in the URL query and body (`dlp_mode`).
2. **Upload limit** (`max_upload_bytes`).
3. **Upstream connection** (`server_connect`): DNS resolution, every resolved IP is checked against
   threat-intel IP lists and internal ranges (DNS-rebinding protection); the vetted IP is then **pinned**
   so a second lookup cannot be rebound.
4. **Response**: SHA-256 against hash IOCs, file type (magic bytes) against `blocked_file_types`,
   ClamAV scan.

### Hook pipeline in the data-plane

| mitmproxy hook | Checks |
|---|---|
| `http_connect` | Server identity from `Proxy-Authorization` (stored per client connection), hard blocks before any TLS handshake (threat intel, ports, IP literals, internal targets). |
| `tls_clienthello` | SNI must equal the CONNECT target (anti domain fronting); scoped no-break TLS passthrough. |
| `requestheaders` | `Host` header and SNI must match the real destination; policy evaluation; block page with a signed block token. |
| `request` | DLP, upload limit. |
| `server_connect` | DNS vetting and IP pinning. |
| `responseheaders` / `response` | Streaming decisions, hash IOCs, file types, ClamAV, redirect lineage, telemetry. |

Non-HTTP payloads inside CONNECT tunnels are never relayed (`rawtcp=false`): mitmproxy parses them as HTTP,
answers `400` and never opens an upstream connection.

## Server identity

A server is identified in this order:

1. `Proxy-Authorization: Basic user:token` (or a bearer token). The token is stored only as SHA-256 and
   rotated in the console. For HTTPS the header comes from the `CONNECT` request and applies to the whole
   connection.
2. A bare user name — **only** if the source IP matches the server's registered IP or subnet.
3. The registered server IP.
4. A server group CIDR (synthetic ID `srv-auto-…`).
5. Otherwise: unregistered, **no** groups (only global rules apply).

The source IP of the servers must therefore reach the data-plane: a Kubernetes Service with
`externalTrafficPolicy: Local`, an L4 load balancer without SNAT, or token authentication.

## Block tokens (self-service access requests)

When a worker blocks a request it signs a **block token**
(`v1.<base64url(json)>.<HMAC-SHA256>` with a key derived from `AEGIS_DATAPLANE_KEY`) containing the server
IP, server ID, URL, method, trace ID and expiry (24 h). The block page and the CLI one-liner submit it to
`POST /api/public/requests`. Only with a valid token does the control-plane accept the server identity and URL;
without a token the TCP source address is used and reviewers see the request flagged as **UNVERIFIED**.
Requests blocked by threat protection (malware, C2, DLP …) or quarantine are not eligible for self-service.

## Block pages

Block page templates are rendered by the control-plane (`internal/blockpage`, Go `html/template` with
contextual escaping) into **shells** per template, locale (en, de) and variant (policy block with request form,
threat/quarantine block without). Request-specific values appear as placeholders (`%%AEGIS:url%%`). The shells
travel in the policy bundle; on a block the worker picks the template of the server's first group that has one
(else the default), selects the locale from `Accept-Language`, and fills the placeholders in a single pass with
HTML-escaped values (control characters stripped for CLI text) and a fresh CSP nonce. If no shell is available
(older control-plane, rendering error) the worker falls back to its built-in page. The console preview uses the
same renderer with sample data.

## High availability

### Control-plane (active-active on PostgreSQL)

With `AEGIS_STORAGE=postgres` any number of equal replicas run behind a load balancer:

- **Configuration** (users, fleet, rules, TLS bypass, sessions, access requests, threat-protection settings,
  revoked sessions) is one versioned JSONB document. Every change runs in a transaction holding
  `SELECT … FOR UPDATE` on that document: writes are **linearizable**, an acknowledged change is never lost,
  and the **audit hash chain** stays linear across all nodes. If a commit fails, the node restores the last
  committed state and returns the error.
- **Change propagation**: `LISTEN/NOTIFY` (milliseconds) plus polling every 10 s as a fallback.
- **Telemetry** (flows, security events, rule hit counters) is append/upsert-only in dedicated tables and
  replicated asynchronously (≈ 1 s) between nodes; retention via `AEGIS_FLOW_RETENTION` /
  `AEGIS_EVENT_RETENTION`.
- **Readiness** (`/readyz`) checks the database; load balancers take a node without database access out of
  rotation. On SIGTERM `/readyz` fails for `AEGIS_SHUTDOWN_DELAY` before the listener closes.
- **Start-up**: replicas wait (with backoff, up to 5 minutes) for the database to become reachable.
- **Shared secrets**: `AEGIS_JWT_SECRET` and `AEGIS_DATAPLANE_KEY` must be identical on all replicas (they are
  not auto-generated in cluster mode). The root CA is created up front with `gen-ca` and distributed.
- **Migration**: when the first node starts against an empty database and finds an existing
  `aegis_state.json`, it imports it including audit history, flows and hit counters.

Node-local by design (not replicated): login throttling, burst detection, SSE connections, threat-feed
downloads (each node downloads and caches feeds itself).

High availability of the database itself is provided by PostgreSQL (CloudNativePG, Patroni, Azure Database
for PostgreSQL, Amazon RDS/Aurora, …).

Verified scenarios (see [testing](testing.md)): concurrent writes on two nodes (no lost updates, intact audit
chain), replica outage during writes (Docker Compose + HAProxy), rolling pod deletion on Kubernetes with
CloudNativePG (40/40 writes succeeded during two pod replacements).

### Data-plane

Workers are stateless and scale horizontally. They keep enforcing the last loaded policy when the
control-plane is unavailable (fail-closed applies only before the very first sync). The only per-worker state
is the short-lived **redirect-object grants** (2 min) — so the load balancer needs **source-IP affinity**
(`sessionAffinity: ClientIP`, HAProxy `balance source`).

### Console

Static files — replicate freely (nginx, CDN, IIS). See [separate console hosting](deployment/separate-console.md).

## Data storage

| Data | File mode | Cluster mode |
|---|---|---|
| Configuration (groups, servers, policy sets with drafts, versions, change requests, governance, block page templates, requests, …) | `aegis_state.json` (atomic, fsync, 0600, `.bak`) | `aegis_config` (JSONB + revision) |
| Effective rules | derived on load; also written to the state file for diagnostics | derived on every node |
| Audit | in the state file (last 2,000) + `audit.jsonl` (complete) | `aegis_audit` (complete) + `audit.jsonl` per node |
| Flows | last 2,000 in the state file | `aegis_flows` (retention) |
| Security events | last 1,000 in the state file | `aegis_security_events` (retention) |
| Rule hit counters | `rule_stats` in the state file | `aegis_rule_stats` (aggregated, pulled every 10 s) |
| Threat-intel feeds | `DATA_DIR/threatintel/*.txt` + `status.json` | per node (cache) |
| Secrets (`jwt.key`, `dataplane.key`, `encryption.key`, …) | `DATA_DIR/secrets/*` (0600) | the platform's secret store |
| Log export spool | `DATA_DIR/export-spool/<sink>` (per node) | per node (`AEGIS_EXPORT_SPOOL_DIR`) |

Passwords: PBKDF2-HMAC-SHA256 with 600,000 iterations (older hashes are upgraded transparently at login).
Proxy tokens and service-account keys: SHA-256 only. Integration secrets inside the configuration (SSO and Defender
client secrets, feed auth headers, log export credentials, webhook URLs) are encrypted with AES-256-GCM
(`AEGIS_ENCRYPTION_KEY`, see [security.md](security.md#encryption-at-rest)) and never returned by the API.
