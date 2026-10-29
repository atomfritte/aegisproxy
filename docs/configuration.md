# Configuration reference

All components are configured exclusively through environment variables (12-factor). Every secret
can alternatively be supplied as a file: `AEGIS_X_FILE=/run/secrets/x` (Docker/Kubernetes secrets,
systemd `LoadCredential`, an ACL-protected file on Windows).

Runtime policy (rules, threat-protection settings, feeds, IOCs, users, fleet inventory) is **not**
configured through the environment. It is managed in the console or through the API, where every change
is versioned and recorded in the audit trail.

## Control-plane (`aegis-control-plane`)

### Network and URLs

| Variable | Default | Description |
|---|---|---|
| `CONTROL_PLANE_PORT` | `8081` | Listen port (all interfaces). |
| `AEGIS_LISTEN_ADDR` | – | Overrides the complete listen address, e.g. `127.0.0.1:8081`. |
| `AEGIS_PUBLIC_URL` | `http://localhost:8081` | **Required in production.** Externally reachable base URL of the API (install scripts, block pages, deep links). Never derived from the `Host` header. `https://` enables Secure cookies and HSTS. |
| `AEGIS_DASHBOARD_URL` | = `AEGIS_PUBLIC_URL` | Console URL when the console is hosted separately (links in block pages and Teams/Slack messages). |
| `AEGIS_PROXY_ADDRESS` | host of `AEGIS_PUBLIC_URL` + `:8080` | `host:port` that servers use as their HTTP(S) proxy (data-plane load balancer). Used in the onboarding snippets shown after rotating a server's proxy token. |
| `AEGIS_TLS_CERT_FILE` / `AEGIS_TLS_KEY_FILE` | – | Native HTTPS (TLS ≥ 1.2). Alternatively terminate TLS at a reverse proxy or ingress controller. |
| `AEGIS_TRUSTED_PROXIES` | – | CIDRs of reverse proxies / load balancers whose `X-Forwarded-For` header is trusted (login and SCIM throttling, CIDR-bound service accounts, audit IPs). Empty = the TCP peer is the client. List exactly the proxy addresses (e.g. `127.0.0.1/32,::1/128` for a local nginx), never whole private ranges: any client inside a trusted range could choose its own address. The right-most untrusted `X-Forwarded-For` entry is used, so appending proxies (`$proxy_add_x_forwarded_for`, HAProxy `option forwardfor`) are safe. See [trusted proxies](#trusted-proxies-and-sign-in-throttling). |
| `AEGIS_TRUSTED_PROXY_HOSTS` | – | Comma-separated DNS names whose current addresses are trusted like `AEGIS_TRUSTED_PROXIES`, for proxies with changing IPs: a headless Service selecting the ingress controller (or console) pods in Kubernetes, service names in Compose. Resolved every 30 s; names containing a dot are resolved as absolute names, so write them fully qualified. A name whose lookup fails keeps its last good addresses for at most 5 minutes. Names only (no IPs or ports). See [trusted proxies](#trusted-proxies-and-sign-in-throttling). |
| `AEGIS_TRUSTED_PROXY_SECRET` (`_FILE`) | – | Shared secret of the trusted reverse proxies (≥ 32 characters of `A-Z a-z 0-9 -._~+/=`). When set, forwarding headers count only from trusted peers that also send `X-Aegis-Proxy-Auth: <secret>`; requests without it are attributed to the peer itself. Required whenever the trusted address is shared with other local accounts (loopback, a Docker bridge gateway). See [trusted proxies](#trusted-proxies-and-sign-in-throttling). |
| `AEGIS_CORS_ORIGINS` | – | Comma-separated origins of a **separately hosted console**, e.g. `https://console.corp.example`. Credentials (the session cookie) are allowed for these origins. |
| `AEGIS_INTERNAL_DOMAINS` | `.internal.corp,.local,.localdomain,.internal,.lan,.home.arpa,.corp` | DNS suffixes of internal destinations. Internal destinations are reachable only through an explicit (non-wildcard) rule; learning sessions and redirect grants never open them. |
| `AEGIS_SHUTDOWN_DELAY` | `3s` | After SIGTERM, `/readyz` fails and the server keeps serving for this long, so load balancers / Kubernetes endpoints stop routing requests before the listener closes (zero-downtime rollouts; the Helm chart uses `10s`). |

#### Trusted proxies and sign-in throttling

The client address drives login and SCIM throttling, CIDR-bound service accounts and the audit trail. The
control-plane takes it from `X-Forwarded-For` only when the TCP peer is a trusted proxy.

- **Shared addresses need the proxy secret:** trusting an address trusts everybody who can connect from it.
  Loopback (`127.0.0.1/32,::1/128` for nginx on the same host) is shared by every local account, and the
  gateway of a Docker network by every local account and container that reaches a published port. Trusting
  such an address without `AEGIS_TRUSTED_PROXY_SECRET` lets any of them choose its client address: use a
  stolen CIDR-bound API key from anywhere, escape the per-source sign-in lockout, or lock out somebody else's
  address. Set the secret and let the proxy send it (`deploy/nginx/aegis-console.conf` includes
  `/etc/aegis/nginx-proxy-auth.conf`, which `install-linux.sh` generates; on Windows
  `Install-AegisControlPlane.ps1` creates the secret for a loopback `-TrustedProxies` and
  `Install-AegisConsole-IIS.ps1 -ApiProxyTarget` lets ARR send it); forwarding headers from a trusted
  address without it are ignored and logged once. The posture report warns about loopback or broad ranges
  (/16 or larger, IPv6 /48) trusted without the secret.

- **Kubernetes ingress:** trust the ingress controller by name instead of by a pod CIDR. A regular Service name
  resolves to its ClusterIP, not to the pod addresses that actually connect to the control-plane. Add a
  headless Service that selects the controller pods and list its fully qualified name, e.g.
  `AEGIS_TRUSTED_PROXY_HOSTS=ingress-nginx-pods.ingress-nginx.svc.cluster.local` (Helm:
  `controlPlane.trustedProxyHosts`):

  ```yaml
  apiVersion: v1
  kind: Service
  metadata: { name: ingress-nginx-pods, namespace: ingress-nginx }
  spec:
    clusterIP: None
    selector: { app.kubernetes.io/name: ingress-nginx, app.kubernetes.io/component: controller }
    ports: [{ name: http, port: 80 }]
  ```

- **Name resolution:** names containing a dot are resolved as absolute names (a trailing dot is added). The
  resolver's search list therefore cannot turn `proxy.corp.example` into
  `proxy.corp.example.<namespace>.svc.cluster.local`. Single-label names (`lb`, `console`) go through the
  search list and are meant for Docker Compose service names only.
- **Failed lookups:** when a lookup fails, that name keeps only its own last good addresses, for at most
  5 minutes. After that they are dropped with a warning, and requests from them are handled as coming from an
  untrusted proxy until the name resolves again. Metrics: `aegis_trusted_proxy_host_addresses{host}`,
  `aegis_trusted_proxy_host_lookup_age_seconds{host}` (alert above 300),
  `aegis_trusted_proxy_host_lookup_failures_total{host}` and `aegis_trusted_proxy_host_expired_total{host}`.
- **Untrusted proxy:** forwarding headers (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`) from a peer that is
  not trusted are logged once per proxy address. Sign-in and SCIM throttling then count failures per proxy
  *and* claimed client (`throttle_source` in the `login failed` log line), so one client's failures behind a
  misconfigured ingress do not lock out everybody else behind it. A client that rotates the claimed address
  still hits the account lockout and a ceiling of 50 failures per proxy address; that ceiling locks for at
  most one minute at a time, as break-glass sign-ins behind the proxy depend on it too. Public endpoints (CA
  download, self-service requests) allow everything behind one such proxy 5 times the per-client rate limit.
  Any client can send these headers, so a client that connects directly gets at most these ceilings. This is
  a fallback, not a configuration: audit IPs and CIDR-bound service accounts still see the proxy address.
  IPv6 clients and proxies are throttled per /64.
- **Break-glass accounts:** failures lock a break-glass account only for the source they come from (5
  failures, then exponential up to 15 minutes). Account-wide, the lock applies only after 1,000 failures and
  lasts at most 1 minute, so an attacker who knows the name cannot keep emergency access locked.
- **Always-available path:** sign in with a break-glass account over a path that bypasses the proxy
  (`kubectl port-forward` to the control-plane Service, the host's loopback interface). That path has its
  own source address, so failures that came through the proxy do not lock it, apart from the bounded
  account-wide lock above.

### Sessions and cookies

| Variable | Default | Description |
|---|---|---|
| `AEGIS_SESSION_TTL` | `8h` | Lifetime of a console session (5m – 168h). |
| `AEGIS_COOKIE_SECURE` | `true` for `https://` | Secure flag of the session cookie. |
| `AEGIS_COOKIE_SAMESITE` | `strict` | `strict` \| `lax` \| `none`. Use `none` only when console and API are on **different sites** (requires HTTPS). `console.corp.example` + `api.corp.example` are the same site and work with `strict`. |
| `AEGIS_COOKIE_DOMAIN` | – | Cookie domain (usually leave empty). |

### Secrets

| Variable | Default | Description |
|---|---|---|
| `AEGIS_JWT_SECRET` | auto (file) | Session-token signing key (≥ 32 characters). If not set, it is generated once and stored in `DATA_DIR/secrets/jwt.key` (0600). **Required in cluster mode and identical on every replica.** |
| `AEGIS_DATAPLANE_KEY` | auto (file) | Shared secret with every data-plane worker (≥ 32 characters). Authenticates workers and signs block tokens. If not set: `DATA_DIR/secrets/dataplane.key`. **Required in cluster mode.** |
| `AEGIS_ENCRYPTION_KEY` | auto (file) | Encrypts secrets stored in the configuration (feed API keys, log export credentials, SSO and Defender client secrets, webhook URLs) with AES-256-GCM. Any random string of ≥ 32 characters (`openssl rand -hex 32`); the AES key is derived from it with SHA-256. Must differ from the JWT secret and the data-plane key. If not set (file mode only), it is generated once in `DATA_DIR/secrets/encryption.key` (0600). **Required in cluster mode and identical on every replica.** Back it up separately from the data: without it the stored configuration cannot be loaded. See [rotation](operations.md#encryption-key). |
| `AEGIS_ENCRYPTION_KEY_PREVIOUS` | – | Previous encryption key, used for decryption only during a key rotation. |
| `AEGIS_BOOTSTRAP_ADMIN_PASSWORD` | random | Password for the bootstrap Super Admin `admin`, applied whenever no usable Super Admin exists. If not set, a random password is written to `DATA_DIR/secrets/initial-admin-password`. |
| `AEGIS_METRICS_TOKEN` | – | Bearer token required for `/metrics`. Empty = `/metrics` is unauthenticated (expose on internal networks only). |
| `AEGIS_DATABASE_URL` | – | PostgreSQL DSN for cluster mode, e.g. `postgres://aegis:***@db:5432/aegis?sslmode=verify-full`. |

Publicly known default secrets of earlier releases are rejected at start-up.

### Persistence and high availability

| Variable | Default | Description |
|---|---|---|
| `AEGIS_STORAGE` | `file` | `file`: single node, state in `DATA_DIR/aegis_state.json` (atomic writes, fsync, 0600, `.bak`). `postgres`: active-active cluster with any number of replicas (see [architecture](architecture.md#high-availability)). |
| `DATA_DIR` | `./data` | State file, audit JSONL, threat-intel cache, generated secrets. Only a cache in cluster mode (may be ephemeral). |
| `CERTS_DIR` | `../certs` | Enterprise root CA (`mitmproxy-ca-cert.pem`). Generated if missing (single node). In clusters, create it up front with `aegis-control-plane gen-ca <dir>` and distribute it as a secret. |
| `AEGIS_FLOW_RETENTION` | `168h` | Retention of flow telemetry in PostgreSQL. |
| `AEGIS_EVENT_RETENTION` | `2160h` | Retention of security events in PostgreSQL. Audit events are never deleted automatically. |
| `AEGIS_AUDIT_LOG` | `DATA_DIR/audit.jsonl` | Append-only audit log (JSON Lines) for SIEM ingestion and long-term archiving. |
| `AEGIS_AUDIT_ROTATE_MB` | `256` | Size at which the control-plane rotates the audit log itself (`audit.jsonl-YYYYMMDDhhmmss`, older generations gzip-compressed, never deleted). `0` = only external rotation (logrotate renaming). Required on Windows and in containers, where nothing else can rotate the open file. See [Operations](operations.md). |
| `AEGIS_EXPORT_DIR` | `DATA_DIR/export` | Directory of `file` log export destinations ([log-export.md](log-export.md)). |
| `AEGIS_EXPORT_SPOOL_DIR` | `DATA_DIR/export-spool` | Durable spool of records not yet accepted by a log export destination (one sub-directory per destination, also holding its audit cursor and `dead-letter.jsonl`). Must be persistent: audit records lost in a crash are replayed from the cursor kept here. |
| `AEGIS_EXPORT_HEC_ACK_ATTEMPTS` | `5` | Splunk HEC with indexer acknowledgement: acknowledgement timeouts (one per resend) after which records are moved to the dead-letter file and an `EXPORT_DELIVERY` security event is raised ([log-export.md](log-export.md#delivery-guarantees)). |

### Threat intelligence

| Variable | Default | Description |
|---|---|---|
| `AEGIS_THREATINTEL_AUTOUPDATE` | `true` | Download feeds automatically. Set `false` in air-gapped environments (cached feeds + custom IOCs only). |
| `AEGIS_FEED_HTTP_PROXY` | – | Explicit proxy for feed downloads (otherwise `HTTPS_PROXY`/`NO_PROXY` from the environment). |

### Operations

| Variable | Default | Description |
|---|---|---|
| `AEGIS_UI_DIR` | auto | Directory of the built console (`frontend/dist`). Set in the all-in-one image. Empty = API only. |
| `AEGIS_DOCS_URL` | – | Base URL of this documentation (the `docs/` folder, e.g. your internal Git server or wiki mirror). When set, the security posture page links its remediation hints, e.g. `https://git.corp.example/aegisproxy/-/blob/main/docs`. |
| `AEGIS_LOG_FORMAT` | `json` | `json` \| `text`. |
| `AEGIS_LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `AEGIS_LOG_FILE` | – | Log to a file instead of stdout (e.g. when running as a Windows service). |
| `AEGIS_DEMO_MODE` | `false` | Showcase data with **publicly known** demo passwords and synthetic traffic. Never use in production. |

### Commands

```
aegis-control-plane                  # run the server
aegis-control-plane healthcheck      # liveness probe (exit code), used by the container HEALTHCHECK
aegis-control-plane gen-ca <dir>     # pre-provision the enterprise root CA (clusters / Kubernetes)
aegis-control-plane gen-csr <dir> "CN=AegisProxy Issuing CA,O=Example Corp,C=DE"
                                     # key + CSR for a subordinate CA issued by your corporate PKI
aegis-control-plane import-ca <dir> <issued-cert.pem> [chain.pem]
                                     # install the certificate issued for that CSR (see operations.md)
aegis-control-plane version
```

## Data-plane (mitmproxy worker)

| Variable | Default | Description |
|---|---|---|
| `CONTROL_PLANE_URL` | `http://localhost:8081` | Control-plane base URL (behind a load balancer in cluster mode). HTTPS recommended. |
| `AEGIS_DATAPLANE_KEY` | – | **Required.** Same value as on the control-plane. |
| `AEGIS_CONTROL_PLANE_CA_FILE` | system trust | CA bundle used to verify the control-plane certificate. |
| `AEGIS_PUBLIC_URL` / `DASHBOARD_URL` | from bundle | Fallback URLs for block pages until the policy bundle provides them. |
| `AEGIS_WORKER_ID` | hostname | Worker name (heartbeat in the console, telemetry). |
| `AEGIS_FAIL_MODE` | `closed` | Behaviour **before** the first successful policy sync: `closed` answers 503. Afterwards the last known policy is enforced while the control-plane is unreachable — indefinitely unless `AEGIS_POLICY_MAX_AGE` is set. |
| `AEGIS_POLICY_MAX_AGE` | `0` (no limit) | Duration (`15m`, `1h`, `900s`; at least `max(30s, 5 × AEGIS_SYNC_INTERVAL_SECONDS)`). When the last successful policy sync is older, the worker fails closed: new requests and tunnels get `503 policy_stale` (`Retry-After: 30`), long-lived connections are closed, `/readyz` fails and `aegis_dp_policy_stale` is 1. It recovers with the next successful sync. Recommended (e.g. `10m`): without it, a worker cut off from the control-plane never learns of quarantines or revocations. Helm, Docker Compose, the systemd unit and the Windows installer default to `10m`. |
| `AEGIS_FLOW_SPOOL_DIR` | – (memory only) | Directory for a durable traffic-record spool (fsync'd segments). Records then survive worker restarts and control-plane outages beyond the 20,000-record memory queue. Private to one worker, writable only by it, and on disk (not tmpfs): records survive exactly as long as the directory does. A Kubernetes `emptyDir` on disk survives container restarts but not the deletion of the pod; a volume, host path or state directory survives that too. The shipped deployments set it ([defaults](operations.md#traffic-telemetry-delivery)). |
| `AEGIS_FLOW_SPOOL_MAX` | `256m` | Size limit of the spool (at least `1m`). When it is full the oldest records are discarded and counted (`aegis_dp_flows_dropped_total{reason="spool_full"}`). |
| `AEGIS_PROXY_MODE` | `regular` | `regular` (explicit proxy, strict Host/SNI checks) \| `transparent`. In transparent (and other non-regular) modes the Host header / TLS SNI is only trusted when the original destination IP is among its DNS answers (resolved by the worker, cached 30 s); otherwise the request is blocked (`host_mismatch` / `sni_mismatch`), and TLS passthrough requires the same binding. Clients and workers must therefore use the same DNS view (split-horizon DNS can cause false blocks). |
| `AEGIS_CLAMD_ADDRESS` | – | `tcp://clamav:3310` or `unix:///run/clamav/clamd.ctl`. Empty = no antivirus (the policy switch has no effect). |
| `AEGIS_CLAMD_TIMEOUT_SECONDS` | `60` | Maximum scan duration per download. |
| `AEGIS_MAGIC_HOSTS` | `aegis.ca,mitm.it` | Host names on which the worker serves the CA certificate and installers itself (`http://aegis.ca/`). |
| `AEGIS_OPS_ADDR` | `0.0.0.0:9091` | Ops endpoint: `/healthz`, `/readyz`, `/metrics` (Prometheus). |
| `AEGIS_ACCESS_LOG` | `off` | Local access log: `stdout`, `stderr`, a file path, `syslog://host:514`, `syslog+tcp://host:514`, `syslog:///dev/log`. See [log-export.md](log-export.md#data-plane-access-log). |
| `AEGIS_ACCESS_LOG_FORMAT` | `squid` | `squid`, `combined` or `json`. |
| `AEGIS_ACCESS_LOG_ROTATE_MB` | `0` (Linux), `100` (Windows) | Size-based rotation of a file access log by the worker itself; `0` = external rotation (logrotate). |
| `AEGIS_ACCESS_LOG_KEEP` | `10` | Generations kept by the worker's own rotation. |
| `AEGIS_SYNC_INTERVAL_SECONDS` | `2` | Policy bundle sync (ETag, 304 when unchanged). |
| `AEGIS_THREAT_SYNC_INTERVAL_SECONDS` | `30` | Threat-intel sync (gzip, ETag). |
| `AEGIS_LOG_LEVEL` | `INFO` | Log level of the addon. |
| `AEGIS_BUFFER_BUDGET` | `min(512m, AEGIS_BODY_SIZE_LIMIT)` | Bytes of message bodies one worker holds for inspection at the same time (`k`/`m`/`g` suffixes, at least `1m`); see [memory sizing](#data-plane-memory-sizing). |
| `AEGIS_BUFFER_CLIENT_SHARE` | `25%` | Part of `AEGIS_BUFFER_BUDGET` one client (its server identity, else its source address) may hold, `1%`–`100%`; never less than one complete scan (2 × the per-flow limit). See [memory sizing](#data-plane-memory-sizing). |

Container-specific (`data-plane/entrypoint.sh`):

| Variable | Default | Description |
|---|---|---|
| `AEGIS_CA_DIR` | `/certs` | Read-only directory containing `mitmproxy-ca.pem` (private key + certificate). |
| `AEGIS_CONFDIR` | `/tmp/mitmproxy` | Private, writable mitmproxy configuration directory. |
| `AEGIS_LISTEN_HOST` / `AEGIS_LISTEN_PORT` | `0.0.0.0` / `8080` | Proxy listener. |
| `AEGIS_BODY_SIZE_LIMIT` | `1g` | mitmproxy `body_size_limit`: the largest request or response body relayed at all (larger messages are refused with 413/502). Not a memory figure — see below. |

Regardless of the command line, the addon enforces `connection_strategy=lazy` (no upstream connection
before a request is authorized), `ssl_insecure=false` (upstream certificates are always verified) and
`rawtcp=false` (no raw TCP through CONNECT tunnels while `block_raw_tcp` is active).

### Data-plane memory sizing

A worker keeps a message body in memory only while an inspection needs it; everything else is streamed:

| Body | Handling |
|---|---|
| Download, no inspection active | streamed; only bodies with a `Content-Length` of at most 8 MiB are buffered (within the budget) |
| Download, inspection active | buffered up to `av_max_scan_bytes`; a larger `Content-Length` is decided up front, a body without `Content-Length` when it outgrows the limit (`av_oversize_action`: `allow` streams the rest unscanned, flag `AV_UNSCANNED:oversize`; `block` sends a 403 and discards the rest) |
| Upload | buffered only for DLP, ICAP REQMOD or the `max_upload_bytes` check of a body without `Content-Length`, up to `max(dlp_max_scan_bytes, icap_max_bytes when REQMOD is set, 8 MiB)` (or `max_upload_bytes` when that is larger); beyond that `dlp_oversize_action` decides (`allow`: streamed, `DLP_UNSCANNED:oversize`; `block`: 413). Uploads of blocked requests are discarded as they arrive |

All buffered bodies of a worker — plus decoded copies kept while scan engines run — share the
`AEGIS_BUFFER_BUDGET`. Only bytes that have actually arrived are counted, chunk by chunk: a `Content-Length`
decides "too large" up front but reserves nothing, so idle connections announcing large bodies hold no budget.
One client — its server identity (proxy token or registered address), else its source address — may hold at
most `AEGIS_BUFFER_CLIENT_SHARE` of the budget (default 25 %, but always enough for one complete scan), so a
single client cannot use up the inspection capacity of everyone else on the worker.

A body that does not fit the budget or the client's share is **busy**, which is not the same as oversize:

| Busy body | Handling |
|---|---|
| Upload, DLP or ICAP REQMOD in `block` mode, or `max_upload_bytes` check of a body without `Content-Length` | 503 `inspection_busy` with `Retry-After: 5` — whatever `dlp_oversize_action` says |
| Download, an inspection that can block is active (blocked file types, threat-intel hashes in `block` mode, ClamAV / YARA / ICAP RESPMOD in `block` mode) | 503 `inspection_busy` with `Retry-After: 5` — whatever `av_oversize_action` says |
| Monitor-only inspections, or no inspection | streamed and flagged `…:busy` (`AV_UNSCANNED:busy`, `DLP_UNSCANNED:busy`, `ICAP_UNSCANNED:busy`) |

`dlp_oversize_action` / `av_oversize_action` therefore apply only to bodies that are larger than the scan
limit, never to a capacity shortage: exhausting the budget cannot turn an enforcing inspection off. The metrics
`aegis_dp_buffered_bytes`, `aegis_dp_buffered_bytes_peak`, `aegis_dp_buffer_budget_bytes`,
`aegis_dp_buffer_clients`, `aegis_dp_buffered_bytes_top_client` (bytes held by the client holding the most) and
`aegis_dp_buffer_limited_total{direction,reason}` show the usage; a `top_client` value at its share together
with rising `reason="busy"` counts points to one client exhausting its share.

Plan the worker's memory limit as roughly **2 × budget + 256 MiB** (mitmproxy copies a body once when it is
complete; Python, YARA rules and TLS state need the rest). The defaults (budget 512 MiB) fit the Helm chart's
2 GiB limit; lower `AEGIS_BUFFER_BUDGET` for smaller hosts, and raise it together with the memory limit when
many concurrent transfers should be scanned instead of being answered with 503 `inspection_busy`.

## Console (separate hosting, `frontend/Dockerfile`)

| Variable | Description |
|---|---|
| `AEGIS_API_BASE_URL` | Origin of the API when it is not on the console's origin (e.g. `https://aegis-api.corp.example`). Written into `/config.js` at runtime and added to the CSP `connect-src`. |
| `AEGIS_API_UPSTREAM` | Alternative: nginx proxies `/api/` to this upstream (same origin, no CORS configuration needed), e.g. `http://control-plane:8081`. |
| `AEGIS_TRUSTED_PROXY_SECRET` (`_FILE`) | With `AEGIS_API_UPSTREAM`: sent to the control-plane as `X-Aegis-Proxy-Auth`, so that only this console (not every container sharing its address) can supply `X-Forwarded-For`. Set the same value on the control-plane. Not needed when the control-plane trusts the console by a name that resolves to it alone (`AEGIS_TRUSTED_PROXY_HOSTS`, as in the HA compose stack and the Helm chart). |

For static hosting without the container (CDN, S3, Azure Static Web Apps, IIS) edit `config.js` in the
web root:

```js
window.__AEGIS_CONFIG__ = { apiBaseUrl: "https://aegis-api.corp.example" };
```

For an API on a different origin also set `AEGIS_CORS_ORIGINS=https://console.corp.example` on the
control-plane (and `AEGIS_COOKIE_SAMESITE=none` if console and API are on different *sites*).

## Security policy (console → Threat Protection → Protection Policy)

| Field | Default | Meaning |
|---|---|---|
| `threat_intel_mode` | `block` | `off` \| `monitor` \| `block` for domains, URLs, IPs/CIDRs (including resolved destination IPs) and file hashes. |
| `av_enabled` / `av_mode` | `true` / `block` | ClamAV scan of downloaded content. `monitor` only reports. |
| `av_fail_mode` | `open` | Behaviour on scanner errors: `open` (allow + event) or `closed` (503). |
| `av_max_scan_bytes` | 25 MiB | Larger downloads are not scanned (align with clamd `StreamMaxLength`). |
| `av_oversize_action` | `allow` | `allow` (stream, flag `AV_UNSCANNED`) or `block`. |
| `dlp_mode` | `monitor` | `off` \| `monitor` \| `block` — secrets in outbound URLs and bodies. |
| `dlp_max_scan_bytes` | 1 MiB | The decoded upload is scanned completely up to this size (4 KiB – 64 MiB). |
| `dlp_oversize_action` | `allow` | Uploads larger than the DLP or ICAP REQMOD scan limit: `allow` (forward, flag `DLP_UNSCANNED:oversize` / `ICAP_UNSCANNED:oversize`) or `block` (413). |
| `dlp_detectors` | all | `private_key`, `aws_access_key`, `aws_secret_key`, `github_token`, `gitlab_token`, `slack_token`, `slack_webhook`, `google_api_key`, `stripe_key`, `azure_storage_key`, `npm_token`, `pypi_token`, `credit_card` (Luhn), `unix_shadow`. |
| `blocked_file_types` | – | File types blocked globally (magic bytes): `pe`, `elf`, `macho`, `java_class`, `msi_ole`, `script`, `jar`, `apk`, `zip`, `archive`, `office_macro`, `iso`. |
| `group_blocked_file_types` | – | Additional per-group blocks, e.g. `{"grp-db-vault": ["pe","elf","script"]}`. |
| `block_ip_literals` | `true` | Bare IP destinations require an explicit rule. |
| `block_private_destinations` | `true` | Internal destinations (RFC 1918, ULA, CGNAT, documentation and reserved ranges, internal suffixes, also embedded in NAT64/6to4 addresses; [table](threat-protection.md#protocol-and-destination-hygiene)) require an explicit rule; DNS-rebinding protection. Loopback, link-local and cloud metadata are **always** blocked. |
| `block_raw_tcp` | `true` | No non-HTTP protocols through CONNECT tunnels. |
| `allowed_ports` | `80, 443` | Allowed destination ports. |
| `punycode_mode` | `monitor` | IDN homograph protection. |
| `max_upload_bytes` | `0` (off) | Maximum request body size (exfiltration brake). |
| `blocked_burst_threshold` | `30` | Anomaly event when a server exceeds this many blocked requests per minute (beaconing / scanning). |
| `telemetry_query_redaction` | `sensitive` | Query strings of recorded URLs (traffic records, worker access log, log export, block pages): `sensitive` replaces the values of credential-like parameters (`token`, `sig`, `password`, `api_key`, `X-Amz-Signature`, SAS and CloudFront signatures, …) with `REDACTED`; `all` drops the query string; `none` records it unchanged. User info (`user:pass@`) is always replaced. Applied by the worker and again by the control-plane; test vectors in `testdata/redaction_vectors.json`. |
| `yara_mode` / `yara_max_bytes` | `off` / 25 MiB | YARA scanning of downloads with the rule sets under Threat Protection: `off` \| `monitor` \| `block`; bytes scanned per body (1 MiB – 2 GiB). |
| `icap_respmod_url` / `icap_reqmod_url` | – | ICAP services for downloads / uploads: `icap://host:1344/service` or `icaps://host:11344/service`. |
| `icap_mode` / `icap_fail_mode` | `block` / `open` | Act on ICAP findings (`block` \| `monitor`); behaviour when the engine fails (`open` \| `closed` = 503). |
| `icap_timeout_seconds` / `icap_max_bytes` | 30 / 25 MiB | Per-request timeout (1 – 600 s); larger bodies are not sent to the engine (1 MiB – 2 GiB). |
| `icap_allow_modified` | `true` | Deliver content sanitized by the engine (CDR); otherwise block it. |
| `icap_tls_skip_verify` / `icap_ca_cert_pem` | `false` / – | TLS verification for `icaps://`. |

Details: [threat-protection.md](threat-protection.md#download-inspection-pipeline).
