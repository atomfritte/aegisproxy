# Operations

## Day-one checklist

1. Sign in as `admin` with the bootstrap password, change it and delete `DATA_DIR/secrets/initial-admin-password`.
   Connect single sign-on (Entra ID or another OIDC provider) and map IdP groups to roles, or create personal
   accounts (**Settings → Identity**). Keep `admin` (or one or two dedicated accounts) as
   [break-glass accounts](identity.md#break-glass-accounts) and then disable password login for everybody else.
2. Model the fleet: **Server Fleet** → groups (CIDRs, owner team, strict isolation for zero-internet tiers) and
   servers (IP, proxy user). Rotate a proxy token for servers that do not have a stable IP.
3. Whitelist: create rules manually, approve access requests, or record a **learning session** on a reference
   server and publish the compiled rules to whole groups.
4. Threat protection: review feeds, enable ClamAV, start DLP in `monitor` mode.
5. Notifications: Teams/Slack webhooks, enable *notify security events*. Forward the audit trail to your SIEM
   (**Settings → Integrations → Log export**).
6. Roll out the CA and proxy configuration to servers (see below). With a corporate PKI, let it issue the
   interception CA first ([corporate PKI](#corporate-pki-subordinate-ca)).
7. Open the [security posture](#security-posture) page and work through the open items.

## Rolling out to servers

The quickest path per server: **Servers → Register**, then **Rotate token** — the console shows the proxy
token once together with ready-to-paste Linux and Windows snippets (CA trust, proxy environment, package
managers, verification). Bulk registration: **Servers → Import** (CSV from your CMDB, dry run first). Unknown
machines that already send traffic appear under **Servers → Discovered**. Details:
[policy-management.md](policy-management.md#fleet-management).

Never pipe a downloaded installer into a shell. **TLS & CA** in the console (and `linux_command` /
`windows_command` of `GET /api/public/ca/info`) shows one-liners that download the installer, check it
against the SHA-256 of the script this deployment serves and only then run it. Manually:

Linux:

```bash
curl -fsSLo aegis-ca-install.sh https://aegis.corp.example/api/public/ca/install-linux.sh
echo '<linux_script_sha256 from the console>  aegis-ca-install.sh' | sha256sum -c - && sudo bash aegis-ca-install.sh
cat <<'EOF' | sudo tee /etc/profile.d/aegis-proxy.sh
export http_proxy=http://svc-web-01:<token>@aegis-proxy.corp.example:8080
export https_proxy=$http_proxy HTTP_PROXY=$http_proxy HTTPS_PROXY=$http_proxy
export no_proxy=localhost,127.0.0.1,.corp.example
EOF
```

Windows (elevated PowerShell):

```powershell
$env:AEGIS_PROXY = "aegis-proxy.corp.example:8080"
$f = Join-Path $env:TEMP 'aegis-ca-install.ps1'
iwr -UseBasicParsing https://aegis.corp.example/api/public/ca/install-windows.ps1 -OutFile $f
if ((Get-FileHash $f -Algorithm SHA256).Hash -ne '<windows_script_sha256 from the console>') { throw 'SHA-256 mismatch' }
powershell -NoProfile -ExecutionPolicy Bypass -File $f
```

Both installers pin the CA by its SHA-256 fingerprint (shown in the console under **TLS & CA**). They refuse a
download that holds more than the one pinned certificate (an extra root in a PEM bundle, PKCS#7 or PFX), and
they add only the verified certificate to the trust store, never the downloaded file. Copy the commands from
the console over https: with a plain-http `AEGIS_PUBLIC_URL` the script hash is the only protection against
a script altered in transit (both installers print a warning in that case). For other tooling,
`GET /api/public/ca/info` also returns `pem_sha256` and `der_sha256`, the SHA-256 of the exact download files
(e.g. for a Dockerfile `ADD --checksum=sha256:…`).
For larger fleets distribute the CA and proxy settings with configuration management (Ansible, GPO, Intune,
cloud-init).

Docker/containerd and Kubernetes nodes need the proxy in their service environment (`systemctl edit docker`
→ `Environment=HTTPS_PROXY=…`) and the CA in the host trust store.

## Access requests

Blocked requests show a block page (browsers) or a CLI message with a one-liner — branded per group, see
[policy-management.md](policy-management.md#block-pages). Requests carrying a data-plane–signed block token
are marked **Verified**. Reviewers can adjust host/path patterns, methods, follow redirects, target groups and
the granted duration; approved rules default to `GET/HEAD` (+ the requested method) and land in the group's
approvals policy set. SLA, assignment, comments, bulk review, extension and revocation are described in
[policy-management.md](policy-management.md#access-requests).

## Monitoring

| Endpoint | Component | Content |
|---|---|---|
| `GET /healthz` | control-plane | liveness |
| `GET /readyz` | control-plane | state loaded + storage reachable; fails while draining |
| `GET /metrics` | control-plane | HTTP metrics, logins, evaluations, flows by verdict, pending requests, open security events, threat-intel indicators and feed age, healthy data-planes, audit log writable (`AEGIS_METRICS_TOKEN`) |
| `GET :9091/healthz`, `/readyz` | data-plane | liveness / policy loaded |
| `GET :9091/metrics` | data-plane | flows by verdict, AV scans and duration, clamd availability, YARA and ICAP scans and duration, policy revision and sync age, telemetry queue |
| `GET /api/system/posture` | control-plane | security posture score and checks ([below](#security-posture)) |

Suggested alerts (shipped as a `PrometheusRule` in the Helm chart: `metrics.prometheusRule.enabled=true`):

- `increase(aegis_dp_hook_errors_total[10m]) > 0` — a worker blocked traffic after an internal error (fail-closed)
- `aegis_dataplanes_healthy < expected` (control-plane view of worker heartbeats)
- `aegis_dp_policy_sync_age_seconds > 120`
- `aegis_dp_clamd_available == 0`
- `increase(aegis_dp_icap_scans_total{result="error"}[15m]) > 0`, or a data-plane reporting `icap_status`
  `…=down` / `yara_status` `error:…` (**Settings → Data planes**)
- `aegis_threatintel_feed_age_seconds > 2 × refresh interval`
- `aegis_security_events_open` increasing, and any `critical` event via Teams/Slack
- `aegis_access_requests_pending > 0` for more than one business day
- `aegis_export_spool_bytes > 0` for 15 minutes or `increase(aegis_export_records_dropped_total[1h]) > 0`
  (a log export destination is unreachable or rejecting records)
- `aegis_audit_log_writable == 0` — the audit log cannot be written (disk full, replaced file); with file
  storage configuration changes are refused until it recovers ([audit trail](#audit-trail); not yet part of the
  shipped `PrometheusRule`)

Logs are structured JSON (`AEGIS_LOG_FORMAT=json`). Audit events are written as `msg="audit"` log lines and to
`audit.jsonl`. To forward audit, traffic ("browsing") and security records to a SIEM or observability platform
(syslog/rsyslog, OpenTelemetry, Splunk, Elastic/OpenSearch, Sentinel, Datadog, Loki, webhooks, files) configure
**Settings → Integrations → Log export** — see [log-export.md](log-export.md).

## Audit trail

Every administrative action is an audit event (actor, role, action, category, entity, summary, before/after
state, affected groups) linked into a hash chain (`prev_hash`, `event_hash`). Since 2.1 each `event_hash` is an
HMAC-SHA256 (`hash_version: 2`) over a length-prefixed encoding of the event, keyed with a random per-installation
audit chain key that is stored encrypted with `AEGIS_ENCRYPTION_KEY`: somebody with write access to the database or
the state file alone cannot recompute a valid chain after changing, inserting or deleting events. A configuration
whose audit chain key (or anchor, below) is stored unencrypted was modified outside AegisProxy: the control-plane
refuses to start with it. The console keeps the latest 2,000 events in memory; the complete trail lives in
`audit.jsonl` (file mode) or the `aegis_audit` table (cluster mode, never deleted automatically).

**Trail anchor.** The configuration also holds a sealed *anchor* (encrypted, keyed with the audit chain key): the
hash the trail starts from (genesis, or a retention point) and the end of the pre-2.1 prefix. Events written
before 2.1 keep their unkeyed SHA-256 hash (`hash_version` absent) and stay verifiable — but only as that sealed
prefix: an unkeyed event after the first keyed one, or anywhere in a trail that has no pre-2.1 prefix, fails the
verification (a "hash-version downgrade": the unkeyed hash can be recomputed by anyone). The anchor is sealed at
the first start of a release that has it: from the complete trail on upgrade (recorded as `AUDIT_ANCHOR_SEALED`),
at initialization for new installations. During a rolling cluster upgrade, replicas of older releases drop it from
the configuration when they write; it is sealed again (and audited again) once they are gone.

| Endpoint | Content |
|---|---|
| `GET /api/audit/verify` | `{valid, events_checked, first_id, last_id, legacy_events, starts_at_genesis, head_matches[, error]}` — checks every hash and link of the **complete** trail (same sources as the export), that it starts at its sealed origin, that unkeyed events occur only in the sealed pre-2.1 prefix, and that it reaches the newest event known to the control-plane (missing newest events or generations fail); Super Admin, InfoSec, Auditor |
| `GET /api/audit/export` | the **complete** trail as JSON Lines, oldest first: cluster mode streams the `aegis_audit` table; file mode streams `audit.jsonl` and all its rotated generations (`audit.jsonl-YYYYMMDD[.gz]`, `audit.jsonl-YYYYMMDDhhmmss[.gz]`, `audit.jsonl.N[.gz]`) in the same directory — also while `audit.jsonl` itself is missing after a logrotate rename — as a consistent snapshot of the moment the export started |
| `POST /api/audit/retention` | after you removed old generations (or `aegis_audit` rows) for retention: verifies the remaining trail and re-seals its start (Super Admin; recorded as `AUDIT_RETENTION_APPLIED`). Until then the verification reports the missing start |

The export is streamed (no size limit, no write timeout) and is available to Super Admins, InfoSec Approvers and
Auditors (Team Leads see only the audit events of their groups in the console). Generations are ordered by
their content (the first event's revision and chain link), not by their names, so logrotate's local-date names,
the built-in UTC names and clock steps cannot reorder the trail. Offline, the links can be checked without a
key: every event's `prev_hash` equals the `event_hash` of the event before it, and the first event's `prev_hash`
is 64 zeros. Pre-2.1 events can also be recomputed as SHA-256 of `prev_hash|id|revision|timestamp (RFC 3339 with
nanoseconds, UTC)|actor|actor_role|action|category|entity_type|entity_id|entity_name|summary|scope_groups
(comma-joined)|before_state|after_state|rollback rule`; version-2 hashes need the audit chain key, so use
`GET /api/audit/verify` (reference implementation: `computeAuditEventHash` in
`control-plane/internal/store/audit.go`). Shipping the audit stream to a SIEM in real time gives you an
independent copy to compare against — the only defence against somebody who controls the server and replaces
state, key and trail together.

**Durability (file mode).** Every event is written and flushed (`fsync`) to `audit.jsonl` before the change is
acknowledged; the state file follows within a second. After a crash in between, the next start adopts the events
that reached the log but not the state into the trail and records `AUDIT_TRAIL_RECOVERED` (their configuration
changes were not saved and are not in effect); events that reached the state but not the log are appended to the
log. A failed or partial write (disk full) is cut off again — the log never keeps a torn line — and while the log
cannot be written the control-plane refuses configuration changes with HTTP 503 (`audit log unavailable`); the
posture check *Audit log writable* fails, `aegis_audit_log_writable` is 0 and `/readyz` reports
`"audit_log": "unavailable"` (reads and policy distribution continue). Changes resume, and the log is completed,
as soon as it can be written again. The audit log and its generations must be regular files: a symbolic link or
FIFO at their names is refused (point `AEGIS_AUDIT_LOG` at the real location instead of linking it).

Rotation works on every platform without losing events:

* **Built in (all platforms, default):** when `audit.jsonl` reaches `AEGIS_AUDIT_ROTATE_MB` (default 256 MB) the
  control-plane renames it to `audit.jsonl-YYYYMMDDhhmmss` (UTC) and continues in a new file. Older generations
  are gzip-compressed one rotation later (like logrotate's `delaycompress`, so a log shipper can finish reading the
  newest one); an existing generation, compressed or not, is never overwritten. An export or verification never
  delays rotation or compression: it reads from the files it opened at its start. This is the only rotation on
  Windows, which cannot rename a file another process holds open, and in containers.
* **logrotate (Linux package, `deploy/systemd/aegis.logrotate`):** additionally rotates monthly by **renaming**
  (`dateext`, `nocreate`); the control-plane notices the rename and continues in a new file on the next event.
  Earlier releases used `copytruncate`, which could lose lines written during rotation.

Rotated generations are **never deleted** by AegisProxy: keep them for your retention period (the export and the
verification include them). To delete old generations according to your retention policy, remove the oldest ones
and call `POST /api/audit/retention`; deleting them without it makes the verification fail. Set
`AEGIS_AUDIT_ROTATE_MB=0` only if an external tool rotates the file. Deleting `aegis_state.json` while keeping the
audit log starts a new chain (with a new key) behind the old one, which then no longer verifies: archive
`audit.jsonl*` before such a reset. Migrating from file to cluster storage imports the complete trail (audit log
with all generations, plus events only the state held) into `aegis_audit`; events already stored are skipped, so a
repeated migration does not duplicate them.

## Security posture

The console's security posture page (summarized on the overview) and `GET /api/system/posture` (InfoSec, Super
Admin) evaluate the installation against the recommendations of this documentation:

```json
{"score": 82, "generated_at": "…", "checks": [{"id": "sso", "category": "identity", "title": "…",
  "status": "pass|warn|fail|info", "detail": "…", "remediation": "…", "doc_link": "docs/identity.md"}]}
```

Score: every `pass` counts 2 points, `warn` 1 and `fail` 0 out of 2; `info` checks are not scored.

| Category | Checks |
|---|---|
| platform | HTTPS for console and API · demo mode off · `/metrics` protected · interception CA validity (warn < 90 days, fail < 30 days) · data-plane workers reporting |
| data | secrets encrypted at rest |
| identity | bootstrap password file removed · SSO enabled · password login limited to break-glass accounts · 2–5 Super Admins · 1–2 break-glass accounts · no accounts unused for 90 days · no service-account key expiring within 14 days · service accounts restricted to source networks |
| governance | four-eyes review · policy sets recertified on time · no catch-all (`*`) ALLOW rules · audit trail forwarded to a SIEM · audit hash chain intact (warn while legacy pre-2.1 events exist) · audit log writable (shown when it is not) |
| detection | threat intelligence in `block` mode · downloads scanned (ClamAV, ICAP or YARA) · DLP active · threat-intel sources up to date |

## Backup and restore

| Storage | Back up | Restore |
|---|---|---|
| file | `DATA_DIR` (`aegis_state.json`, `.bak`, `audit.jsonl*`, `secrets/` incl. `encryption.key`) and `CERTS_DIR` | stop, restore files (owner = service user, mode 0600), start |
| postgres | database (PITR or `pg_dump -Fc`), secrets (**including `AEGIS_ENCRYPTION_KEY`**), CA | restore the database, start the replicas with the same secrets |

Integration secrets in the configuration are encrypted with `AEGIS_ENCRYPTION_KEY`. A backup is only usable
together with the key that was current when it was taken — store the key in your secret vault, separately from
the data backups, and keep retired keys as long as backups encrypted with them are retained.

The state file is written atomically (temp file + fsync + rename) and the previous version is kept as `.bak`.
If the state file is corrupt the control-plane refuses to start rather than overwriting it.

**Restore verified (2.1):** file mode (archive of `DATA_DIR` + `CERTS_DIR`) and cluster mode (`pg_dump -Fc` →
`pg_restore` into a new PostgreSQL) were restored after deleting the originals: same admin credentials,
published policy sets, CA fingerprint, encrypted integration secrets usable (verified by a valid webhook HMAC)
and a valid complete audit chain. A restore without the encryption key, or with the wrong key, refuses to start.

## Sizing

Measured with the release images (mitmproxy 12.3, Python 3.14) on an 8-core x86 host, small responses, origin
on the local network, threat intelligence on, YARA/ICAP/ClamAV off:

| Traffic | Per worker (one process, ~1 CPU core) | Latency at 10 concurrent clients |
|---|---|---|
| HTTP, keep-alive | ~230 requests/s | ~50 ms |
| HTTPS intercepted, keep-alive | ~205 requests/s | ~50 ms |
| HTTPS, new TLS session per request (handshakes on both sides) | ~45 requests/s | ~450 ms at 20 clients |
| Denied (block page) | ~230 requests/s | ~50 ms |

- A worker is one mitmproxy process and uses about one CPU core. mitmproxy alone reaches ~250 requests/s on the
  same host; the AegisProxy addon adds 7 % (HTTP) to 17 % (HTTPS) on top. Plan **one worker per core** and scale
  horizontally (replicas, systemd instances, Windows services behind a load balancer).
- New TLS sessions dominate the cost: clients that keep connections alive (package managers, container runtimes)
  are much cheaper than clients opening a connection per request.
- Content inspection adds per-download cost: hash and file type checks are negligible; YARA, ClamAV and ICAP add
  the engine's scan time for every scanned body (up to the scan limits).
- Control-plane: telemetry ingestion costs about 3 % of a core per 100 requests/s in file mode (16 % at 556
  requests/s). In cluster mode add the PostgreSQL writes of the traffic log; size the database for
  `requests/s × AEGIS_FLOW_RETENTION`.
- Memory: ~100–160 MB per worker, ~50–150 MB per control-plane replica plus the in-memory windows.

## Upgrades

- Container/Helm: roll out new images; the control-plane migrates the schema on start (single writer via
  advisory lock in PostgreSQL). Update the control-plane replicas first, then the data-plane workers
  (the policy bundle format is extended additively).
- Always back up before upgrading. Downgrades across schema versions are not supported.

### Upgrading from 2.0

- The first 2.1 start converts the flat rule list into **policy sets** (schema version 3, see
  [policy-management.md](policy-management.md#migrating-from-20)); hit counters, requests and audit history are
  kept. File mode: the previous state stays in `aegis_state.json.bak` after the first save — copy the whole
  `DATA_DIR` before upgrading anyway.
- **Cluster mode: upgrade all control-plane replicas together** (scale to the new version, do not run 2.0 and
  2.1 replicas side by side). A 2.0 replica does not know policy sets and would drop them when it writes the
  shared configuration. Data-plane workers can be upgraded afterwards; 2.0 workers keep working with a 2.1
  control-plane (they ignore the new bundle fields, i.e. use their built-in block page and do not enforce
  quarantine — upgrade them promptly).
- API changes: `POST /api/rules`, `DELETE /api/rules/{id}` and `POST /api/audit/{id}/rollback` were removed.
  Automation that created rules must create or edit policy sets instead (see [api.md](api.md#policy-sets)).
- `*`-scoped rules no longer apply to unregistered sources (sources that are neither registered nor inside a
  group CIDR). Register servers or add their networks as group CIDRs before upgrading if you relied on that.
- Team Leads can no longer grant permanent access through requests; the governance setting
  `max_temporary_access_days` (default 30) caps their grants.
- Set `AEGIS_PROXY_ADDRESS` so the new onboarding snippets point at your data-plane address.
- **Encryption at rest**: secrets in the configuration are encrypted on the first save after the upgrade. File
  mode generates `DATA_DIR/secrets/encryption.key` automatically — add it to your backups. **Cluster mode requires
  `AEGIS_ENCRYPTION_KEY`** (identical on every replica, `openssl rand -hex 32`, Helm: `secrets.encryptionKey` or
  the `encryption-key` entry of `secrets.existingSecret`, systemd: `/etc/aegis/secrets/encryption.key`, Windows:
  `secrets\encryption.key`); replicas refuse to start without it. Provision the key before rolling out 2.1.
- Identity: existing local Super Admins are marked as break-glass accounts; review the flag
  ([identity.md](identity.md#break-glass-accounts)). SSO settings can now only be changed by Super Admins.
- Learning sessions: publishing rules of a session that is still recording is rejected with HTTP 409 — stop the
  session first (`POST /api/sessions/{id}/stop`). Stopping a session that already ended is refused as well.
- Linux package: the logrotate rule for `audit.jsonl` changed from `copytruncate` to rename-based rotation
  (re-run `install-linux.sh` or copy `deploy/systemd/aegis.logrotate`).

### Upgrading from 1.x

- State is migrated automatically: plaintext proxy tokens are hashed, the security policy and threat-feed
  catalog are added, `grp-db-vault` becomes a strict-isolation group.
- 1.x never persisted password hashes: a bootstrap admin password is generated
  (`DATA_DIR/secrets/initial-admin-password`) unless `AEGIS_BOOTSTRAP_ADMIN_PASSWORD` is set; reset the other
  users' passwords in the console.
- Data-plane workers need `AEGIS_DATAPLANE_KEY` (the former hard-coded default is rejected).
- The UI no longer accepts session tokens in URLs or `localStorage`; API clients use
  `Authorization: Bearer <token>` from `POST /api/auth/login`.
- To move to cluster mode, start the first PostgreSQL-backed replica with the old `DATA_DIR` mounted: the
  existing `aegis_state.json` is imported.

## Rotating secrets and the CA

| Item | Procedure |
|---|---|
| Server proxy token | console → Server Fleet → *Rotate token* (old token invalid immediately) |
| `AEGIS_JWT_SECRET` | change on all replicas and restart → all users sign in again |
| `AEGIS_DATAPLANE_KEY` | change on control-plane and all workers in one maintenance window (workers fail closed only if they never synced; running workers keep the last policy until they can sync again) |
| Root CA | `gen-ca` into a new directory, distribute the new certificate to all servers **first**, then switch the data-plane secret and the control-plane certificate — or let your corporate PKI issue it ([below](#corporate-pki-subordinate-ca)) |
| `AEGIS_ENCRYPTION_KEY` | see [encryption key](#encryption-key) |
| User passwords | users: *Change my password*; admins: *Reset password* (revokes sessions) |
| Service-account keys | *Rotate* (old key invalid immediately) before `expires_at`; the posture page lists keys expiring within 14 days |
| SSO / Defender client secrets, export credentials | create the new secret in the IdP / Entra ID / target system, paste it into the console (write-only), test, then revoke the old one |

### Encryption key

Secrets in the configuration are stored as `enc:v1:<key id>:<ciphertext>`. The key id (8 hex characters) is
logged at start-up (`secrets at rest are encrypted … key_id=…`); `grep -o 'enc:v1:[0-9a-f]*' aegis_state.json |
sort | uniq -c` shows which keys are in use. With `AEGIS_ENCRYPTION_KEY_PREVIOUS` the control-plane decrypts
values of the previous key and writes everything with the current key.

**Single node** (file mode, or one replica):

1. Back up `DATA_DIR` and the current key.
2. Generate a new key (`openssl rand -hex 32`). Configure it as `AEGIS_ENCRYPTION_KEY` (or `_FILE`) and the old one
   as `AEGIS_ENCRYPTION_KEY_PREVIOUS` (or `_FILE`). With the auto-generated key: move
   `secrets/encryption.key` to `secrets/encryption.key.previous`, write the new key to `secrets/encryption.key`
   and set `AEGIS_ENCRYPTION_KEY_PREVIOUS_FILE=<DATA_DIR>/secrets/encryption.key.previous`.
3. Restart. The log shows the new `key_id` and `previous_key=true`; at start-up the control-plane re-encrypts
   every secret that is still sealed with the old key (`re-encrypting secrets with the current key secrets=<n>`).
4. Verify that the old key id no longer occurs in `aegis_state.json`.
5. Remove `AEGIS_ENCRYPTION_KEY_PREVIOUS` and restart. Archive the old key as long as backups that need it exist.

**Cluster** (no downtime; every replica must be able to read what any other replica writes):

1. Phase 1 — on all replicas: `AEGIS_ENCRYPTION_KEY` = old key (unchanged), `AEGIS_ENCRYPTION_KEY_PREVIOUS` =
   **new** key. Roll out.
2. Phase 2 — on all replicas: `AEGIS_ENCRYPTION_KEY` = new key, `AEGIS_ENCRYPTION_KEY_PREVIOUS` = old key. Roll out.
   Every replica re-encrypts old-key secrets when it starts, so after the last replica has restarted the shared
   configuration contains only the new key. Check:
   `SELECT count(*) FROM aegis_config WHERE doc::text LIKE '%enc:v1:<old key id>:%';` → `0` (if not, restart one
   replica again).
3. Phase 3 — remove `AEGIS_ENCRYPTION_KEY_PREVIOUS` everywhere and roll out.

Where to set the variables:

| Platform | Current key | Previous key |
|---|---|---|
| Helm | `secrets.encryptionKey` or the `encryption-key` entry of `secrets.existingSecret` | `secrets.encryptionKeyPrevious` or the `encryption-key-previous` entry of `secrets.existingSecret` |
| Docker Compose (single node and HA) | `AEGIS_ENCRYPTION_KEY` in `.env` | `AEGIS_ENCRYPTION_KEY_PREVIOUS` in `.env` (passed through by both compose files) |
| systemd | `/etc/aegis/secrets/encryption.key` | `/etc/aegis/secrets/encryption.key.previous` (0600 root) + `systemctl edit aegis-control-plane`: `LoadCredential=encryption-previous:/etc/aegis/secrets/encryption.key.previous` and `Environment=AEGIS_ENCRYPTION_KEY_PREVIOUS_FILE=%d/encryption-previous` |
| Windows | `<DataRoot>\secrets\encryption.key` | write the previous key (single node: the old key) to `<DataRoot>\secrets\encryption.key.previous` (inherits the restricted ACL of the directory) and re-run the installer with your usual parameters plus `-ExtraEnvironment @{ AEGIS_ENCRYPTION_KEY_PREVIOUS_FILE = 'C:\ProgramData\AegisProxy\secrets\encryption.key.previous' }`; remove it later with an empty value |

**Wrong or missing key**: the control-plane refuses to start and names the key id it needs (`secret was
encrypted with key <id>, which is not configured`) — nothing is overwritten. Restore the key from your vault.
If it is irrecoverably lost, stop all replicas, blank the encrypted values and re-enter the integration secrets
(SSO and Defender client secrets, feed auth headers, export credentials, webhook URLs) after the start:

```bash
# file mode
jq 'walk(if type == "string" and startswith("enc:v1:") then "" else . end)' aegis_state.json > state.new \
  && mv state.new aegis_state.json            # keep a copy of the original first
# cluster mode
psql "$DSN" -At -c 'SELECT doc FROM aegis_config WHERE id = 1' \
  | jq -c 'walk(if type == "string" and startswith("enc:v1:") then "" else . end)' > doc.json
psql "$DSN" -v doc="$(cat doc.json)" <<'SQL'
UPDATE aegis_config SET doc = :'doc'::jsonb WHERE id = 1;
SQL
```

### Corporate PKI (subordinate CA)

Instead of a self-signed root, let your corporate CA (Active Directory Certificate Services, HashiCorp Vault,
EJBCA, …) issue the interception CA. Servers that already trust the corporate root (GPO, MDM, golden images) then
trust AegisProxy without any CA roll-out.

1. Create the key and the request in a staging directory:
   `aegis-control-plane gen-csr ./ca-new "CN=AegisProxy Issuing CA,O=Example Corp,OU=Platform Security,C=DE"`
   (attributes `CN` (required), `O`, `OU`, `C`, `L`, `ST`). It writes `pending-ca.key` (RSA-3072, 0600) and
   `pending.csr`, which requests a CA certificate (basic constraints `CA:true, pathlen:0`, key usage
   `keyCertSign, cRLSign`).
2. Have the CSR signed with a subordinate-CA template, for example:
   - AD CS: `certreq -submit -attrib "CertificateTemplate:SubCA" pending.csr issued.cer` (template
     *Subordinate Certification Authority*; restrict the path length to 0 where your policy allows it).
   - Vault: `vault write -field=certificate pki/root/sign-intermediate csr=@pending.csr use_csr_values=true
     max_path_length=0 ttl=26280h > issued.pem`.
   - Lab/OpenSSL 3: `openssl x509 -req -in pending.csr -CA root.pem -CAkey root.key -days 1095 -copy_extensions copy -out issued.pem`.
3. Install it: `aegis-control-plane import-ca ./ca-new issued.pem [chain.pem]`. The command accepts PEM or DER
   and checks that the certificate belongs to the pending key, is a CA certificate with `keyCertSign`, is
   currently valid and — when intermediates/root are given — that the chain verifies. It warns when the path
   length is not 0 or the certificate expires within 30 days. It writes `mitmproxy-ca.pem` (key + issuing CA +
   intermediates; the root is never sent), `mitmproxy-ca-cert.pem`, `aegis-enterprise-ca.crt`/`.der`, keeps
   previous files as `*.bak` and deletes the pending key and CSR.
4. Deploy the directory like a `gen-ca` CA: replace `CERTS_DIR` on single nodes, or the CA secret in Kubernetes
   (`kubectl create secret generic aegis-ca --from-file=ca-new/mitmproxy-ca.pem
   --from-file=ca-new/mitmproxy-ca-cert.pem --dry-run=client -o yaml | kubectl apply -f -`), then restart the
   control-plane and the data-plane workers. Workers present the issuing CA and intermediates in every TLS chain.
5. Servers that trusted the previous AegisProxy root keep working once they trust the corporate root; remove the
   old root from them afterwards. The posture page warns 90 days before the CA expires.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Proxy answers `503 policy not available yet` | worker never synced: check `CONTROL_PLANE_URL`, `AEGIS_DATAPLANE_KEY` (control-plane logs `rejected data-plane request with invalid key`) |
| TLS errors on servers | CA not installed in the trust store used by the client runtime (Java keystore, Python certifi, Node `NODE_EXTRA_CA_CERTS`) |
| Everything from a server is default-denied | server not identified: check the source IP seen by the worker (block page shows it), `externalTrafficPolicy`, NAT, or use a proxy token |
| `POLICY_BLOCKED host_mismatch` / `sni_mismatch` | client sends a `Host`/SNI different from the CONNECT target (domain fronting) — fix the client |
| `POLICY_BLOCKED internal_destination` / `ip_literal` | add an explicit rule for that exact host/IP, or reconsider whether the traffic should use the egress proxy at all |
| `AV_ERROR` events | clamd unreachable, overloaded or scan timeout; check `aegis_dp_clamd_available`, clamd memory, `AEGIS_CLAMD_TIMEOUT_SECONDS` |
| Antivirus false positive | add a SHA-256 exception for the file (Threat Protection → Exceptions) |
| Feed shows an error | moved/retired source (HTML page or HTTP 4xx); disable it or add the replacement URL as a custom feed |
| Console shows `cluster storage unavailable` | database unreachable; reads continue, writes are rejected |
