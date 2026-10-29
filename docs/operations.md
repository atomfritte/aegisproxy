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

## Proxy credentials on the wire

Proxy tokens travel in the `Proxy-Authorization` header (Basic, `<hostname>:<token>`). On a plain
`http://proxy:8080` listener that header is **clear text on the client → proxy hop**: anyone who can capture
traffic on that segment can copy a server's token and use it from any address. HTTPS destinations are still
tunnelled with TLS end to end, but the `CONNECT` request and its credentials are not. Protect the hop with one of:

| Option | Protects | Notes |
|---|---|---|
| IPsec or WireGuard between servers and the data-plane | everything on the hop | Recommended for servers outside a trusted segment. The proxy sees the tunnel address, so register servers by token or by their tunnel address. |
| TLS to the proxy ("secure web proxy", `https://` proxy URL) | the proxy request, `CONNECT` and credentials | Supported by the data-plane image (mitmproxy 12.3): the regular listener detects a TLS handshake and serves the proxy over TLS with a certificate issued by the AegisProxy CA for the name the client connects to. Clients must trust the AegisProxy CA for the proxy itself, e.g. `curl --proxy https://proxy.corp.example:8080 --proxy-cacert aegis-ca.pem`, `HTTPS_PROXY=https://…` for tools that support TLS proxies. The same port keeps accepting plain-text clients, so this protects only clients configured for it. |
| Dedicated network segment / VLAN for proxy traffic | traffic outside the segment | Limits who can capture the hop; does not protect against hosts on the same segment. |

A token alone does not identify a server forever: rotate it (console → server → *Rotate token*) if it may have
been exposed. Groups with **Require proxy token** never fall back to address-based identification, which matters
behind NAT or shared addresses ([policy-management.md](policy-management.md#proxy-tokens-and-shared-addresses)).

Behaviour of the data-plane for credentials:

- An invalid token, a malformed `Proxy-Authorization` header or a hostname used from an address it is not bound
  to is refused with **HTTP 407** and the verdict `AUTH_FAILED` (security event "Proxy authentication"). The
  request is never evaluated as the anonymous source address.
- A member of a *Require proxy token* group that sends no token, or only its hostname, gets 407 as well.

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
| `GET :9091/healthz`, `/readyz` | data-plane | liveness / policy loaded and not stale (`/readyz` answers 503 with the reason) |
| `GET :9091/metrics` | data-plane | flows by verdict, AV scans and duration, clamd availability, YARA and ICAP scans and duration, policy revision, sync age, max age and staleness, telemetry queue, spool bytes, lost records by reason, tracked and terminated connections |
| `GET /api/system/posture` | control-plane | security posture score and checks ([below](#security-posture)) |

Suggested alerts (shipped as a `PrometheusRule` in the Helm chart: `metrics.prometheusRule.enabled=true`):

- `increase(aegis_dp_hook_errors_total[10m]) > 0` — a worker blocked traffic after an internal error (fail-closed)
- `aegis_dataplanes_healthy < expected` (control-plane view of worker heartbeats)
- `aegis_dp_policy_sync_age_seconds > 120`; `aegis_dp_policy_stale == 1` (the worker fails closed)
- `increase(aegis_dp_flows_dropped_total[1h]) > 0` or `increase(aegis_flows_dropped_total[1h]) > 0` —
  traffic records were lost ([telemetry delivery](#traffic-telemetry-delivery)); `aegis_dp_telemetry_queue`
  growing for 15 minutes (the control-plane does not accept records)
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
- `aegis_audit_trail_intact == 0` — an audit trail integrity violation was detected; `aegis_audit_legacy_pending
  == 1` — unkeyed pre-2.1 events await acceptance; `aegis_audit_full_verify_ok == 0` or `time() -
  aegis_audit_full_verify_timestamp_seconds > 2 × AEGIS_AUDIT_VERIFY_INTERVAL` — the complete verification of
  the trail failed or stopped running ([audit trail](#audit-trail); not yet part of the shipped `PrometheusRule`)

Logs are structured JSON (`AEGIS_LOG_FORMAT=json`). Audit events are written as `msg="audit"` log lines and to
`audit.jsonl`. To forward audit, traffic ("browsing") and security records to a SIEM or observability platform
(syslog/rsyslog, OpenTelemetry, Splunk, Elastic/OpenSearch, Sentinel, Datadog, Loki, webhooks, files) configure
**Settings → Integrations → Log export** — see [log-export.md](log-export.md).

### Traffic telemetry delivery

Traffic records ("flows") travel from a worker to the control-plane **at least once**, and the control-plane
stores each flow ID once:

1. The worker queues each record in memory (20,000 records). With `AEGIS_FLOW_SPOOL_DIR` it moves them to
   fsync'd spool segments every flush interval and when it shuts down, so they survive a restart.
2. It uploads batches of up to 500 records, oldest first, to `POST /api/dataplane/flows/batch`, and removes a batch
   only after a `201`.
3. The control-plane answers `201` only once the batch is stored durably. With file storage the batch is appended
   to `DATA_DIR/flow-journal/` and fsync'd; the journal is replayed after a crash until the next state save includes
   it. In a cluster the batch is committed to PostgreSQL. Otherwise it answers `503` with `Retry-After`:
   the worker keeps the batch and retries (`429`/`503` honour `Retry-After`; network errors and other `5xx` back
   off exponentially up to 30 s).
4. A resend after a lost acknowledgement is recognized by flow ID (`duplicate_count`,
   `aegis_flow_duplicates_total`). In PostgreSQL a unique index on `aegis_flows.flow_id` covers resends to another
   replica.

Records are lost only in these cases, and each one is counted:

| Where | Metric reason | Cause |
|---|---|---|
| worker | `overflow` | memory queue full: no spool and the control-plane unreachable or refusing for too long |
| worker | `spool_full` | `AEGIS_FLOW_SPOOL_MAX` reached (oldest records discarded) |
| worker | `rejected` | the control-plane refused a batch as malformed (`400`/`413`/`422`) |
| worker | `spool_corrupt` | unreadable spool lines (e.g. disk corruption) |
| control-plane | `queue_overflow` | cluster: PostgreSQL unreachable while more than the in-memory telemetry queue accumulated |
| control-plane | `batch_too_large` | a batch with more than 1,000 records |

Worker counters are `aegis_dp_flows_dropped_total{reason}` and are also reported in the heartbeat. Per worker they
appear under **Settings → Data planes** and as `aegis_dataplane_flows_dropped_total{dataplane,reason}` /
`aegis_dataplane_flow_backlog{dataplane}` on the control-plane. The control-plane's own counter is
`aegis_flows_dropped_total{reason}`; refused batches are counted in `aegis_flow_batches_refused_total`. The posture
check *Traffic records delivered completely* warns while any of these counters is above zero.

**Control-plane outage.** Workers keep enforcing the last policy and queue records. Without a spool, at most
20,000 records per worker are kept, which is minutes on a busy worker. Enable the spool for an outage budget
(about 1 KiB per record: 256 MiB holds roughly 250,000 records). After `AEGIS_POLICY_MAX_AGE`, workers fail closed
([configuration](configuration.md#data-plane-mitmproxy-worker)).

### Connection termination on revocation

Workers track long-lived connections (requests in progress, SSE and other streamed responses, WebSockets, CONNECT
tunnels, TLS passthrough and raw relays). They evaluate them again after every policy or threat-intel update, when a
rule, TLS exception or learning session expires, and when the policy becomes stale. A connection that is no longer
allowed is closed. Reasons: server quarantined, threat intelligence, TLS exception revoked, rule revoked or blocked,
learning session ended, redirect grant expired, group membership changed, raw TCP disabled, or policy stale. The
closure is recorded as a traffic record with flag `CONNECTION_TERMINATED:<reason>` (block reason
`connection_terminated`), raises a security event, and is counted in
`aegis_dp_connections_terminated_total{kind,reason}`. The client's whole connection is closed, so other HTTP/2
streams multiplexed on it are reset as well. A WebSocket message that arrives after the revocation is dropped and
not forwarded.

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
verification (a "hash-version downgrade": the unkeyed hash can be recomputed by anyone). A new installation seals
its anchor at initialization; an existing installation without one is handled as a [legacy
trail](#legacy-trail-after-an-upgrade-from-20) that a Super Admin must accept.

**Head checkpoint.** Every change also stores a sealed *checkpoint* in the configuration: `event_hash` and revision
of the newest event, the number of events since the anchor and the configuration revision, with a MAC keyed with
the audit chain key. It is written in the same atomic step as the state (file mode: the state file; cluster: the
configuration row, in the transaction that inserts the audit rows). The verification compares the complete trail
with it, so deleting the newest events — lines of `audit.jsonl`, the newest generation, `aegis_audit` rows — is
detected although the remaining chain still links correctly, and so is a checkpoint copied from an older state.

**Integrity violations.** Two kinds of checks run:

* *Seal checks* — at start-up, and on every cluster reload, before anything is appended: anchor and checkpoint
  against the in-memory window (the newest 2,000 events). They detect a missing anchor or checkpoint in a trail
  written by 2.1 or later (keyed events, an audit chain key or a checkpoint exist), an invalid seal, newest events
  cut off the end, a configuration replaced by an older copy, and an audit log that diverged from the state.
* *Complete verification* — reads the whole trail (`audit.jsonl` and every generation, or all `aegis_audit` rows)
  in the background: at start-up (right after the control-plane is up, so a large trail does not delay it), every
  `AEGIS_AUDIT_VERIFY_INTERVAL` (default 6 h), after the audit log was rotated or truncated by another program (at
  most every 15 minutes), and with every `GET /api/audit/verify`. It detects events changed, inserted, deleted or
  reordered anywhere in the trail, a hash-version downgrade, a start that does not link to the anchor and an event
  count that differs from the checkpoint. Changes made between two runs are found by the next one.

A failed seal check, and a failed complete verification (confirmed by a second run a moment later, so a trail
changing under it is not mistaken for tampering), is an *integrity violation*: it is logged, recorded as an
`AUDIT_INTEGRITY_VIOLATION` audit event and raised as a high-severity security event (exported with the security
stream and sent to Teams/Slack/webhooks when *notify on security events* is on — also when it is found at start-up,
before the export destinations are running: such alerts are held back until they are); `aegis_audit_trail_intact`
drops to 0, the posture check *Audit hash chain intact* fails and `GET /api/audit/verify` reports it. The
control-plane keeps running. The violation is sealed into the checkpoint and **stays** — across restarts (each start
raises the alert again), on every replica and also when the evidence is put back afterwards — until the data is
restored from a backup taken before it: compare the trail with your SIEM copy, preserve the affected `DATA_DIR` or
database for the investigation, then restore.

Not recorded as violations, but alerted as `AUDIT_VERIFICATION_FAILED` (high) with the posture check failing and
`aegis_audit_full_verify_ok` 0 until the next successful run: a trail that does not start at its sealed origin —
also the state between removing old generations for retention and applying the retention point; otherwise the
oldest events were deleted — and a complete verification that could not finish twice in a row (unreadable file,
database error; retried every 10 minutes). Missing newest events while the audit log is not writable are reported
by the posture check *Audit log writable* instead. The same alert as for a violation (without a violation) is raised
for every retention point (`AUDIT_RETENTION_APPLIED`), every anchor sealed for an existing installation
(`AUDIT_LEGACY_PENDING`, repeated at every start while pending) and every acceptance of legacy events
(`AUDIT_LEGACY_ACCEPTED`).

**What only an independent copy reveals.** A complete rollback — state (or configuration row) and trail replaced
together by an older, consistent copy such as a backup — is internally intact and cannot be detected by the
control-plane. Neither can anything done by somebody who also holds the encryption key (and with it the audit chain
key): keep `AEGIS_ENCRYPTION_KEY` outside `DATA_DIR` ([encryption key](#encryption-key)). Forward the audit stream
to a SIEM in real time ([log-export.md](log-export.md)); without it the posture check *Audit trail forwarded to a
SIEM* fails in production. Besides the audit events the stream carries `AUDIT_CHECKPOINT` records — at start-up,
every 100 events and at least every 15 minutes while the trail grows — whose `after_state` holds the checkpoint
(`head`, `head_revision`, `events`, `state_revision`, `violation`). Alert in the SIEM when checkpoint records stop
arriving, when `events` decreases, or when a later verification reports fewer `events_checked` than the last
checkpoint received (allow for retention points, which are audited). Checkpoint records are not audit events: they
are neither in `audit.jsonl`/`aegis_audit` nor in the console, have no `event_hash` and must be skipped when you
check the links of the exported stream.

| Endpoint | Content |
|---|---|
| `GET /api/audit/verify` | `{valid, events_checked, first_id, last_id, legacy_events, starts_at_genesis, head_matches, checkpoint_matches, checkpoint_events, legacy_pending[, legacy_head][, error]}` — checks every hash and link of the **complete** trail (same sources as the export), that it starts at its sealed origin, that unkeyed events occur only in the sealed pre-2.1 prefix, that it reaches the newest event known to the control-plane (missing newest events or generations fail) and that it matches the sealed checkpoint (newest hash, event count, configuration revision); fails with `legacy_pending` while a legacy prefix awaits acceptance; Super Admin, InfoSec, Auditor |
| `GET /api/audit/export` | the **complete** trail as JSON Lines, oldest first: cluster mode streams the `aegis_audit` table; file mode streams `audit.jsonl` and all its rotated generations (`audit.jsonl-YYYYMMDD[.gz]`, `audit.jsonl-YYYYMMDDhhmmss[.gz]`, `audit.jsonl.N[.gz]`) in the same directory — also while `audit.jsonl` itself is missing after a logrotate rename — as a consistent snapshot of the moment the export started |
| `POST /api/audit/retention` | after you removed old generations (or `aegis_audit` rows) for retention: verifies the remaining trail and re-seals its start (Super Admin; recorded as `AUDIT_RETENTION_APPLIED`, raises a security event). Until then the verification reports the missing start. Refused while an integrity violation is recorded |
| `POST /api/audit/anchor/accept-legacy` | `{legacy_events, legacy_head}`: accepts the pending legacy prefix ([below](#legacy-trail-after-an-upgrade-from-20); Super Admin; recorded as `AUDIT_LEGACY_ACCEPTED`, raises a security event) |

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
state, key and trail together (see [above](#audit-trail)).

**Durability (file mode).** Every event is written and flushed (`fsync`) to `audit.jsonl` before the change is
acknowledged; the state file follows within a second. After a crash in between, the next start adopts the events
that reached the log but not the state into the trail and records `AUDIT_TRAIL_RECOVERED` (their configuration
changes were not saved and are not in effect); events that reached the state but not the log are appended to the
log. A failed or partial write (disk full) is cut off again — the log never keeps a torn line — and while the log
cannot be written the control-plane refuses configuration changes with HTTP 503 (`audit log unavailable`); the
posture check *Audit log writable* fails, `aegis_audit_log_writable` is 0 and `/readyz` reports
`"audit_log": "unavailable"` (reads and policy distribution continue). Changes resume, and the log is completed,
as soon as it can be written again. A break-glass sign-in is refused (HTTP 503) while its audit event cannot be
written. The audit log and its generations must be regular files: a symbolic link, junction or FIFO at their names
is refused (point `AEGIS_AUDIT_LOG` at the real location instead of linking it).

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

### Legacy trail after an upgrade from 2.0

The first 2.1 start on an existing installation without an anchor seals the unkeyed prefix as **pending**
(`AUDIT_ANCHOR_SEALED`, security event `AUDIT_LEGACY_PENDING`). Somebody who removed the audit chain key, anchor
and checkpoint and re-hashed a rewritten trail with the unkeyed algorithm produces exactly the same picture, so
AegisProxy never trusts such a prefix on its own: until a Super Admin accepts it, the verification fails with
`legacy_pending`, the posture check *Audit hash chain intact* fails and `aegis_audit_legacy_pending` is 1. Everything
else works normally and new events are keyed.

1. **Before the upgrade**, archive the complete trail outside the server: the export, a copy of `audit.jsonl*`
   (cluster: `pg_dump -t aegis_audit`) or the SIEM copy.
2. After the upgrade, **Audit trail → Verify hash chain** (or `GET /api/audit/verify`) shows the number of legacy
   events (`legacy_events`) and the `event_hash` of the last one (`legacy_head`).
3. Compare both with the archive: the number of events and the `event_hash` of the newest event before the upgrade
   (export: `wc -l < audit.jsonl` and `tail -n1 audit.jsonl | jq -r .event_hash`).
4. If they match, a Super Admin chooses **Review and accept…** and enters the count and the hash from the archive
   (`POST /api/audit/anchor/accept-legacy` with `{"legacy_events": 1234, "legacy_head": "…"}`); both must match
   exactly and the rest of the trail must verify. The acceptance applies to every replica, is audited and raises a
   high-severity security event; afterwards the posture check warns as long as legacy events exist.
5. If they do not match, there is no archive to compare with, or the installation already ran 2.1 before (then
   the audit chain key and anchor were removed): **do not accept** — restore from a backup and investigate.

Installations that ran a pre-release 2.1 build without checkpoints report an integrity violation after
the update: archive the trail and [start a new one](#starting-a-new-trail). The same applies to the [lost
encryption key](#encryption-key): the keyed trail can no longer be verified.

### Starting a new trail

Only when the existing trail cannot be verified any more (encryption key lost, pre-release data) and is archived:
stop all replicas; file mode: move `audit.jsonl*` away and remove `audit_chain_key`, `audit_anchor`,
`audit_checkpoint` and `audit_events` from `aegis_state.json` (`jq 'del(.audit_chain_key, .audit_anchor,
.audit_checkpoint, .audit_events)'`); cluster: archive and empty `aegis_audit` and remove the same keys from
`aegis_config.doc`. The next start seals an empty pending prefix: accept it with `legacy_events` 0 and
`legacy_head` of 64 zeros. Like every acceptance this is audited and alerted — which is also what an insider who
discards the trail would have to get past.

### What somebody with access to the storage can and cannot do

Against a person who can write `DATA_DIR` or the database but does not hold `AEGIS_ENCRYPTION_KEY` (key kept
outside `DATA_DIR`):

| They can | They cannot (detected locally) |
|---|---|
| Delete or corrupt the data — detected as a violation (or, without a state file, a new installation without its configuration); recoverable from backups | Change, insert, reorder or delete individual events, also not at the end, without an integrity violation (keyed chain, anchor, checkpoint, complete verification) |
| Replace state and trail together with an older complete copy (rollback) — **only the SIEM copy reveals it** | Remove the anchor, checkpoint or audit chain key without an integrity violation or a pending legacy prefix plus alert |
| Discard key, seals and trail and present a re-hashed unkeyed trail — it stays untrusted (`legacy_pending`, posture fail, alert) unless a Super Admin accepts it | Forge a seal, hide a recorded violation, or make an unkeyed trail verify without a Super Admin's audited acceptance |
| Delete the oldest events — alerted (`AUDIT_VERIFICATION_FAILED`, posture fail) like a retention in progress until a Super Admin applies a retention point | Add or change records in the export spool (MAC per record: dead-lettered with an alert) |
| Change the trail and put it back before the next complete verification (`AEGIS_AUDIT_VERIFY_INTERVAL`, or the next rotation) | |

Whoever also holds the encryption key (key in `DATA_DIR`, root on the host, database plus secret store) can
recompute chain and seals: only the real-time SIEM copy protects against that. Super Admins can accept legacy
prefixes and apply retention points through the API — both audited and alerted — but cannot delete or change
events. See also the [threat model](threat-model.md#audit-trail-against-insiders).

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
| data | secrets encrypted at rest (warn when the key is stored in `DATA_DIR`) |
| identity | bootstrap password file removed · SSO enabled · password login limited to break-glass accounts · 2–5 Super Admins · 1–2 break-glass accounts · no accounts unused for 90 days · no service-account key expiring within 14 days · service accounts restricted to source networks |
| governance | four-eyes review · policy sets recertified on time · no catch-all (`*`) ALLOW rules · audit trail forwarded to a SIEM (fail in production, warn in demo mode, unless at least one destination with the audit stream delivers: state ok/idle or a delivery within 15 minutes) · audit hash chain intact (fail after an integrity violation, a failed complete verification and while legacy events await acceptance; warn while the complete verification has not finished or is overdue, and while accepted pre-2.1 events exist) · audit log writable (shown when it is not) |
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
- **Audit trail**: archive the complete trail before upgrading; after the first start a Super Admin compares and
  accepts the pre-2.1 events ([legacy trail](#legacy-trail-after-an-upgrade-from-20)) — until then the posture
  check *Audit hash chain intact* fails. Configure a log export destination with the audit stream: production
  installations without one (or whose destinations do not deliver) fail the posture check *Audit trail
  forwarded to a SIEM*. The complete trail is verified in the background at every start and every
  `AEGIS_AUDIT_VERIFY_INTERVAL` (default 6 h): on large trails this reads the whole `audit.jsonl` history once per
  run.
- **Log export spool**: spool records now carry a MAC. Records spooled by 2.0 are not resent automatically; they
  are moved to the destination's `dead-letter.jsonl` with an `EXPORT_DELIVERY` alert — let the spools drain before
  the upgrade, or review and replay the dead-letter file afterwards ([log-export.md](log-export.md#delivery-guarantees)).
- Identity: existing local Super Admins are marked as break-glass accounts; review the flag
  ([identity.md](identity.md#break-glass-accounts)). SSO settings can now only be changed by Super Admins.
- Learning sessions: publishing rules of a session that is still recording is rejected with HTTP 409 — stop the
  session first (`POST /api/sessions/{id}/stop`). Stopping a session that already ended is refused as well.
- Linux package: the logrotate rule for `audit.jsonl` changed from `copytruncate` to rename-based rotation
  (re-run `install-linux.sh` or copy `deploy/systemd/aegis.logrotate`).
- **Path patterns** (schema version 4): `*` now matches one path segment and `**` any depth. The first start
  rewrites stored patterns that ended in `*` to `**` so they keep their meaning, and writes the audit event
  `POLICY_PATH_PATTERNS_MIGRATED` (patterns with a `*` in the middle are listed for review). Imported bundles
  without `path_syntax: 2` are rewritten the same way. See
  [policy-management.md](policy-management.md#path-patterns).
- **Proxy credentials**: wrong or malformed proxy credentials now get HTTP 407 (`AUTH_FAILED`) instead of being
  treated as the anonymous source address — fix stale tokens in client configurations before upgrading
  (the traffic log shows them as `AUTH_FAILED` afterwards). New group setting `require_proxy_token`.
- **Shared addresses**: redirect grants and learning sessions are bound to the server identity, not to its IP
  address; servers behind the same NAT address no longer share them. Strict-isolation groups get neither.
- Upgrade the control-plane and the data-plane workers **together** for these changes: an older worker does not
  know `AUTH_FAILED`, `require_proxy_token` or the new path semantics.

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

Keep the key outside `DATA_DIR` (Kubernetes or Docker secret, systemd credential, vault agent): it also protects
the audit chain key, and a key next to the data protects neither against anybody who can read the data directory.
A key read from `DATA_DIR` — the auto-generated `secrets/encryption.key` or an `AEGIS_ENCRYPTION_KEY_FILE` inside it
— logs a warning at start-up and turns the posture check *Secrets encrypted at rest* into a warning. To move it,
copy the key to the secret store, point `AEGIS_ENCRYPTION_KEY_FILE` (or `AEGIS_ENCRYPTION_KEY`) at it, restart and
delete it from `DATA_DIR`.

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
(SSO and Defender client secrets, feed auth headers, export credentials, webhook URLs) after the start. Blanking
also removes the audit chain key: the existing trail can no longer be verified and is reported as an integrity
violation — archive it and [start a new trail](#starting-a-new-trail).

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
