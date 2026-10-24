# Log export (SIEM and observability)

AegisProxy forwards three record streams to external systems:

| Stream | Content | Typical consumer |
|---|---|---|
| `audit` | every administrative change and decision (hash-chained audit events: logins, policy publishes, reviews, quarantine, settings) | SIEM, compliance archive |
| `traffic` | every proxied request — the "browsing log" of the server fleet: server, destination, URL, method, status, bytes, verdict, matched rule, threat/AV/DLP details | SIEM, log analytics, proxy reporting |
| `security` | threat-protection events (threat intel, malware, DLP, file type, protocol guard, bursts, quarantine) with severity | SOC alerting |

Destinations are configured in the console under **Settings → Integrations → Log export** (or via the
[API](api.md#log-export)). Any number of destinations can run in parallel, each with its own streams, filters
and format.

## Destinations

| Type | Systems | Transport | Record formats |
|---|---|---|---|
| `syslog` | rsyslog, syslog-ng, IBM QRadar, ArcSight, Graylog, LogRhythm, any syslog receiver | RFC 5424 or RFC 3164 over UDP, TCP or TLS (mutual TLS optional); TCP framing octet-counting (RFC 6587) or newline | `json`, `ecs`, `cef`, `leef` |
| `otlp` | OpenTelemetry Collector, Grafana Cloud, Elastic, Dynatrace, New Relic, Honeycomb, Splunk Observability … | OTLP/HTTP logs, JSON encoding, gzip | OTel log records with ECS/semantic-convention attributes |
| `splunk_hec` | Splunk Enterprise / Splunk Cloud | HTTP Event Collector (`/services/collector/event`), gzip | `json`, `ecs`, `cef`, `leef` as event payload |
| `elasticsearch` | Elasticsearch, OpenSearch, Elastic Cloud | Bulk API, gzip, idempotent document IDs | ECS documents |
| `sentinel` | Microsoft Sentinel / Azure Monitor Logs | Logs Ingestion API (data collection rule), Entra ID client credentials | flat table columns |
| `datadog` | Datadog Logs (all sites) | HTTP intake v2, gzip | Datadog log entries with nested attributes |
| `loki` | Grafana Loki / Grafana Cloud Logs | push API with low-cardinality labels | `json`, `ecs`, `cef`, `leef` as log line |
| `webhook` | SOAR platforms, Kafka REST proxies, custom pipelines, serverless functions | HTTPS POST of JSON batches, HMAC-SHA256 signature | `json`, `ecs` |
| `file` | Filebeat, Fluent Bit, Vector, Splunk Universal Forwarder, NXLog | rotating file (100 MB × 5) in `AEGIS_EXPORT_DIR` | `json`, `ecs`, `cef`, `leef` |

Anything else (Kafka, Amazon S3, Google SecOps, Sumo Logic, Azure Event Hubs …) is reachable through an
**OpenTelemetry Collector** with the respective exporter — see the example below.

## Record formats

| Format | Description |
|---|---|
| `json` | Native document: `{timestamp, stream, severity, product, version, node, message, data}` where `data` is the unmodified record (`AuditEvent`, `TrafficFlow`, `SecurityEvent` as in the [API](api.md)). |
| `ecs` | Flat [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/) fields — `@timestamp`, `event.*`, `source.ip`, `destination.domain`, `url.full`, `http.request.method`, `http.response.status_code`, `user_agent.original`, `rule.name`, `user.name`, `threat.indicator.*`, `file.hash.sha256` — plus product fields under `aegisproxy.*`. The same field names are used as OTLP attributes (they match the OpenTelemetry semantic conventions where both define a field). |
| `cef` | ArcSight Common Event Format: `CEF:0|AegisProxy|Egress Gateway|<version>|<verdict/action/type>|<name>|<severity 0–10>|…` with `src`, `shost`, `dhost`, `dpt`, `request`, `requestMethod`, `act`, `reason`, `suser`, `msg`, `cs1…cs4` (rule, groups, threat category/source, role, entity, hash), `cn1` (HTTP status), `in`/`out`, `fileHash`, `externalId`. |
| `leef` | IBM QRadar LEEF 2.0, tab-delimited, with `devTime`/`devTimeFormat`, `sev`, `src`, `srcHostName`, `dstHostName`, `dstPort`, `url`, `method`, `usrName`, `action`, `cat`, `msg`. |

Severity mapping: traffic `info` (allowed), `low` (blocked by policy), `medium` (blocked by threat protection);
security events keep their severity; audit events are `info`. Syslog severities: info → 6, low → 5, medium → 4,
high → 3, critical → 2; OTLP severity numbers 9 / 10 / 13 / 17 / 21.

## Filters and privacy

| Option | Effect |
|---|---|
| Streams | any combination of audit, traffic, security |
| Traffic filter | `all`, `blocked` (everything not forwarded upstream), `security` (threat-protection verdicts and monitor-mode findings), `allowed` |
| Minimum severity | for security events: low, medium, high, critical |
| Remove URL query strings | strips `?…` from URLs before export (tokens in query strings never leave the proxy) |

## Delivery guarantees

- Every destination has its own in-memory queue (20,000 records), batches records (`batch_size`, default 500;
  `flush_seconds`, default 2) and never blocks the proxy or the API.
- When the queue is full (the destination is slower than the record rate), **audit and security** records are
  written to the spool instead (behind the records already spooled, so they may arrive slightly out of order);
  **traffic** records are dropped. Drops are counted as `dropped` and reported as the destination's last error
  (at most once a minute).
- When a destination is unavailable (network error, HTTP 408/429/5xx), batches are written to a durable
  **spool** on disk (`AEGIS_EXPORT_SPOOL_DIR/<sink id>`, size limit `spool_mb`, default 256 MB) and replayed **in
  order** with exponential backoff (1 s … 5 min). The spool survives restarts — delivery is **at least once**.
  Elasticsearch/OpenSearch use deterministic document IDs, so replays do not create duplicates.
- When the spool limit is reached the oldest segment is discarded and counted as `dropped`.
- Permanent rejections (HTTP 4xx such as invalid credentials or a mapping error) are counted as `failed` (records)
  and `discarded_batches` and not retried; the error is shown in the console. Destinations that carry audit or
  security records keep each rejected batch in `AEGIS_EXPORT_SPOOL_DIR/<sink id>/dead-letter.jsonl` (one JSON
  object per batch: time, sink, error and the encoded records; 32 MB, one older generation `.1`) so it can be
  inspected and replayed after fixing the cause. Deleting the destination deletes its spool directory and with
  it the dead-letter file.
- Splunk HEC with indexer acknowledgement: a batch counts as delivered once Splunk confirms it was indexed. A
  delivery attempt waits at most 30 s; when the acknowledgement takes longer, later attempts keep polling the
  same `ackId` instead of resending the batch. Only if no acknowledgement arrives within 2 minutes of sending is
  the batch resent (at least once, as Splunk recommends).
- In a cluster, every control-plane replica exports the records it produced itself (audit events of the writes it
  performed, flows and security events reported by the workers connected to it) — no duplicates across replicas.
  Status and counters in the console are those of the replica that answers the request; Prometheus metrics are
  per replica.

Prometheus metrics: `aegis_export_records_sent_total`, `aegis_export_records_failed_total`,
`aegis_export_records_dropped_total`, `aegis_export_batches_discarded_total`, `aegis_export_queue_records`,
`aegis_export_spool_bytes`, `aegis_export_sink_healthy` (label `sink`). Suggested alert:
`aegis_export_spool_bytes > 0 for 15m`, `increase(aegis_export_records_dropped_total[1h]) > 0` or
`increase(aegis_export_batches_discarded_total[1h]) > 0`.

## Security

- Only **Super Admins** can create, change or delete destinations (they decide where all logs go); InfoSec can
  view and test them. Every change is audited.
- Secrets (tokens, API keys, passwords, client secrets, TLS client keys, header values) are write-only: the API
  never returns them, empty values on update keep the stored ones.
- TLS certificate validation is on by default; a private CA can be pasted per destination, mutual TLS is
  supported for syslog/TLS and HTTPS destinations. `tls_skip_verify` exists for lab setups only.
- Destinations in link-local ranges (cloud metadata endpoints) are refused. Private and loopback addresses are
  allowed on purpose (internal SIEM collectors, local sidecars).
- Microsoft Sentinel with **managed identity** or **workload identity** sends tokens of the platform's identity,
  which the destination's author does not hold: the endpoint must be an Azure Monitor data collection endpoint
  (`*.monitor.azure.com`, `.us`, `.cn`, also via Private Link) and `authority_url` an Entra ID authority
  (`login.microsoftonline.com`, `.us`, `login.chinacloudapi.cn`). Loopback addresses stay allowed for local test
  doubles. Client-secret authentication is not restricted (the author supplies the secret).
- Endpoint URLs can carry credentials: query values are always masked in API responses and delivery errors,
  and webhook destinations show only scheme and host (`https://hooks.example/••••••`); sending the masked value
  back keeps the stored URL. Delivery errors never quote the full request URL. InfoSec Approvers see delivery
  errors without the destination's response body.
- `file` sinks can only write plain file names inside `AEGIS_EXPORT_DIR`.

## Setup examples

### rsyslog

```
# /etc/rsyslog.d/10-aegisproxy.conf  — TLS: also see the gtls/ossl stream driver documentation
module(load="imtcp")
input(type="imtcp" port="6514")    # destination: transport tcp, framing octet-counting (default)
template(name="aegis" type="string" string="/var/log/aegisproxy/%$.stream%.log")
if $app-name == "aegisproxy" then {
  set $.stream = $msgid;           # AUDIT | TRAFFIC | SECURITY
  action(type="omfile" dynaFile="aegis")
  stop
}
```

### syslog-ng

```
source s_aegis { network(transport("tcp") port(6514) flags(syslog-protocol)); };
destination d_aegis { file("/var/log/aegisproxy/${MSGID}.log"); };
log { source(s_aegis); filter { program("aegisproxy"); }; destination(d_aegis); };
```

### IBM QRadar / ArcSight

Syslog destination with format `leef` (QRadar, auto-detected as LEEF 2.0) or `cef` (ArcSight SmartConnector,
Splunk CEF add-ons). Use TCP or TLS; UDP truncates records above 64 KB.

### Splunk

Create an HEC token (Settings → Data inputs → HTTP Event Collector) with the target index allowed. Destination:
`https://splunk.corp.example:8088`, secret = token, optional index (`{stream}` is replaced by the stream name) and
source type prefix (default `aegisproxy` → `aegisproxy:traffic`, `aegisproxy:audit`, `aegisproxy:security`).
The add-on `deploy/splunk/TA-aegisproxy` maps these source types to the CIM data models Web, Change and
Intrusion Detection (Splunk Enterprise Security works without custom searches).

**Indexer acknowledgement** works without configuration: every request carries a stable request channel
(`X-Splunk-Request-Channel`, a GUID per destination). When the token has acknowledgement enabled, Splunk answers
with an `ackId`; AegisProxy then polls `/services/collector/ack` and counts the batch as delivered only once
Splunk confirms it was indexed. Without a confirmation within two minutes the batch stays in the spool and is
resent (at-least-once, so a rare duplicate is possible). Behind a load balancer the acknowledgement queries
follow the balancer's stickiness cookie to the same indexer.

### Elasticsearch / OpenSearch

Default index `logs-aegisproxy.{stream}-default` — the built-in `logs-*-*` data stream template of Elasticsearch
applies ECS mappings automatically. Create an API key with `create_doc` and `auto_configure` on
`logs-aegisproxy.*-*` and paste the encoded key as secret (or set a user name and use the password as secret).
For OpenSearch without data streams use an index such as `aegisproxy-{stream}`.

### Microsoft Sentinel

1. Create a Log Analytics custom table `AegisProxy_CL` with the columns `TimeGenerated (datetime), Stream,
   Severity, Message, EventId, Node, Action, Outcome, ServerName, ServerIP, Destination, Url, Method, RuleName,
   Actor, ThreatIndicator, ThreatSource (string), StatusCode (int), Data (dynamic)`.
2. Create a data collection endpoint (DCE) and a data collection rule (DCR) with the stream
   `Custom-AegisProxy_CL` (same columns) and the transformation `source`.
3. Choose how AegisProxy authenticates and grant that identity **Monitoring Metrics Publisher** on the DCR:

   | `azure_auth` | Identity | Destination fields |
   |---|---|---|
   | `client_secret` (default) | Entra ID app registration with a client secret | tenant ID, client ID, client secret |
   | `managed_identity` | managed identity of the Azure VM / VM scale set running the control-plane (token from IMDS) | client ID only for a user-assigned identity |
   | `workload_identity` | AKS workload identity: federated credential on an app registration or user-assigned identity for the control-plane's ServiceAccount | none; tenant and client ID come from `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` injected by the webhook (fields override them) |

   For workload identity in the Helm chart:

   ```yaml
   controlPlane:
     serviceAccount:
       create: true
       annotations: { azure.workload.identity/client-id: "<client id>" }
     podLabels: { azure.workload.identity/use: "true" }
   ```

   and add a federated credential for `system:serviceaccount:<namespace>:<release>-aegisproxy-control-plane`
   with the cluster's OIDC issuer.
4. Destination: endpoint = DCE logs ingestion URL, DCR immutable ID (`dcr-…`), stream name, and the fields of the
   chosen authentication. **Sovereign clouds** are detected from the endpoint: a DCE in Azure Government
   (`*.ingest.monitor.azure.us`) uses the token audience `https://monitor.azure.us` and the authority
   `https://login.microsoftonline.us`, Azure operated by 21Vianet (`*.azure.cn`) `https://monitor.azure.cn` and
   `https://login.chinacloudapi.cn`. Set `authority_url` only for a different Entra ID host.

Requests follow the official API definition (`POST /dataCollectionRules/{id}/streams/{stream}?api-version=2023-01-01`,
gzip, JSON array, at most 1 MB per call, split automatically) and carry an `x-ms-client-request-id`; it is part of
the error message of a failed upload, so Microsoft support can trace it.

Steps 1–3 are automated by `deploy/sentinel/aegisproxy-sentinel.bicep` (outputs endpoint, DCR immutable ID and
stream name). The same directory contains ASIM parsers (`ASimWebSessionAegisProxy`, `ASimAuditEventAegisProxy`),
analytics rules (malware downloads, threat-intel destinations, beaconing bursts, DLP, break-glass logins,
emergency changes, quarantines), a workbook and a Logic App playbook that quarantines incident hosts through a
[service account](identity.md#service-accounts) — see `deploy/sentinel/README.md`.

### Datadog

Endpoint of your site (`https://http-intake.logs.datadoghq.eu`, `…us3.datadoghq.com`, …) or of a Datadog
Observability Pipelines worker, secret = API key. Labels become tags (`env:prod`); `service:aegisproxy`,
`ddsource:aegisproxy`. Each log item carries only the reserved attributes (`ddsource`, `service`, `hostname`,
`ddtags`, `status`, `timestamp` in milliseconds) and the ECS attributes as a JSON `message`, which Datadog
parses into nested, facet-able attributes; agent-schema intakes (Observability Pipelines, Vector) accept the
same items unchanged.

### Grafana Loki

Endpoint `https://loki.corp.example:3100` (or Grafana Cloud with user name = instance ID and an access policy
token as secret). Multi-tenant Loki: add the header `X-Scope-OrgID`. Labels: `job=aegisproxy`, `stream`, `level`,
`node`, `verdict` (traffic) plus your static labels. Example query:
`{job="aegisproxy", stream="traffic"} | json | data_verdict != "ALLOWED"`.

### OpenTelemetry Collector (and everything behind it)

```yaml
receivers:
  otlp:
    protocols:
      http: { endpoint: 0.0.0.0:4318 }
exporters:
  kafka:
    brokers: [kafka-1:9092]
    topic: aegisproxy-logs
    encoding: otlp_json
  awss3:
    s3uploader: { region: eu-central-1, s3_bucket: corp-security-archive, s3_prefix: aegisproxy }
service:
  pipelines:
    logs: { receivers: [otlp], exporters: [kafka, awss3] }
```

Destination: `otlp`, endpoint `http://otel-collector:4318` (`/v1/logs` is appended). Authentication for hosted
backends goes into headers (e.g. `Authorization: Api-Token …`) or the bearer-token secret.

### Webhook

Each request carries `X-Aegis-Timestamp`, `X-Aegis-Delivery` (unique ID) and — with a secret —
`X-Aegis-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>`. Verify it and reject old
timestamps:

```python
import hmac, hashlib, time
def verify(secret: bytes, ts: str, body: bytes, sig: str) -> bool:
    if abs(time.time() - int(ts)) > 300:
        return False
    mac = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + mac, sig)
```

Body: `{"source":"aegisproxy","version":…,"node":…,"sent_at":…,"events":[…]}`.

### Files for log shippers

`file` destination `aegis-events.jsonl` → `$AEGIS_EXPORT_DIR/aegis-events.jsonl`. Filebeat:

```yaml
filebeat.inputs:
  - type: filestream
    id: aegisproxy
    paths: [/var/lib/aegis/export/aegis-events.jsonl]
    parsers: [{ ndjson: { target: "", overwrite_keys: true } }]
```

## Data-plane access log

Independently of the central export, each data-plane worker can write a classic proxy access log — useful for
Squid log analyzers, local rsyslog on the proxy host and container log collectors:

| Variable | Values |
|---|---|
| `AEGIS_ACCESS_LOG` | `off` (default), `stdout`, `stderr`, a file path, `syslog://host:514` (UDP), `syslog+tcp://host:514`, `syslog:///dev/log` (Linux) |
| `AEGIS_ACCESS_LOG_ROTATE_MB` | File destination only. `0` (Linux default): rotate externally with logrotate, the worker reopens the file after a rename. `> 0` (Windows default `100`): the worker rotates the file itself into `access.log.1 … .N` — required on Windows, where no other process can rename the open file |
| `AEGIS_ACCESS_LOG_KEEP` | Generations kept by the worker's own rotation (default `10`, oldest deleted). Size them to your privacy retention period for browsing data |
| `AEGIS_ACCESS_LOG_FORMAT` | `squid` (native Squid format: `time elapsed client TCP_MISS/200 bytes method URL user HIER_DIRECT/ip type`; blocks are `TCP_DENIED/403`, TLS passthrough `TCP_TUNNEL`), `combined` (Apache/NCSA combined with the verdict appended), `json` |

Writes happen on a background thread; an unreachable syslog server never slows down the proxy (lines are
dropped and retried after 5 seconds). Syslog messages use facility `local5` and the tag `aegisproxy-access`.
