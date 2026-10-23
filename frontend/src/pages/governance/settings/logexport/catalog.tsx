// Presentation metadata for log export destination types. The list of types, their formats and
// type-specific fields come from the server catalog (GET /api/integrations/exports → types[]).

import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { BarChart3, Cloud, Database, Dog, FileText, Radio, ScrollText, Search, Webhook } from 'lucide-react';
import type { ExportSink, ExportSinkStatus, ExportSinkType, ExportStream } from '../../../../types';
import type { Tone } from '../../../../ui';

export const TYPE_ICONS: Record<string, LucideIcon> = {
  syslog: ScrollText,
  otlp: Radio,
  splunk_hec: Search,
  elasticsearch: Database,
  sentinel: Cloud,
  datadog: Dog,
  loki: BarChart3,
  webhook: Webhook,
  file: FileText,
};

/** Short names for chips and cards (the catalog label is the long form). */
export const TYPE_SHORT: Record<string, string> = {
  syslog: 'Syslog',
  otlp: 'OpenTelemetry',
  splunk_hec: 'Splunk HEC',
  elasticsearch: 'Elasticsearch',
  sentinel: 'Microsoft Sentinel',
  datadog: 'Datadog',
  loki: 'Grafana Loki',
  webhook: 'Webhook',
  file: 'Local file',
};

export const typeId = (t: ExportSinkType) => t.type || t.id || '';

export const FORMAT_LABELS: Record<string, { label: string; hint: string }> = {
  json: { label: 'JSON (native)', hint: 'The unmodified record in a small envelope — best for custom pipelines.' },
  ecs: { label: 'ECS (Elastic Common Schema)', hint: 'Flat, well-known field names (source.ip, url.full …) — works with most SIEM parsers.' },
  cef: { label: 'CEF (ArcSight)', hint: 'Common Event Format for ArcSight SmartConnectors and CEF add-ons (Splunk, Sentinel via AMA).' },
  leef: { label: 'LEEF 2.0 (QRadar)', hint: 'IBM QRadar detects LEEF automatically.' },
  otel: { label: 'OpenTelemetry log records', hint: 'OTLP logs with ECS / semantic-convention attributes.' },
  structured: { label: 'Structured fields', hint: 'Fixed for this destination: records are mapped to its native fields.' },
};

export const STREAMS: Array<{ value: ExportStream; label: string; description: string }> = [
  { value: 'audit', label: 'Audit', description: 'Every administrative change and decision (hash-chained).' },
  { value: 'traffic', label: 'Traffic', description: 'Every proxied request: server, URL, verdict, bytes, rule.' },
  { value: 'security', label: 'Security', description: 'Threat-protection events with severity.' },
];

export const TRAFFIC_FILTERS = [
  { value: 'all', label: 'All requests' },
  { value: 'blocked', label: 'Blocked only' },
  { value: 'security', label: 'Security verdicts only' },
  { value: 'allowed', label: 'Allowed only' },
];

export const SEVERITIES = [
  { value: 'low', label: 'Low and above' },
  { value: 'medium', label: 'Medium and above' },
  { value: 'high', label: 'High and above' },
  { value: 'critical', label: 'Critical only' },
];

export const FACILITIES = ['local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7', 'user', 'daemon', 'auth', 'authpriv', 'syslog', 'security', 'kern'];

/** Endpoint label per type. */
export function endpointLabel(type: string): { label: string; hint: string } {
  switch (type) {
    case 'syslog':
      return { label: 'Host and port', hint: 'e.g. siem.corp.example:6514 (TLS) or :514 (UDP/TCP).' };
    case 'file':
      return { label: 'File name', hint: 'A plain file name; written to the export directory and rotated at 100 MB × 5.' };
    case 'sentinel':
      return { label: 'Data collection endpoint', hint: 'Logs ingestion URL of the DCE (https://…ingest.monitor.azure.com).' };
    case 'otlp':
      return { label: 'Collector URL', hint: '/v1/logs is appended automatically.' };
    case 'datadog':
      return { label: 'Intake URL', hint: 'The HTTP log intake of your Datadog site; empty uses datadoghq.com.' };
    default:
      return { label: 'URL', hint: 'http(s):// endpoint of the destination.' };
  }
}

/** Concise setup guidance per type (shown in the drawer). */
export const TYPE_HELP: Record<string, React.ReactNode> = {
  syslog: (
    <>
      Use <strong>LEEF</strong> for IBM QRadar and <strong>CEF</strong> for ArcSight; JSON or ECS for rsyslog / syslog-ng. Prefer TCP or TLS — UDP truncates
      records above 64 KB. Octet-counting framing (RFC 6587) is the safe default for TCP.
    </>
  ),
  otlp: (
    <>
      Sends OTLP/HTTP logs (JSON, gzip) to an <strong>OpenTelemetry Collector</strong> or any OTLP backend. Everything else — Kafka, S3, Google SecOps, Sumo
      Logic, Event Hubs — is reachable through a collector exporter. Hosted backends usually need an authorization header.
    </>
  ),
  splunk_hec: (
    <>
      Create an HEC token (Settings → Data inputs → HTTP Event Collector) that may write to the target index. The index may contain <code>{'{stream}'}</code>; the
      source type defaults to <code>aegisproxy</code> → <code>aegisproxy:traffic</code>.
    </>
  ),
  elasticsearch: (
    <>
      ECS documents via the Bulk API; the default index <code>{'logs-aegisproxy.{stream}-default'}</code> uses the built-in data stream template. Paste an
      encoded API key with <code>create_doc</code> and <code>auto_configure</code>, or set a user name and use the password as secret. OpenSearch: use an index
      like <code>{'aegisproxy-{stream}'}</code>.
    </>
  ),
  sentinel: (
    <ol className="list-decimal space-y-0.5 pl-4">
      <li>
        Create the custom table <code>AegisProxy_CL</code> in the Log Analytics workspace.
      </li>
      <li>
        Create a data collection endpoint (DCE) and rule (DCR) with the stream <code>Custom-AegisProxy_CL</code>.
      </li>
      <li>
        Grant “Monitoring Metrics Publisher” on the DCR to the identity AegisProxy uses: an app registration with a client secret, the managed identity of
        the Azure VM, or an AKS workload identity.
      </li>
      <li>Enter the DCE URL and the DCR immutable ID (dcr-…) here and choose the authentication. Azure Government and Azure China are detected from the URL.</li>
    </ol>
  ),
  datadog: (
    <>
      Choose the intake of your Datadog site (e.g. <code>https://http-intake.logs.datadoghq.eu</code>) and paste an API key. Labels become tags such as{' '}
      <code>env:prod</code>.
    </>
  ),
  loki: (
    <>
      Labels stay low-cardinality (job, stream, level, node, verdict plus yours). Grafana Cloud: user name = instance ID, secret = access policy token.
      Multi-tenant Loki: add the header <code>X-Scope-OrgID</code>.
    </>
  ),
  webhook: (
    <>
      JSON batches via HTTPS POST. With a secret, every request carries <code>X-Aegis-Signature: sha256=…</code> (HMAC-SHA256 of timestamp + body) — verify it
      and reject old timestamps.
    </>
  ),
  file: (
    <>
      JSON Lines (or CEF/LEEF lines) in the export directory for Filebeat, Fluent Bit, Vector, NXLog or a Splunk forwarder. Each file destination needs its own
      file name.
    </>
  ),
};

export const STATE_META: Record<string, { label: string; tone: Tone; description: string }> = {
  ok: { label: 'Delivering', tone: 'success', description: 'The last batch was delivered.' },
  idle: { label: 'Idle', tone: 'neutral', description: 'Running; nothing to send yet.' },
  retrying: { label: 'Retrying', tone: 'warning', description: 'The destination is unavailable; records are spooled to disk and retried with backoff.' },
  error: { label: 'Error', tone: 'danger', description: 'The destination rejected records (e.g. credentials or mapping). They are counted as failed and not retried.' },
  disabled: { label: 'Disabled', tone: 'neutral', description: 'Not exporting.' },
};

export function stateOf(sink: ExportSink, status?: ExportSinkStatus): { label: string; tone: Tone; description: string } {
  if (!sink.enabled) return STATE_META.disabled;
  if (!status) return { label: 'No status yet', tone: 'neutral', description: 'This replica has not reported a status for the destination yet.' };
  return STATE_META[status.state] ?? { label: status.state, tone: 'neutral', description: '' };
}

export const SECRET_REQUIRED = ['splunk_hec', 'datadog', 'sentinel'];
