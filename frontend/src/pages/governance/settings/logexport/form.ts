// Log export destination form: conversion from/to the API model and client-side validation
// (mirrors control-plane/internal/export/validate.go; the server stays authoritative).

import type { AzureAuth, ExportSink, ExportSinkType, ExportStream } from '../../../../types';
import { SECRET_REQUIRED } from './catalog';

export interface HeaderRow {
  name: string;
  value: string;
  /** Exists on the server; an empty value keeps the stored value. */
  stored: boolean;
}

export type SecretMode = 'new' | 'keep' | 'replace' | 'clear';

export interface SinkForm {
  id?: string;
  name: string;
  type: string;
  enabled: boolean;
  streams: ExportStream[];
  format: string;
  traffic_filter: ExportSink['traffic_filter'];
  min_severity: ExportSink['min_severity'];
  redact_query: boolean;
  endpoint: string;
  transport: string;
  syslog_protocol: string;
  syslog_facility: string;
  syslog_framing: string;
  index: string;
  source_type: string;
  labels: Record<string, string>;
  username: string;
  tenant_id: string;
  client_id: string;
  dcr_immutable_id: string;
  stream_name: string;
  authority_url: string;
  azure_auth: AzureAuth;
  tls_skip_verify: boolean;
  ca_cert_pem: string;
  client_cert_pem: string;
  /** Stored client key on the server. */
  hasStoredKey: boolean;
  keyMode: 'keep' | 'replace';
  client_key_pem: string;
  secretMode: SecretMode;
  secret: string;
  headers: HeaderRow[];
  batch_size: number;
  flush_seconds: number;
  spool_mb: number;
}

export function newForm(t: ExportSinkType, type: string): SinkForm {
  return {
    name: '',
    type,
    enabled: true,
    streams: ['audit', 'security', 'traffic'],
    format: (t.formats ?? [])[0] || 'json',
    traffic_filter: 'all',
    min_severity: 'low',
    redact_query: true,
    endpoint: type === 'file' ? 'aegis-events.jsonl' : '',
    transport: 'tcp',
    syslog_protocol: 'rfc5424',
    syslog_facility: 'local0',
    syslog_framing: 'octet-counting',
    index: '',
    source_type: '',
    labels: {},
    username: '',
    tenant_id: '',
    client_id: '',
    dcr_immutable_id: '',
    stream_name: type === 'sentinel' ? 'Custom-AegisProxy_CL' : '',
    authority_url: '',
    azure_auth: 'client_secret',
    tls_skip_verify: false,
    ca_cert_pem: '',
    client_cert_pem: '',
    hasStoredKey: false,
    keyMode: 'replace',
    client_key_pem: '',
    secretMode: 'new',
    secret: '',
    headers: [],
    batch_size: 500,
    flush_seconds: 2,
    spool_mb: 256,
  };
}

export function fromSink(s: ExportSink): SinkForm {
  return {
    id: s.id,
    name: s.name,
    type: s.type,
    enabled: s.enabled,
    streams: [...(s.streams ?? [])],
    format: s.format,
    traffic_filter: s.traffic_filter || 'all',
    min_severity: s.min_severity || 'low',
    redact_query: !!s.redact_query,
    endpoint: s.endpoint || '',
    transport: s.transport || 'tcp',
    syslog_protocol: s.syslog_protocol || 'rfc5424',
    syslog_facility: s.syslog_facility || 'local0',
    syslog_framing: s.syslog_framing || 'octet-counting',
    index: s.index || '',
    source_type: s.source_type || '',
    labels: { ...(s.labels ?? {}) },
    username: s.username || '',
    tenant_id: s.tenant_id || '',
    client_id: s.client_id || '',
    dcr_immutable_id: s.dcr_immutable_id || '',
    stream_name: s.stream_name || '',
    authority_url: s.authority_url || '',
    azure_auth: s.azure_auth || 'client_secret',
    tls_skip_verify: !!s.tls_skip_verify,
    ca_cert_pem: s.ca_cert_pem || '',
    client_cert_pem: s.client_cert_pem || '',
    hasStoredKey: !!s.has_client_key,
    keyMode: s.has_client_key ? 'keep' : 'replace',
    client_key_pem: '',
    secretMode: s.has_secret ? 'keep' : 'new',
    secret: '',
    headers: Object.keys(s.headers ?? {})
      .sort()
      .map((name) => ({ name, value: '', stored: true })),
    batch_size: s.batch_size || 500,
    flush_seconds: s.flush_seconds || 2,
    spool_mb: s.spool_mb || 256,
  };
}

/** Whether the TLS section applies (syslog only over TLS). */
export function usesTLS(f: SinkForm, fields: string[]): boolean {
  if (!fields.includes('tls')) return false;
  return !fields.includes('transport') || f.transport === 'tls';
}

/**
 * Whether the form points a saved destination somewhere else (mirrors sameSinkDestination on the
 * server): stored secrets, header values and client keys stay with the saved destination.
 */
export function destinationChanged(f: SinkForm, s: ExportSink | null | undefined): boolean {
  if (!s) return false;
  return (
    f.endpoint.trim() !== (s.endpoint || '') ||
    (f.transport || 'tcp') !== (s.transport || 'tcp') ||
    f.username.trim() !== (s.username || '') ||
    f.tenant_id.trim() !== (s.tenant_id || '') ||
    f.client_id.trim() !== (s.client_id || '') ||
    f.authority_url.trim() !== (s.authority_url || '') ||
    f.azure_auth !== (s.azure_auth || 'client_secret') ||
    f.tls_skip_verify !== !!s.tls_skip_verify ||
    f.ca_cert_pem.trim() !== (s.ca_cert_pem || '').trim() ||
    f.client_cert_pem.trim() !== (s.client_cert_pem || '').trim()
  );
}

/** Request body for create / update / test. Write-only values follow the "empty = keep" contract. */
export function toPayload(f: SinkForm, fields: string[]): Partial<ExportSink> {
  const has = (k: string) => fields.includes(k);
  const p: Partial<ExportSink> = {
    name: f.name.trim(),
    type: f.type,
    enabled: f.enabled,
    streams: f.streams,
    format: f.format,
    traffic_filter: f.traffic_filter,
    min_severity: f.min_severity,
    redact_query: f.redact_query,
    endpoint: f.endpoint.trim(),
    batch_size: f.batch_size,
    flush_seconds: f.flush_seconds,
    spool_mb: f.spool_mb,
    tls_skip_verify: has('tls') ? f.tls_skip_verify : false,
  };
  if (f.id) p.id = f.id;
  if (has('transport')) p.transport = f.transport;
  if (has('syslog_protocol')) p.syslog_protocol = f.syslog_protocol;
  if (has('syslog_facility')) p.syslog_facility = f.syslog_facility;
  if (has('syslog_framing')) p.syslog_framing = f.syslog_framing;
  if (has('index')) p.index = f.index.trim();
  if (has('source_type')) p.source_type = f.source_type.trim();
  if (has('username')) p.username = f.username.trim();
  if (has('labels')) p.labels = f.labels;
  if (has('tenant_id')) p.tenant_id = f.tenant_id.trim();
  if (has('client_id')) p.client_id = f.client_id.trim();
  if (has('dcr_immutable_id')) p.dcr_immutable_id = f.dcr_immutable_id.trim();
  if (has('stream_name')) p.stream_name = f.stream_name.trim();
  if (has('authority_url')) p.authority_url = f.authority_url.trim();
  if (f.type === 'sentinel') p.azure_auth = f.azure_auth;
  if (has('tls')) {
    p.ca_cert_pem = f.ca_cert_pem.trim() ? f.ca_cert_pem : '';
    p.client_cert_pem = f.client_cert_pem.trim() ? f.client_cert_pem : '';
    if (f.keyMode === 'replace' && f.client_key_pem.trim()) p.client_key_pem = f.client_key_pem;
  }
  if (has('headers')) {
    const h: Record<string, string> = {};
    for (const r of f.headers) if (r.name.trim()) h[r.name.trim()] = r.value;
    p.headers = h;
  }
  if (!usesSecret(f)) {
    // Passwordless authentication: a client secret stored earlier is no longer needed.
    if (f.secretMode !== 'new') p.clear_secret = true;
    return p;
  }
  if (f.secretMode === 'clear') p.clear_secret = true;
  else if ((f.secretMode === 'new' || f.secretMode === 'replace') && f.secret) p.secret = f.secret;
  return p;
}

const HEADER_RE = /^[A-Za-z0-9!#$%&'*+.^_|~-]{1,64}$/;
const FORBIDDEN_HEADERS = ['host', 'content-length', 'content-type', 'content-encoding', 'transfer-encoding', 'connection', 'te', 'upgrade'];
const LABEL_RE = /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/;
const FILE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$/;

function httpUrl(v: string, httpsOnly: boolean): boolean {
  try {
    const u = new URL(v);
    if (!u.host || u.username || u.password) return false;
    return u.protocol === 'https:' || (!httpsOnly && u.protocol === 'http:');
  } catch {
    return false;
  }
}

export type FormErrors = Partial<Record<string, string>>;

/** Sentinel with managed or workload identity authenticates without a stored secret. */
export function usesSecret(f: Pick<SinkForm, 'type' | 'azure_auth'>): boolean {
  return f.type !== 'sentinel' || f.azure_auth === 'client_secret';
}

export function validateForm(f: SinkForm, t: ExportSinkType | undefined, saved?: ExportSink | null): FormErrors {
  const e: FormErrors = {};
  const fields = t?.fields ?? [];
  if (!f.name.trim()) e.name = 'Give the destination a name.';
  else if (f.name.trim().length > 80) e.name = 'At most 80 characters.';
  if (f.streams.length === 0) e.streams = 'Select at least one stream.';
  const ep = f.endpoint.trim();
  switch (f.type) {
    case 'syslog':
      if (!/^(\[[0-9a-fA-F:.]+\]|[^\s:[\]]+):\d{1,5}$/.test(ep) || Number(ep.split(':').pop()) < 1 || Number(ep.split(':').pop()) > 65535)
        e.endpoint = 'Use host:port, e.g. siem.corp.example:6514.';
      break;
    case 'file':
      if (!FILE_RE.test(ep) || ep.includes('..')) e.endpoint = 'A plain file name: letters, digits, . _ - (no folders).';
      break;
    case 'datadog':
      if (ep && !httpUrl(ep, true)) e.endpoint = 'Use an https:// URL (or leave empty for datadoghq.com).';
      break;
    case 'sentinel':
      if (!httpUrl(ep, true)) e.endpoint = 'Use the https:// logs ingestion URL of the data collection endpoint.';
      for (const k of ['tenant_id', 'client_id', 'dcr_immutable_id'] as const)
        if (!f[k].trim() && (k === 'dcr_immutable_id' || f.azure_auth === 'client_secret')) e[k] = 'Required.';
      if (f.stream_name.trim() && !f.stream_name.trim().startsWith('Custom-')) e.stream_name = 'Must start with Custom- (the stream declared in the DCR).';
      if (f.authority_url.trim() && !httpUrl(f.authority_url.trim(), true)) e.authority_url = 'Use an https:// URL.';
      break;
    default:
      if (!httpUrl(ep, false)) e.endpoint = 'Use an http(s):// URL without credentials (put secrets into the secret field).';
  }
  const secretProvided = f.secretMode === 'keep' || ((f.secretMode === 'new' || f.secretMode === 'replace') && !!f.secret);
  if (SECRET_REQUIRED.includes(f.type) && usesSecret(f) && !secretProvided) e.secret = `${t?.secret_label || 'A secret'} is required for this destination.`;
  else if (f.secretMode === 'replace' && !f.secret) e.secret = 'Enter the new value, or keep the stored one.';
  if (fields.includes('headers')) {
    const seen = new Set<string>();
    f.headers.forEach((h, i) => {
      const n = h.name.trim();
      if (!n) {
        if (h.value) e[`headers.${i}`] = 'Enter the header name.';
        return;
      }
      if (!HEADER_RE.test(n)) e[`headers.${i}`] = 'Invalid header name.';
      else if (FORBIDDEN_HEADERS.includes(n.toLowerCase())) e[`headers.${i}`] = `${n} is set by AegisProxy and cannot be overridden.`;
      else if (seen.has(n.toLowerCase())) e[`headers.${i}`] = 'Duplicate header.';
      else if (!h.stored && !h.value) e[`headers.${i}`] = 'Enter a value.';
      seen.add(n.toLowerCase());
    });
    if (f.headers.filter((h) => h.name.trim()).length > 20) e.headers = 'At most 20 headers.';
  }
  if (fields.includes('labels')) {
    const keys = Object.keys(f.labels);
    if (keys.length > 20) e.labels = 'At most 20 labels.';
    const bad = keys.find((k) => !LABEL_RE.test(k));
    if (bad) e.labels = `Label “${bad}”: start with a letter or _, then letters, digits, _ or .`;
  }
  if (usesTLS(f, fields)) {
    const cert = f.client_cert_pem.trim();
    const keyProvided = f.keyMode === 'replace' ? !!f.client_key_pem.trim() : f.hasStoredKey;
    if (cert && !keyProvided) e.client_key_pem = 'Paste the private key of the client certificate.';
    if (!cert && f.keyMode === 'replace' && f.client_key_pem.trim()) e.client_cert_pem = 'Paste the client certificate for this key.';
    if (cert && !cert.includes('-----BEGIN')) e.client_cert_pem = 'Paste a PEM certificate (-----BEGIN CERTIFICATE-----).';
    if (f.ca_cert_pem.trim() && !f.ca_cert_pem.includes('-----BEGIN CERTIFICATE-----')) e.ca_cert_pem = 'Paste one or more PEM certificates.';
  }
  const range = (k: 'batch_size' | 'flush_seconds' | 'spool_mb', min: number, max: number) => {
    const v = f[k];
    if (!Number.isInteger(v) || v < min || v > max) e[k] = `${min}–${max}`;
  };
  range('batch_size', 1, 5000);
  range('flush_seconds', 1, 300);
  range('spool_mb', 16, 102400);
  if (destinationChanged(f, saved)) {
    const again = 'The destination changed — enter this value again (stored values stay with the saved destination).';
    if (f.secretMode === 'keep' && usesSecret(f)) e.secret ??= again;
    f.headers.forEach((h, i) => {
      if (h.stored && h.name.trim() && !h.value) e[`headers.${i}`] ??= again;
    });
    if (usesTLS(f, fields) && f.client_cert_pem.trim() && f.keyMode !== 'replace' && f.hasStoredKey) e.client_key_pem ??= again;
  }
  return e;
}
