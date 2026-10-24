// Helpers for the live traffic page: verdict classes, filter values, links and copy snippets.
import type { FlowVerdict, TrafficFlow } from '../../../types';
import type { Tone } from '../../../ui';

export type VerdictClass = 'allowed' | 'blocked' | 'security' | 'bypass' | 'learning' | 'simulated';

export const VERDICT_CLASSES: Array<{ id: VerdictClass; label: string; description: string; tone: Tone; verdicts: FlowVerdict[] }> = [
  {
    id: 'allowed',
    label: 'Allowed',
    description: 'Matched an allow rule, incl. linked redirect objects',
    tone: 'success',
    verdicts: ['ALLOWED', 'REDIRECT_OBJECT_ALLOWED'],
  },
  {
    id: 'blocked',
    label: 'Blocked',
    description: 'No allow rule matched (default deny) or a block rule',
    tone: 'danger',
    verdicts: ['BLOCKED'],
  },
  {
    id: 'security',
    label: 'Threats',
    description: 'Threat intel, antivirus, DLP, file type, policy guardrails, quarantine, failed proxy authentication',
    tone: 'danger',
    verdicts: ['THREAT_BLOCKED', 'MALWARE_BLOCKED', 'DLP_BLOCKED', 'FILETYPE_BLOCKED', 'POLICY_BLOCKED', 'QUARANTINED', 'AUTH_FAILED'],
  },
  {
    id: 'bypass',
    label: 'TLS passthrough',
    description: 'Not decrypted (TLS inspection exception)',
    tone: 'violet',
    verdicts: ['TLS_BYPASS'],
  },
  {
    id: 'learning',
    label: 'Learning',
    description: 'Recorded and allowed by a learning session',
    tone: 'info',
    verdicts: ['LEARNING_ALLOWED'],
  },
  {
    id: 'simulated',
    label: 'Simulated',
    description: 'Dry-run evaluations',
    tone: 'neutral',
    verdicts: ['SIMULATED'],
  },
];

export const ALL_VERDICTS: Array<{ value: FlowVerdict; label: string }> = [
  { value: 'ALLOWED', label: 'Allowed' },
  { value: 'REDIRECT_OBJECT_ALLOWED', label: 'Redirect object allowed' },
  { value: 'BLOCKED', label: 'Blocked' },
  { value: 'THREAT_BLOCKED', label: 'Threat blocked' },
  { value: 'MALWARE_BLOCKED', label: 'Malware blocked' },
  { value: 'DLP_BLOCKED', label: 'DLP blocked' },
  { value: 'FILETYPE_BLOCKED', label: 'File type blocked' },
  { value: 'POLICY_BLOCKED', label: 'Policy blocked' },
  { value: 'QUARANTINED', label: 'Quarantined' },
  { value: 'AUTH_FAILED', label: 'Proxy authentication failed' },
  { value: 'TLS_BYPASS', label: 'TLS bypass' },
  { value: 'LEARNING_ALLOWED', label: 'Learning' },
  { value: 'SIMULATED', label: 'Simulated' },
];

export function verdictClass(v: string): VerdictClass {
  for (const c of VERDICT_CLASSES) if ((c.verdicts as string[]).includes(v)) return c.id;
  return 'blocked';
}

export function isBlockedVerdict(v: string): boolean {
  const c = verdictClass(v);
  return c === 'blocked' || c === 'security';
}

/** Verdicts for which the block portal offers self-service requests. */
export function portalEligible(v: string): boolean {
  return v === 'BLOCKED' || v === 'POLICY_BLOCKED';
}

export function statusClass(code: number | undefined): string {
  if (!code) return 'none';
  if (code >= 500) return '5xx';
  if (code >= 400) return '4xx';
  if (code >= 300) return '3xx';
  if (code >= 200) return '2xx';
  return 'other';
}

export const STATUS_OPTIONS = [
  { value: '2xx', label: '2xx success' },
  { value: '3xx', label: '3xx redirect' },
  { value: '4xx', label: '4xx blocked / client error' },
  { value: '5xx', label: '5xx upstream error' },
  { value: 'none', label: 'No status' },
];

export type Signal = 'threat' | 'malware' | 'dlp' | 'flags' | 'redirect' | 'session';

export const SIGNAL_OPTIONS: Array<{ value: Signal; label: string }> = [
  { value: 'threat', label: 'Threat indicator match' },
  { value: 'malware', label: 'Antivirus finding' },
  { value: 'dlp', label: 'DLP finding' },
  { value: 'flags', label: 'Security flags' },
  { value: 'redirect', label: 'Redirect lineage' },
  { value: 'session', label: 'Learning session' },
];

export function flowSignals(f: TrafficFlow): Signal[] {
  const out: Signal[] = [];
  if (f.threat_indicator || f.threat_category) out.push('threat');
  if (f.av_signature || (f.av_result && f.av_result !== 'clean' && f.av_result !== 'skipped')) out.push('malware');
  if ((f.dlp_findings ?? []).length > 0) out.push('dlp');
  if ((f.security_flags ?? []).length > 0) out.push('flags');
  if (f.redirect_parent_url || f.redirect_location) out.push('redirect');
  if (f.session_id) out.push('session');
  return out;
}

export function flowBytes(f: TrafficFlow): number {
  return (f.bytes_received || 0) + (f.bytes_sent || 0);
}

/** "08:00:43" in local time. */
export function clockTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

const REASONS: Record<string, string> = {
  default_deny: 'No allow rule matches this destination (default deny)',
  raw_tcp: 'Raw TCP connections (non-HTTP tunnels) are blocked',
  ip_literal: 'Requests to bare IP addresses are blocked',
  private_destination: 'Requests to private or internal address ranges are blocked',
  port_not_allowed: 'The destination port is not in the allowed port list',
  punycode: 'Internationalized (punycode) host names are blocked',
  upload_too_large: 'The upload exceeds the maximum allowed size',
  quarantined: 'The server is quarantined: every destination is denied',
  host_mismatch: 'The Host header does not match the connection target (spoofing attempt)',
  sni_mismatch: 'The TLS server name (SNI) does not match the destination (domain fronting)',
  dns_rebinding: 'The host name resolved to an internal address (DNS rebinding)',
  forbidden_destination: 'Loopback, link-local and cloud metadata addresses are never reachable',
  internal_destination: 'Internal destinations are not reachable through the proxy',
  malformed_host: 'The host name is not a valid DNS name or IP address',
  malformed_path: 'The request path could not be normalized safely',
  missing_host: 'The request has no destination host',
  undecodable_content: 'The content encoding is unknown or broken, so it could not be inspected',
  partial_content: 'Partial (range) downloads cannot be inspected and are blocked',
  internal_error: 'The proxy blocked the request after an internal error (fail-closed)',
  unevaluated: 'The request was blocked because its policy evaluation did not complete (fail-closed)',
  av_oversize: 'The download exceeds the malware scan limit',
  av_error: 'The malware scanner was unavailable and the policy is fail-closed',
  icap_error: 'The ICAP scanning service was unavailable and the policy is fail-closed',
  icap_dlp: 'The data loss prevention engine (ICAP) blocked the upload',
  icap: 'The antivirus engine (ICAP) found malware',
  yara: 'The download matched a YARA rule',
  malware_hash: 'The file hash is listed as malicious',
  file_type: 'This file type is not permitted for the server group',
};

/** Human readable block reason (the data-plane sends machine codes such as default_deny). */
export function reasonLabel(f: Pick<TrafficFlow, 'block_reason' | 'verdict' | 'matched_rule_name'>): string | null {
  const r = f.block_reason;
  if (!r) {
    if (f.verdict === 'BLOCKED') return f.matched_rule_name ? `Block rule: ${f.matched_rule_name}` : 'No allow rule matches this destination (default deny)';
    return null;
  }
  if (REASONS[r]) return REASONS[r];
  const s = r.replace(/_/g, ' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Extracts the signed block token from a CLI block message (".../?portal=block&bt=<token>"). */
export function extractBlockToken(cli?: string | null): string | undefined {
  if (!cli) return undefined;
  const m = cli.match(/[?&]bt=([^\s&"']+)/);
  if (!m) return undefined;
  try {
    return decodeURIComponent(m[1]);
  } catch {
    return m[1];
  }
}

/** Public block portal for a blocked flow (signed token when available, else ip/url/trace). */
export function portalUrl(f: Pick<TrafficFlow, 'server_ip' | 'full_url' | 'id' | 'block_token'>, token?: string): string {
  const p = new URLSearchParams({ portal: 'block' });
  const bt = token || f.block_token;
  if (bt) p.set('bt', bt);
  p.set('ip', f.server_ip);
  p.set('url', f.full_url);
  p.set('trace', f.id);
  return `/?${p.toString()}`;
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** curl command that repeats the request through the proxy (run it on the server). */
export function curlCommand(f: Pick<TrafficFlow, 'method' | 'full_url' | 'user_agent'>, proxyAddress?: string): string {
  const parts = ['curl -sS'];
  parts.push(f.method === 'HEAD' ? '-I' : '-o /dev/null -w "%{http_code}\\n"');
  if (proxyAddress) parts.push(`-x ${shellQuote(proxyAddress.includes('://') ? proxyAddress : `http://${proxyAddress}`)}`);
  if (f.method && !['GET', 'HEAD', 'CONNECT'].includes(f.method)) parts.push(`-X ${f.method}`);
  parts.push(shellQuote(f.full_url));
  return parts.join(' ');
}
