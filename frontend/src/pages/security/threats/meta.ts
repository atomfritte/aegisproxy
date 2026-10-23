// Labels, tones and helpers for the threat protection area (page-local).
import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  AlertTriangle,
  Ban,
  Bug,
  FileQuestion,
  FileX,
  KeyRound,
  Languages,
  Lock,
  Radar,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-react';
import type { FeedFormat, IndicatorType, SecurityEvent, SecuritySeverity, ThreatException, ThreatMode } from '../../../types';
import type { Tone } from '../../../ui';

export const THREAT_TABS = ['overview', 'events', 'feeds', 'iocs', 'exceptions', 'yara', 'policy', 'lookup'] as const;
export type ThreatTab = (typeof THREAT_TABS)[number];

export const tabPath = (t: ThreatTab) => (t === 'overview' ? '/threats' : `/threats/${t}`);
export const eventPath = (id: string) => `/threats/events/${encodeURIComponent(id)}`;

export const SEVERITIES: SecuritySeverity[] = ['critical', 'high', 'medium', 'low'];
export const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
export const SEVERITY_META: Record<SecuritySeverity, { label: string; tone: Tone; solid?: boolean }> = {
  critical: { label: 'Critical', tone: 'danger', solid: true },
  high: { label: 'High', tone: 'danger' },
  medium: { label: 'Medium', tone: 'warning' },
  low: { label: 'Low', tone: 'neutral' },
};

export interface EventTypeMeta {
  label: string;
  icon: LucideIcon;
  description: string;
}

export const EVENT_TYPES: Record<string, EventTypeMeta> = {
  THREAT_INTEL: { label: 'Threat intelligence', icon: Radar, description: 'The destination matched a threat-intelligence feed or a custom indicator.' },
  MALWARE: { label: 'Malware', icon: Bug, description: 'The antivirus scanner found a malware signature in downloaded content.' },
  DLP: { label: 'Data loss prevention', icon: KeyRound, description: 'Credentials or secrets were detected in an outbound request.' },
  FILE_TYPE: { label: 'Blocked file type', icon: FileX, description: 'A download of a blocked file type (detected by magic bytes) was stopped.' },
  POLICY: { label: 'Protocol guard', icon: Ban, description: 'A protocol or destination hygiene check failed (raw TCP, SNI or Host mismatch, DNS rebinding).' },
  ANOMALY: { label: 'Anomaly', icon: Activity, description: 'Unusual behaviour was detected for this server.' },
  PUNYCODE: { label: 'Punycode domain', icon: Languages, description: 'An internationalized (xn--) domain was accessed — check for homograph spoofing.' },
  AV_UNSCANNED: { label: 'Unscanned download', icon: FileQuestion, description: 'Content was delivered without an antivirus scan (too large or scanner unavailable).' },
  AV_ERROR: { label: 'Antivirus error', icon: AlertTriangle, description: 'The antivirus scan failed or timed out.' },
  AV_SUPPRESSED: { label: 'Antivirus suppressed', icon: ShieldCheck, description: 'An antivirus verdict was overridden by a SHA-256 exception.' },
  BLOCK_BURST: { label: 'Blocked burst', icon: Activity, description: 'Many blocked requests within one minute — possible malware beaconing or a broken job.' },
  QUARANTINE: { label: 'Quarantine', icon: Lock, description: 'A quarantined server tried to reach the internet.' },
};

export function eventTypeMeta(type: string): EventTypeMeta {
  return EVENT_TYPES[type] ?? { label: humanizeCode(type), icon: ShieldAlert, description: '' };
}

export function humanizeCode(v: string): string {
  const s = (v || '').replace(/[_-]+/g, ' ').toLowerCase().trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '—';
}

export const MODE_META: Record<string, { label: string; tone: Tone; description: string }> = {
  block: { label: 'Block', tone: 'success', description: 'Matching requests are denied and logged.' },
  monitor: { label: 'Monitor', tone: 'warning', description: 'Requests are allowed; matches are logged as security events.' },
  off: { label: 'Off', tone: 'neutral', description: 'Not evaluated.' },
};

export const THREAT_MODES: ThreatMode[] = ['off', 'monitor', 'block'];

export const FEED_FORMATS: Array<{ value: FeedFormat; label: string; hint: string; structured?: boolean }> = [
  { value: 'domains', label: 'Domains', hint: 'One domain per line (adblock ||domain^ syntax works too)' },
  { value: 'hosts', label: 'Hosts file', hint: '0.0.0.0 domain or 127.0.0.1 domain lines' },
  { value: 'urls', label: 'URLs', hint: 'Absolute http(s) URLs, matched exactly' },
  { value: 'ips', label: 'IPs / CIDRs', hint: 'IP addresses or networks (Spamhaus format supported)' },
  { value: 'sha256', label: 'SHA-256 hashes', hint: 'File hashes, one per line' },
  { value: 'taxii21', label: 'TAXII 2.1 collection', hint: 'STIX 2.1 indicators (domain, URL, IP, file hash patterns)', structured: true },
  { value: 'misp', label: 'MISP instance', hint: 'Exportable (to_ids) attributes via restSearch, warninglists applied', structured: true },
];

/** Feed managed by the Microsoft Defender integration (format mde). */
export const isDefenderFeed = (f: { format: string; id?: string }) => f.format === 'mde' || f.id === 'microsoft-defender-indicators';

export const feedFormatLabel = (format: string) =>
  format === 'mde' ? 'Microsoft Defender indicators' : FEED_FORMATS.find((x) => x.value === format)?.label ?? format;

/** Threat categories; the category drives the severity of resulting security events. */
export const THREAT_CATEGORIES: Array<{ value: string; label: string; severity: SecuritySeverity }> = [
  { value: 'malware', label: 'Malware distribution', severity: 'critical' },
  { value: 'ransomware', label: 'Ransomware', severity: 'critical' },
  { value: 'botnet_c2', label: 'Botnet / command and control', severity: 'critical' },
  { value: 'compromised_host', label: 'Compromised host', severity: 'critical' },
  { value: 'phishing', label: 'Phishing', severity: 'high' },
  { value: 'hijacked_network', label: 'Hijacked network', severity: 'high' },
  { value: 'threat_intel', label: 'Generic threat intelligence', severity: 'high' },
  { value: 'cryptomining', label: 'Cryptomining', severity: 'medium' },
  { value: 'exfiltration', label: 'Data exfiltration', severity: 'medium' },
  { value: 'adware_tracking', label: 'Adware / tracking', severity: 'medium' },
  { value: 'custom', label: 'Custom', severity: 'medium' },
];

export const categoryLabel = (v: string) =>
  v === 'microsoft_defender' ? 'Microsoft Defender' : THREAT_CATEGORIES.find((c) => c.value === v)?.label ?? humanizeCode(v);

/** Select options for a category (keeps an unknown current value selectable). */
export function categoryOptions(current: string) {
  const opts = THREAT_CATEGORIES.map((c) => ({ value: c.value, label: `${c.label} (${c.severity})` }));
  if (current && !THREAT_CATEGORIES.some((c) => c.value === current)) opts.push({ value: current, label: current });
  return opts;
}

export const IOC_TYPES: Array<{ value: IndicatorType; label: string; placeholder: string; hint: string }> = [
  { value: 'domain', label: 'Domain', placeholder: 'evil.example', hint: 'Matches the domain and its subdomains. A leading *. is ignored.' },
  { value: 'url', label: 'URL', placeholder: 'https://cdn.example/payload.bin', hint: 'Absolute http(s) URL, matched exactly after normalization.' },
  { value: 'ip', label: 'IP address', placeholder: '203.0.113.7', hint: 'IPv4 or IPv6. Also matches hostnames that resolve to it.' },
  { value: 'cidr', label: 'Network (CIDR)', placeholder: '198.51.100.0/24', hint: 'Prefix length of at least /8.' },
  { value: 'sha256', label: 'SHA-256', placeholder: '64 hexadecimal characters', hint: 'Blocks downloads whose content hash matches.' },
];

export const EXCEPTION_TYPES: Array<{ value: ThreatException['type']; label: string; placeholder: string; hint: string }> = [
  { value: 'domain', label: 'Domain', placeholder: 'good.example', hint: 'Suppresses matches for the domain and its subdomains.' },
  { value: 'url', label: 'URL', placeholder: 'https://good.example/file.zip', hint: 'Suppresses matches for exactly this URL.' },
  { value: 'ip', label: 'IP address', placeholder: '192.0.2.10', hint: 'Suppresses IP and CIDR matches for this address.' },
  { value: 'sha256', label: 'SHA-256', placeholder: '64 hexadecimal characters', hint: 'Also overrides an antivirus verdict for exactly this file.' },
];

/** Client-side hint (the server validates again). */
export function validateIndicatorValue(type: IndicatorType, raw: string): string | null {
  const v = raw.trim();
  if (!v) return 'Enter a value.';
  switch (type) {
    case 'domain':
      return /^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]{2,}$/i.test(v) && !/^\d+(\.\d+){3}$/.test(v) ? null : 'Enter a domain like evil.example (no scheme or path).';
    case 'url':
      try {
        const u = new URL(v);
        return /^https?:$/.test(u.protocol) && u.host ? null : 'Use an absolute http:// or https:// URL.';
      } catch {
        return 'Use an absolute http:// or https:// URL.';
      }
    case 'ip':
      return isIP(v) ? null : 'Enter an IPv4 or IPv6 address.';
    case 'cidr': {
      const [ip, bits] = v.split('/');
      const n = Number(bits);
      if (!ip || bits === undefined || !isIP(ip) || !Number.isInteger(n)) return 'Enter a network like 198.51.100.0/24.';
      if (n < 8) return 'The prefix length must be at least /8.';
      if (n > (ip.includes(':') ? 128 : 32)) return 'Prefix length too large.';
      return null;
    }
    case 'sha256':
      return /^[a-f0-9]{64}$/i.test(v) ? null : 'A SHA-256 hash has 64 hexadecimal characters.';
  }
  return null;
}

export function isIP(v: string): boolean {
  if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(v)) return v.split('.').every((p) => Number(p) <= 255);
  return v.includes(':') && /^[0-9a-f:.]+$/i.test(v);
}

/** Guesses the indicator type of a value (lookup results, event indicators). */
export function guessIndicatorType(value: string): IndicatorType {
  const v = value.trim();
  if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256';
  if (/^https?:\/\//i.test(v)) return 'url';
  if (v.includes('/') && isIP(v.split('/')[0])) return 'cidr';
  if (isIP(v)) return 'ip';
  return 'domain';
}

export const DLP_LABELS: Record<string, string> = {
  private_key: 'Private keys (PEM)',
  aws_access_key: 'AWS access key IDs',
  aws_secret_key: 'AWS secret keys',
  github_token: 'GitHub tokens',
  gitlab_token: 'GitLab tokens',
  slack_token: 'Slack tokens',
  slack_webhook: 'Slack webhook URLs',
  google_api_key: 'Google API keys',
  stripe_key: 'Stripe keys',
  azure_storage_key: 'Azure storage keys',
  npm_token: 'npm tokens',
  pypi_token: 'PyPI tokens',
  credit_card: 'Card numbers (Luhn)',
  unix_shadow: '/etc/shadow content',
};

export const FILE_TYPE_LABELS: Record<string, { label: string; hint: string }> = {
  pe: { label: 'Windows executables', hint: 'PE: .exe, .dll, .sys' },
  elf: { label: 'Linux executables', hint: 'ELF binaries and shared objects' },
  macho: { label: 'macOS executables', hint: 'Mach-O binaries' },
  java_class: { label: 'Java class files', hint: '.class bytecode' },
  msi_ole: { label: 'MSI / OLE files', hint: 'Windows installers, legacy Office' },
  script: { label: 'Scripts', hint: 'Shell, PowerShell, batch, VBS …' },
  jar: { label: 'Java archives', hint: '.jar, .war' },
  apk: { label: 'Android packages', hint: '.apk' },
  zip: { label: 'ZIP archives', hint: '.zip' },
  archive: { label: 'Other archives', hint: 'tar, gzip, 7z, rar, xz …' },
  office_macro: { label: 'Office macros', hint: '.docm, .xlsm, .pptm' },
  iso: { label: 'Disk images', hint: '.iso, .img' },
};

export const RESTRICTIVE_LICENSE = /non[-\s]?commercial|\bnc\b|by-nc|personal use|research only/i;

export const MIB = 1024 * 1024;
export const KIB = 1024;

/** Value for <input type="datetime-local"> → ISO (undefined when empty / invalid). */
export function localToISO(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isFinite(d.getTime()) ? d.toISOString() : undefined;
}

/** Date → value for <input type="datetime-local"> (local time). */
export function toLocalInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** Free-text search haystack for an event. */
export function eventSearchText(e: SecurityEvent): string {
  return [e.type, e.severity, e.server_hostname, e.server_ip, e.host, e.url, e.detail, e.indicator, e.source, e.verdict, e.id].filter(Boolean).join(' ');
}
