// Block page templates: field metadata, defaults and client-side validation (mirrors
// control-plane/internal/store/blockpages.go — the server stays authoritative).

import type { BlockPageTemplate } from '../../../types';

export type Locale = 'en' | 'de';
export type Variant = 'request' | 'threat';

/** Text variables (`{name}`) with what they turn into (sample values match the preview). */
export const VARIABLES: Array<{ name: string; label: string; sample: string }> = [
  { name: 'company', label: 'Company name of this template', sample: 'Enterprise Corp' },
  { name: 'hostname', label: 'Hostname of the blocked server', sample: 'build-agent-07.corp.example' },
  { name: 'ip', label: 'IP address of the blocked server', sample: '10.20.4.17' },
  { name: 'url', label: 'Blocked URL', sample: 'https://downloads.example.org/tools/…' },
  { name: 'host', label: 'Destination host', sample: 'downloads.example.org' },
  { name: 'method', label: 'HTTP method', sample: 'GET' },
  { name: 'trace_id', label: 'Trace ID to quote in support tickets', sample: '4f9c2a7e1b3d' },
  { name: 'groups', label: 'Server groups of the blocked server', sample: 'ci-runners, linux-prod' },
  { name: 'verdict', label: 'Verdict', sample: 'BLOCKED' },
  { name: 'reason', label: 'Why the request was blocked', sample: 'No allow rule matches…' },
];

export const SCOPES: Array<{ value: string; label: string; description: string }> = [
  {
    value: 'prefix_with_objects',
    label: 'Path prefix and linked download objects',
    description: 'For example github.com/org/** plus the redirect targets it needs (release assets, CDN objects).',
  },
  { value: 'exact_path', label: 'Exact URL path only', description: 'Only the path that was blocked. The narrowest option.' },
  { value: 'domain', label: 'Entire domain', description: 'Every path on the blocked host.' },
  {
    value: 'learning_session_15m',
    label: '15-minute learning session',
    description: 'Records the server’s traffic for 15 minutes; reviewers turn it into rules.',
  },
];

export const DURATIONS: Array<{ value: string; label: string; description: string }> = [
  { value: '1h', label: '1 hour', description: 'Maintenance window or a one-off download.' },
  { value: '24h', label: '24 hours', description: 'A release or deployment window.' },
  { value: '7d', label: '7 days', description: 'Short projects and migrations.' },
  { value: 'permanent', label: 'Permanent', description: 'Adds a lasting rule to the group’s approvals set.' },
];

/** Built-in texts used when a field is empty (control-plane/internal/blockpage/blockpage.go). */
export const BUILTIN: Record<Locale, { title: string; message: string; threat_title: string; threat_message: string }> = {
  en: {
    title: 'Outbound access blocked',
    message:
      'This server tried to reach a destination that is not on its allow list. Outbound connections are denied by default.',
    threat_title: 'Destination blocked by threat protection',
    threat_message:
      'This request was stopped by {company} threat protection (malware, phishing, command-and-control or data-loss prevention). Self-service access is not available. If you believe this is a false positive, contact the security team and quote the trace ID.',
  },
  de: {
    title: 'Ausgehender Zugriff blockiert',
    message:
      'Dieser Server hat versucht, ein Ziel zu erreichen, das nicht freigegeben ist. Ausgehende Verbindungen sind standardmäßig gesperrt.',
    threat_title: 'Ziel durch Threat Protection blockiert',
    threat_message:
      'Diese Anfrage wurde durch die Threat Protection von {company} gestoppt (Malware, Phishing, Command-and-Control oder Data Loss Prevention). Eine Self-Service-Freigabe ist nicht möglich. Bei einem Fehlalarm wenden Sie sich bitte mit der Trace-ID an das Security-Team.',
  },
};

export const LIMITS = {
  name: 80,
  company_name: 120,
  title: 120,
  message: 2000,
  threat_message: 2000,
  footer_text: 1000,
  cli_header: 1000,
  cli_footer: 1000,
  link_label: 60,
  links: 6,
  logoBytes: 200 * 1024,
};

export const LOGO_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml'];

/** The editable part of a template (what is sent to the API). */
export type TemplateDraft = Omit<BlockPageTemplate, 'id' | 'updated_at' | 'updated_by'> & { id?: string };

export function newTemplate(company = ''): TemplateDraft {
  return {
    name: '',
    is_default: false,
    company_name: company,
    logo_data_url: '',
    primary_color: '#2563EB',
    accent_color: '#DC2626',
    theme: 'auto',
    title: '',
    message: '',
    threat_message: '',
    footer_text: '',
    support: { label: '', email: '', phone: '', url: '' },
    links: [],
    show_request_form: true,
    show_ca_section: true,
    show_technical_details: true,
    show_suggested_rule: true,
    allowed_scopes: SCOPES.map((s) => s.value),
    allowed_durations: DURATIONS.map((d) => d.value),
    default_locale: 'en',
    cli_header: '',
    cli_footer: '',
  };
}

/** Normalizes a template from the API into a draft (nulls → empty values, no server metadata). */
export function toDraft(t: BlockPageTemplate): TemplateDraft {
  return {
    id: t.id,
    name: t.name || '',
    is_default: !!t.is_default,
    company_name: t.company_name || '',
    logo_data_url: t.logo_data_url || '',
    primary_color: t.primary_color || '#2563EB',
    accent_color: t.accent_color || '#DC2626',
    theme: t.theme || 'auto',
    title: t.title || '',
    message: t.message || '',
    threat_message: t.threat_message || '',
    footer_text: t.footer_text || '',
    support: {
      label: t.support?.label || '',
      email: t.support?.email || '',
      phone: t.support?.phone || '',
      url: t.support?.url || '',
    },
    links: (t.links ?? []).map((l) => ({ label: l.label || '', url: l.url || '' })),
    show_request_form: !!t.show_request_form,
    show_ca_section: !!t.show_ca_section,
    show_technical_details: !!t.show_technical_details,
    show_suggested_rule: !!t.show_suggested_rule,
    allowed_scopes: [...(t.allowed_scopes ?? [])],
    allowed_durations: [...(t.allowed_durations ?? [])],
    default_locale: t.default_locale || 'en',
    cli_header: t.cli_header || '',
    cli_footer: t.cli_footer || '',
  };
}

/** Payload for POST/PUT (keeps the canonical order of scopes and durations). */
export function toPayload(d: TemplateDraft): Partial<BlockPageTemplate> {
  const { id, ...rest } = d;
  return {
    ...rest,
    name: d.name.trim(),
    links: (d.links ?? []).map((l) => ({ label: l.label.trim(), url: l.url.trim() })),
    allowed_scopes: SCOPES.map((s) => s.value).filter((v) => (d.allowed_scopes ?? []).includes(v)),
    allowed_durations: DURATIONS.map((x) => x.value).filter((v) => (d.allowed_durations ?? []).includes(v)),
  };
}

const HEX = /^#[0-9A-Fa-f]{6}$/;
const EMAIL = /^[^\s@<>()]+@[^\s@<>()]+\.[^\s@<>()]+$/;
const PHONE = /^[0-9+()./ -]{3,40}$/;

function isHttpUrl(v: string): boolean {
  try {
    const u = new URL(v);
    return (u.protocol === 'http:' || u.protocol === 'https:') && !!u.host && v.length <= 500;
  } catch {
    return false;
  }
}

export type DraftErrors = Partial<Record<string, string>>;

/** Client-side validation; keys are field paths used by the form ("support.email", "links.2.url"). */
export function validateDraft(d: TemplateDraft): DraftErrors {
  const e: DraftErrors = {};
  if (!d.name.trim()) e.name = 'Give the template a name.';
  else if (d.name.trim().length > LIMITS.name) e.name = `At most ${LIMITS.name} characters.`;
  if (d.company_name.length > LIMITS.company_name) e.company_name = `At most ${LIMITS.company_name} characters.`;
  if (!HEX.test(d.primary_color)) e.primary_color = 'Use a hex color like #2563EB.';
  if (!HEX.test(d.accent_color)) e.accent_color = 'Use a hex color like #DC2626.';
  for (const k of ['title', 'message', 'threat_message', 'footer_text', 'cli_header', 'cli_footer'] as const) {
    if ((d[k] || '').length > LIMITS[k]) e[k] = `At most ${LIMITS[k]} characters.`;
  }
  const s = d.support;
  if (s.email && !EMAIL.test(s.email.trim())) e['support.email'] = 'Enter a plain e-mail address.';
  if (s.phone && !PHONE.test(s.phone.trim())) e['support.phone'] = 'Digits, spaces and + ( ) . / - only.';
  if (s.url && !isHttpUrl(s.url.trim())) e['support.url'] = 'Enter an http(s) URL.';
  (d.links ?? []).forEach((l, i) => {
    if (!l.label.trim()) e[`links.${i}.label`] = 'Label required.';
    else if (l.label.trim().length > LIMITS.link_label) e[`links.${i}.label`] = `At most ${LIMITS.link_label} characters.`;
    if (!isHttpUrl(l.url.trim())) e[`links.${i}.url`] = 'Enter an http(s) URL.';
  });
  if (d.show_request_form) {
    if ((d.allowed_scopes ?? []).length === 0) e.allowed_scopes = 'The request form needs at least one scope.';
    if ((d.allowed_durations ?? []).length === 0) e.allowed_durations = 'The request form needs at least one duration.';
  }
  return e;
}

/** Stable JSON for dirty checks. */
export function draftKey(d: TemplateDraft): string {
  return JSON.stringify(toPayload(d));
}
