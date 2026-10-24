// Helpers for editing policy sets: spec conversion and client-side rule validation that mirrors
// control-plane/internal/store/validate.go (the server re-validates and has the final word).

import type { PolicyRule, PolicySet, PolicySetSpec, PolicySetSpecInput, RuleInput } from '../../types';

export const HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT'] as const;

/** Spec currently being edited: the draft if there is one, otherwise the published content. */
export function workingSpec(set: PolicySet): PolicySetSpec {
  return set.draft ? set.draft.spec : set;
}

/**
 * Converts a spec for PUT /draft. Rules are passed through unchanged (keeping ids and the exact
 * null/[] shape of arrays) so that untouched rules are not reported as modified.
 */
export function toSpecInput(spec: PolicySetSpec): PolicySetSpecInput {
  return {
    name: spec.name,
    description: spec.description || '',
    owner_team: spec.owner_team || '',
    tags: [...(spec.tags ?? [])],
    priority: spec.priority || 0,
    enabled: spec.enabled,
    group_ids: [...(spec.group_ids ?? [])],
    server_ids: [...(spec.server_ids ?? [])],
    review_interval_days: spec.review_interval_days || 0,
    rules: (spec.rules ?? []).map((r) => ({ ...r }) as unknown as RuleInput),
  };
}

/** Copies rules for a new set (new ids are assigned by the server). */
export function cloneRulesForNewSet(rules: PolicyRule[] | null | undefined): RuleInput[] {
  const now = Date.now();
  return (rules ?? []).map((r) => ({
    id: '',
    name: r.name,
    description: r.description || '',
    action: r.action,
    host_pattern: r.host_pattern,
    path_pattern: r.path_pattern,
    methods: [...(r.methods ?? ['GET', 'HEAD'])],
    follow_redirects: r.follow_redirects,
    ...(r.redirect_hosts?.length ? { redirect_hosts: [...r.redirect_hosts] } : {}),
    companion_rules: [...(r.companion_rules ?? [])],
    enabled: r.enabled,
    ...(r.expires_at && new Date(r.expires_at).getTime() > now ? { expires_at: r.expires_at } : {}),
  }));
}

export function emptyRule(): RuleInput {
  return {
    id: '',
    name: '',
    description: '',
    action: 'ALLOW',
    host_pattern: '',
    path_pattern: '/**',
    methods: ['GET', 'HEAD'],
    follow_redirects: false,
    companion_rules: [],
    enabled: true,
  };
}

export function totalHits(rules: PolicyRule[] | null | undefined): number {
  return (rules ?? []).reduce((a, r) => a + (r.hit_count || 0), 0);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;

function isIP(h: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return h.split('.').every((p) => Number(p) <= 255);
  return h.includes(':') && /^[0-9a-f:.]+$/i.test(h);
}

/** Catch-all / TLD wildcard patterns that Team Leads may not use (auth.IsBroadHostPattern). */
export function isBroadHostPattern(pattern: string): boolean {
  const p = pattern.trim().toLowerCase();
  if (p === '*' || p === '') return true;
  if (p.startsWith('*.')) {
    const labels = p.slice(2).split('.');
    if (labels.length < 2) return true;
    if (labels.length === 2 && labels[0].length <= 3 && labels[1].length === 2) return true;
  }
  return false;
}

/** Returns an error message or null. */
export function validateHostPattern(raw: string): string | null {
  const h = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!h) return 'Enter a host, e.g. github.com or *.ubuntu.com.';
  if (h === '*') return null;
  if (/^[a-z]+:\/\//.test(h)) return 'Remove the scheme: enter only the host name (github.com).';
  if (/[/:@ ?#]/.test(h) && !isIP(h.replace(/^\[|\]$/g, ''))) return 'Enter a bare host name without port, path or credentials.';
  if (isIP(h)) return null;
  const check = h.startsWith('*.') ? h.slice(2) : h;
  if (check.includes('*')) return 'Wildcards are only allowed as a leading "*." label (*.example.com).';
  if (check === 'localhost') return null;
  const labels = check.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL_RE.test(l))) return `"${raw}" is not a valid host name.`;
  return null;
}

export function validatePathPattern(raw: string): string | null {
  const p = raw.trim();
  if (p === '' || p === '*') return null;
  if (!p.startsWith('/')) return 'The path must start with "/" (e.g. /acme/**).';
  if (/[\s\\]/.test(p)) return 'The path must not contain spaces or backslashes.';
  if (p.length > 1024) return 'The path is too long (max 1024 characters).';
  return null;
}

export function validateCompanion(raw: string): string | null {
  const c = raw.trim();
  const i = c.indexOf('/');
  const host = i >= 0 ? c.slice(0, i) : c;
  const path = i >= 0 ? c.slice(i) : '/**';
  if (host.trim() === '*') return 'Companion rules cannot use a catch-all host.';
  return validateHostPattern(host) || validatePathPattern(path);
}

/** A redirect target pattern (rule.redirect_hosts): a host or *.domain, never the catch-all. */
export function validateRedirectHost(raw: string): string | null {
  if (raw.trim() === '*') return 'Leave the list empty to allow any public host.';
  return validateHostPattern(raw);
}

export interface RuleErrors {
  name?: string;
  host_pattern?: string;
  path_pattern?: string;
  companion_rules?: string;
  redirect_hosts?: string;
  action?: string;
  expires_at?: string;
  methods?: string;
}

export function validateRule(r: RuleInput, opts: { teamLead: boolean; superAdmin: boolean }): RuleErrors {
  const e: RuleErrors = {};
  if (!r.name.trim()) e.name = 'Give the rule a name that explains its purpose.';
  else if (r.name.length > 200) e.name = 'At most 200 characters.';
  const hostErr = validateHostPattern(r.host_pattern);
  if (hostErr) e.host_pattern = hostErr;
  else if (r.host_pattern.trim() === '*' && r.action === 'ALLOW' && !opts.superAdmin) e.host_pattern = 'Only Super Admins may allow every host (*).';
  else if (opts.teamLead && isBroadHostPattern(r.host_pattern)) e.host_pattern = 'Team Leads cannot use catch-all or top-level wildcards such as *.com.';
  const pathErr = validatePathPattern(r.path_pattern);
  if (pathErr) e.path_pattern = pathErr;
  if (opts.teamLead && r.action === 'BLOCK') e.action = 'Only InfoSec Approvers and Super Admins manage BLOCK rules.';
  if ((r.methods ?? []).length === 0) e.methods = 'Select at least one method (or Any).';
  const comps = r.companion_rules ?? [];
  if (comps.length > 20) e.companion_rules = 'At most 20 companion rules.';
  for (const c of comps) {
    const ce = validateCompanion(c);
    if (ce) {
      e.companion_rules = `${c}: ${ce}`;
      break;
    }
    if (opts.teamLead && isBroadHostPattern(c.split('/')[0])) {
      e.companion_rules = `${c}: Team Leads cannot use catch-all companion hosts.`;
      break;
    }
  }
  const targets = r.redirect_hosts ?? [];
  if (targets.length > 20) e.redirect_hosts = 'At most 20 redirect hosts.';
  for (const h of targets) {
    const he = validateRedirectHost(h);
    if (he) {
      e.redirect_hosts = `${h}: ${he}`;
      break;
    }
  }
  if (r.expires_at && new Date(r.expires_at).getTime() < Date.now() - 60_000) e.expires_at = 'The expiry must be in the future.';
  return e;
}

export const PATTERN_EXAMPLES: Array<{ host: string; path: string; label: string; companions?: string[]; follow?: boolean }> = [
  { host: 'github.com', path: '/acme/**', label: 'One GitHub organisation', companions: ['codeload.github.com/acme/**', 'api.github.com/repos/acme/**'], follow: true },
  { host: '*.ubuntu.com', path: '/ubuntu/**', label: 'Ubuntu mirrors' },
  { host: 'registry-1.docker.io', path: '/v2/library/**', label: 'Docker official images', follow: true },
  { host: 'pypi.org', path: '/simple/**', label: 'Python package index', companions: ['files.pythonhosted.org/packages/**'] },
  { host: 'pastebin.com', path: '/**', label: 'Whole site (guardrail)' },
];

/** Human sentence describing what a rule does. */
export function describeRule(r: Pick<RuleInput, 'action' | 'methods' | 'host_pattern' | 'path_pattern'>): string {
  const methods = (r.methods ?? []).includes('*') ? 'any method' : (r.methods ?? ['GET', 'HEAD']).join(', ');
  const target = `${r.host_pattern || '…'}${r.path_pattern && r.path_pattern !== '/**' ? r.path_pattern : ''}`;
  return r.action === 'BLOCK' ? `Blocks every request to ${target}${r.path_pattern === '/**' ? ' (whole host)' : ''}.` : `Allows ${methods} requests to ${target}${r.path_pattern === '/**' || !r.path_pattern ? ' (whole host)' : ''}.`;
}
