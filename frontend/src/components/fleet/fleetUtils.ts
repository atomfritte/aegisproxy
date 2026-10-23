// Fleet helpers: server health, static vs. label-selected (dynamic) group membership, client-side
// validation that mirrors control-plane/internal/store/fleet.go, CSV export and file downloads.

import { apiFetch, ApiError } from '../../api';
import { toTime } from '../../lib/format';
import type { Server, ServerGroup } from '../../types';

export const STALE_MS = 24 * 3600_000;

export type ServerHealth = 'quarantined' | 'stale' | 'never' | 'healthy';

/** Mirrors overviewStats: not seen within 24 h (never seen counts as stale). */
export function isStale(s: Pick<Server, 'last_seen_at'>, now = Date.now()): boolean {
  const t = toTime(s.last_seen_at);
  return t === null || now - t > STALE_MS;
}

export function serverHealth(s: Server, now = Date.now()): ServerHealth {
  if (s.quarantined) return 'quarantined';
  if (toTime(s.last_seen_at) === null) return 'never';
  return isStale(s, now) ? 'stale' : 'healthy';
}

export const HEALTH_META: Record<ServerHealth, { label: string; tone: 'danger' | 'warning' | 'neutral' | 'success'; description: string }> = {
  quarantined: { label: 'Quarantined', tone: 'danger', description: 'Every destination is denied (verdict QUARANTINED).' },
  stale: { label: 'Stale', tone: 'warning', description: 'No traffic for more than 24 hours.' },
  never: { label: 'Never seen', tone: 'neutral', description: 'Registered, but the proxy has not seen a request yet.' },
  healthy: { label: 'Healthy', tone: 'success', description: 'Seen by the proxy within the last 24 hours.' },
};

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

/** Same semantics as store.labelsMatch: all selector pairs present, `*` = any value. Empty selector never matches. */
export function labelsMatch(labels: Record<string, string> | null | undefined, selector: Record<string, string> | null | undefined): boolean {
  const sel = selector ?? {};
  const keys = Object.keys(sel);
  if (keys.length === 0) return false;
  const l = labels ?? {};
  return keys.every((k) => k in l && (sel[k] === '*' || l[k] === sel[k]));
}

export function effectiveGroups(s: Server): string[] {
  return s.effective_group_ids ?? s.group_ids ?? [];
}

export function staticGroups(s: Server): string[] {
  return s.group_ids ?? [];
}

/** Groups the server belongs to only because its labels match the group's selector. */
export function dynamicGroups(s: Server): string[] {
  const st = new Set(staticGroups(s));
  return effectiveGroups(s).filter((g) => !st.has(g));
}

export function hasSelector(g: Pick<ServerGroup, 'match_labels'>): boolean {
  return Object.keys(g.match_labels ?? {}).length > 0;
}

export interface GroupMembers {
  static: Server[];
  dynamic: Server[];
  all: Server[];
}

/** Registered members of a group, split into static and label-selected memberships. */
export function groupMembers(g: ServerGroup, servers: Server[]): GroupMembers {
  const stat: Server[] = [];
  const dyn: Server[] = [];
  for (const s of servers) {
    if (staticGroups(s).includes(g.id)) stat.push(s);
    else if (effectiveGroups(s).includes(g.id) || labelsMatch(s.labels, g.match_labels)) dyn.push(s);
  }
  return { static: stat, dynamic: dyn, all: [...stat, ...dyn] };
}

/** Groups whose selector would match these labels (live preview while editing a server). */
export function matchingGroups(labels: Record<string, string>, groups: ServerGroup[]): ServerGroup[] {
  return groups.filter((g) => labelsMatch(labels, g.match_labels));
}

export function formatLabel(k: string, v: string): string {
  return v === '*' ? `${k}=*` : `${k}=${v}`;
}

// ---------------------------------------------------------------------------
// Validation (mirrors fleet.go; the server has the final word)
// ---------------------------------------------------------------------------

const ID_RE = /^[a-z0-9][a-z0-9-]{1,63}$/;
const USER_RE = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const LABEL_KEY_RE = /^[a-z0-9]([a-z0-9._/-]{0,61}[a-z0-9])?$/;
const HEX_RE = /^#[0-9a-f]{6}$/i;

export function validateServerId(raw: string): string | null {
  const id = raw.trim().toLowerCase();
  if (!id) return null; // server generates one
  if (!ID_RE.test(id)) return '2–64 characters: lowercase letters, digits or "-", starting with a letter or digit.';
  if (id.startsWith('srv-auto-') || id.startsWith('srv-unregistered-')) return 'The prefixes srv-auto- and srv-unregistered- are reserved.';
  return null;
}

export function validateGroupId(raw: string): string | null {
  const id = raw.trim().toLowerCase();
  if (!id) return 'Enter an id, e.g. grp-payments.';
  if (!ID_RE.test(id)) return '2–64 characters: lowercase letters, digits or "-".';
  return null;
}

export function validateProxyUser(raw: string): string | null {
  const u = raw.trim().toLowerCase();
  if (!u) return null;
  return USER_RE.test(u) ? null : '2–64 characters: lowercase letters, digits, ".", "_" or "-".';
}

export function validateLabelKey(raw: string): string | null {
  const k = raw.trim();
  if (!k) return null;
  if (k !== k.toLowerCase()) return 'Use lowercase letters.';
  return LABEL_KEY_RE.test(k) ? null : 'Letters, digits, ".", "_", "/" or "-"; must start and end with a letter or digit.';
}

export function validateHexColor(raw: string): string | null {
  return HEX_RE.test(raw.trim()) ? null : 'Use a hex color like #2563EB.';
}

function parseIPv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((p) => p <= 255) ? parts : null;
}

function isIPv6(s: string): boolean {
  if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(':')) return false;
  const dbl = s.split('::');
  if (dbl.length > 2) return false;
  const groups = s.split(':').filter((x) => x !== '');
  return groups.length <= 8 && groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g) || parseIPv4(g) !== null);
}

export function validateIP(raw: string): string | null {
  const v = raw.trim();
  if (!v) return null;
  return parseIPv4(v) || isIPv6(v) ? null : `"${v}" is not a valid IPv4 or IPv6 address.`;
}

export function validateCIDR(raw: string): string | null {
  const v = raw.trim();
  if (!v) return null;
  const [addr, bits, ...rest] = v.split('/');
  if (rest.length > 0 || bits === undefined || !/^\d{1,3}$/.test(bits)) return `"${v}" is not a CIDR (e.g. 10.20.0.0/16).`;
  const n = Number(bits);
  if (parseIPv4(addr)) return n <= 32 ? null : 'IPv4 prefixes are at most /32.';
  if (isIPv6(addr)) return n <= 128 ? null : 'IPv6 prefixes are at most /128.';
  return `"${v}" is not a CIDR (e.g. 10.20.0.0/16).`;
}

/** Does a CIDR contain an IPv4 address? (IPv6 not evaluated client-side.) */
export function cidrContains(cidr: string, ip: string): boolean {
  const [addr, bitsS] = cidr.split('/');
  const a = parseIPv4(addr);
  const b = parseIPv4(ip);
  if (!a || !b) return false;
  const bits = Number(bitsS);
  const toInt = (p: number[]) => ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (toInt(a) & mask) === (toInt(b) & mask);
}

export const GROUP_COLORS = ['#2563EB', '#0284C7', '#0D9488', '#059669', '#65A30D', '#D97706', '#EA580C', '#DC2626', '#BE185D', '#7C3AED', '#4F46E5', '#64748B'];

export const ENVIRONMENTS = ['prod', 'staging', 'dev', 'test', 'infra', 'dmz'];

// ---------------------------------------------------------------------------
// CSV export / download
// ---------------------------------------------------------------------------

export const CSV_COLUMNS = ['id', 'hostname', 'ip', 'subnet_cidr', 'proxy_auth_user', 'group_ids', 'labels', 'os', 'department', 'owner_team', 'description'] as const;

function csvCell(v: string): string {
  // defuse spreadsheet formulas like the server does (csvSafe)
  const safe = v && '=+-@\t\r'.includes(v[0]) ? `'${v}` : v;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/** Same format as GET /api/servers/export?format=csv (static group_ids `;`-separated, labels `k=v;k=v`). */
export function serversToCsv(servers: Server[]): string {
  const lines = [CSV_COLUMNS.join(',')];
  for (const s of servers) {
    const labels = Object.keys(s.labels ?? {})
      .sort()
      .map((k) => `${k}=${s.labels![k]}`)
      .join(';');
    lines.push(
      [s.id, s.hostname, s.ip, s.subnet_cidr, s.proxy_auth_user, staticGroups(s).join(';'), labels, s.os, s.department, s.owner_team ?? '', s.description ?? '']
        .map((v) => csvCell(v ?? ''))
        .join(',')
    );
  }
  return lines.join('\n') + '\n';
}

export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function timestamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

/**
 * Downloads an authenticated API resource (session cookie, runtime API base URL) as a file.
 * Throws ApiError with the server's message on failure.
 */
export async function downloadApiFile(path: string, fallbackName: string): Promise<string> {
  const res = await apiFetch(path);
  if (!res.ok) {
    let msg = res.statusText || `HTTP ${res.status}`;
    try {
      const data = await res.json();
      if (data?.error) msg = data.error;
    } catch {
      // not JSON
    }
    throw new ApiError(msg, res.status);
  }
  const cd = res.headers.get('Content-Disposition') || '';
  const m = /filename="?([^";]+)"?/i.exec(cd);
  const name = m?.[1] || fallbackName;
  saveBlob(await res.blob(), name);
  return name;
}
