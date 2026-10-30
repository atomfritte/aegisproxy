// Shared constants and helpers for the package firewall console (/packages…).
import type { LucideIcon } from 'lucide-react';
import { Boxes, FlaskConical, Hexagon, SquareTerminal } from 'lucide-react';
import { toTime } from '../../lib/format';
import type { Tone } from '../../ui';
import type {
  PackageAssessment,
  PackageEcosystem,
  PackageMode,
  PackageNodeState,
  PackageRisk,
  PackageVerificationStatus,
} from '../../types';

// --- Ecosystems -------------------------------------------------------------

export const ECOSYSTEMS: PackageEcosystem[] = ['npm', 'pypi', 'nuget', 'psgallery'];

export interface EcosystemMeta {
  label: string;
  short: string;
  icon: LucideIcon;
  /** Client tooling, shown as a hint. */
  clients: string;
}

export const ECOSYSTEM_META: Record<string, EcosystemMeta> = {
  npm: { label: 'npm', short: 'npm', icon: Hexagon, clients: 'npm, pnpm, yarn' },
  pypi: { label: 'PyPI', short: 'PyPI', icon: FlaskConical, clients: 'pip, uv, poetry' },
  nuget: { label: 'NuGet', short: 'NuGet', icon: Boxes, clients: 'dotnet, nuget.exe, Visual Studio' },
  psgallery: { label: 'PowerShell Gallery', short: 'PS Gallery', icon: SquareTerminal, clients: 'PowerShellGet, PSResourceGet' },
};

export function ecosystemLabel(id: string): string {
  return ECOSYSTEM_META[id]?.label ?? id;
}

// --- Enforcement mode -------------------------------------------------------

export const MODE_META: Record<PackageMode, { label: string; tone: Tone; hint: string }> = {
  off: { label: 'Off', tone: 'neutral', hint: 'Registry traffic follows the ordinary egress rules only.' },
  monitor: { label: 'Monitor', tone: 'info', hint: 'Egress rules decide; package requests are recorded and discovered.' },
  enforce: { label: 'Enforce', tone: 'success', hint: 'Metadata is filtered to approved versions; only approved artifacts are delivered.' },
};

export function modeMeta(mode: string): { label: string; tone: Tone; hint: string } {
  return MODE_META[(mode as PackageMode)] ?? MODE_META.off;
}

// --- Risk -------------------------------------------------------------------

export const RISK_ORDER: PackageRisk[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown', 'none'];

export const RISK_META: Record<PackageRisk, { label: string; tone: Tone; solid: boolean }> = {
  none: { label: 'No risk', tone: 'success', solid: false },
  info: { label: 'Info', tone: 'info', solid: false },
  low: { label: 'Low', tone: 'success', solid: false },
  medium: { label: 'Medium', tone: 'warning', solid: false },
  high: { label: 'High', tone: 'danger', solid: false },
  critical: { label: 'Critical', tone: 'danger', solid: true },
  unknown: { label: 'Unknown', tone: 'neutral', solid: false },
};

/** Mirrors models.RiskRank (unknown ranks like medium). */
export function riskRank(r?: string | null): number {
  switch (r) {
    case 'none':
    case '':
    case null:
    case undefined:
      return 0;
    case 'info':
      return 1;
    case 'low':
      return 2;
    case 'medium':
    case 'unknown':
      return 3;
    case 'high':
      return 4;
    case 'critical':
      return 5;
  }
  return 3;
}

export function riskMeta(r?: string | null): { label: string; tone: Tone; solid: boolean } {
  return RISK_META[(r as PackageRisk)] ?? RISK_META.unknown;
}

export function riskTone(r?: string | null): Tone {
  return riskMeta(r).tone;
}

/** True for high / critical (and malware) — the nodes that must jump out. */
export function isHotRisk(r?: string | null): boolean {
  return riskRank(r) >= 4;
}

// --- Node states ------------------------------------------------------------

export const NODE_STATE_META: Record<PackageNodeState, { label: string; tone: Tone; order: number }> = {
  blocked: { label: 'Blocked', tone: 'danger', order: 0 },
  new: { label: 'New', tone: 'info', order: 1 },
  update: { label: 'Update', tone: 'violet', order: 2 },
  approved: { label: 'Approved', tone: 'success', order: 3 },
};

export function nodeStateMeta(s: string): { label: string; tone: Tone; order: number } {
  return NODE_STATE_META[(s as PackageNodeState)] ?? NODE_STATE_META.new;
}

// --- Request status ---------------------------------------------------------

export const REQUEST_STATUS_META: Record<string, { label: string; tone: Tone }> = {
  resolving: { label: 'Resolving', tone: 'info' },
  analyzing: { label: 'Analyzing', tone: 'info' },
  ready: { label: 'Ready to review', tone: 'warning' },
  approved: { label: 'Approved', tone: 'success' },
  rejected: { label: 'Rejected', tone: 'danger' },
  failed: { label: 'Failed', tone: 'danger' },
};

export function requestStatusMeta(s: string): { label: string; tone: Tone } {
  return REQUEST_STATUS_META[s] ?? { label: s || 'Unknown', tone: 'neutral' };
}

/** A request is still working (resolving / analyzing) — poll it. */
export function requestInFlight(s: string): boolean {
  return s === 'resolving' || s === 'analyzing';
}

// --- Verification -----------------------------------------------------------

export const VERIFICATION_META: Record<PackageVerificationStatus, { label: string; tone: Tone }> = {
  verified: { label: 'Verified', tone: 'success' },
  unsigned: { label: 'Unsigned', tone: 'warning' },
  failed: { label: 'Verification failed', tone: 'danger' },
  unchecked: { label: 'Not checked', tone: 'neutral' },
};

// --- Cooldown / Karenz ------------------------------------------------------

/** Age of a published-at timestamp in hours (null when unknown). */
export function ageHours(iso?: string | null, now: number = Date.now()): number | null {
  const t = toTime(iso);
  if (t === null) return null;
  return Math.max(0, (now - t) / 3_600_000);
}

/** Human cooldown / age hint, e.g. "36 hours", "3 days", "2 weeks". */
export function humanHours(h?: number | null): string {
  if (!h || h <= 0) return 'none';
  const hours = Math.round(h);
  if (hours < 48) return `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
  const days = Math.round(hours / 24);
  if (days < 14 || days % 7 !== 0) return `${days} ${days === 1 ? 'day' : 'days'}`;
  const weeks = days / 7;
  return `${weeks} ${weeks === 1 ? 'week' : 'weeks'}`;
}

// --- Assessment summaries ---------------------------------------------------

/** Advisory counts by severity (withdrawn advisories excluded), most severe first. */
export function advisoryCounts(a?: PackageAssessment | null): Array<{ severity: PackageRisk; count: number }> {
  const counts = new Map<PackageRisk, number>();
  for (const adv of a?.advisories ?? []) {
    if (adv.withdrawn) continue;
    const sev = (adv.malware ? 'critical' : adv.severity || 'unknown') as PackageRisk;
    counts.set(sev, (counts.get(sev) ?? 0) + 1);
  }
  return RISK_ORDER.filter((s) => counts.has(s)).map((s) => ({ severity: s, count: counts.get(s)! }));
}

/** Whether any non-withdrawn advisory is a malware verdict. */
export function hasMalware(a?: PackageAssessment | null): boolean {
  return (a?.advisories ?? []).some((adv) => adv.malware && !adv.withdrawn);
}

export function activeAdvisoryTotal(a?: PackageAssessment | null): number {
  return (a?.advisories ?? []).filter((adv) => !adv.withdrawn).length;
}

/** Total system calls recorded by the sandbox summary. */
export function syscallTotal(counts?: Record<string, number> | null): number {
  let n = 0;
  for (const v of Object.values(counts ?? {})) n += v || 0;
  return n;
}

/** name@version display for a node / approval. */
export function nameVersion(name: string, version?: string, display?: string): string {
  const n = display || name;
  return version ? `${n}@${version}` : n;
}
