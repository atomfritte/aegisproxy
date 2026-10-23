// Formatting helpers (English, en-US number formatting).

const nf = new Intl.NumberFormat('en-US');
const compactNf = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });

export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  return nf.format(n);
}

/** 1,284 / 12.9K / 4.2M */
export function formatCompact(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  return Math.abs(n) < 10000 ? nf.format(n) : compactNf.format(n);
}

export function formatBytes(bytes: number | null | undefined): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function toTime(iso?: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isFinite(t) && t > 0 ? t : null;
}

/** Compact duration: 45s, 12m, 3h 20m, 2d 4h */
export function formatDuration(ms: number): string {
  const abs = Math.abs(ms);
  const s = Math.round(abs / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) {
    const rm = m % 60;
    return rm ? `${h}h ${rm}m` : `${h}h`;
  }
  const d = Math.floor(h / 24);
  const rh = h % 24;
  if (d < 30 && rh) return `${d}d ${rh}h`;
  return `${d}d`;
}

/** "3m ago", "in 2h", "just now", "—" */
export function formatRelative(iso?: string | null, now: number = Date.now()): string {
  const t = toTime(iso);
  if (t === null) return '—';
  const diff = now - t;
  if (Math.abs(diff) < 30_000) return 'just now';
  const d = formatDuration(diff).split(' ')[0];
  return diff >= 0 ? `${d} ago` : `in ${d}`;
}

export function formatDateTime(iso?: string | null): string {
  const t = toTime(iso);
  if (t === null) return '—';
  return new Date(t).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

export function formatDate(iso?: string | null): string {
  const t = toTime(iso);
  if (t === null) return '—';
  return new Date(t).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function pluralize(n: number, singular: string, plural = `${singular}s`): string {
  return `${formatNumber(n)} ${n === 1 ? singular : plural}`;
}

export function initials(name: string): string {
  const parts = name
    .replace(/\(.*?\)/g, '')
    .split(/[\s._@-]+/)
    .filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

/** Human readable labels for access durations. */
export const DURATION_LABELS: Record<string, string> = {
  '1h': '1 hour',
  '8h': '8 hours',
  '24h': '24 hours',
  '7d': '7 days',
  '30d': '30 days',
  '90d': '90 days',
  permanent: 'Permanent',
};

export function humanize(value: string): string {
  const s = value.replace(/_/g, ' ').toLowerCase();
  return s.charAt(0).toUpperCase() + s.slice(1);
}
