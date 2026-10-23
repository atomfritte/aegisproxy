/** 840 Mbps / 2.08 Gbps */
export function formatMbps(mbps: number | null | undefined): string {
  const v = mbps ?? 0;
  if (!Number.isFinite(v)) return '—';
  if (v >= 1000) return `${(v / 1000).toFixed(2)} Gbps`;
  if (v > 0 && v < 10) return `${v.toFixed(1)} Mbps`;
  return `${Math.round(v)} Mbps`;
}

export function percent(part: number, whole: number): number {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}
