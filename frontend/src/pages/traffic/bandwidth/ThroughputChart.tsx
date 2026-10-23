import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { cn } from '../../../lib/cn';
import { formatNumber } from '../../../lib/format';
import type { BandwidthSample } from '../../../types';
import { formatMbps } from './bandwidthFormat';

/**
 * Chart-local categorical palette (validated with the dataviz validator against the console
 * surfaces: light #ffffff, dark #141820 — all pairs pass CVD and normal-vision floors). Values are
 * RGB triplets so they switch with the `.dark` class like the design tokens.
 */
export const VIZ_VARS =
  '[--viz-1:42_120_214] [--viz-2:235_104_52] [--viz-3:27_175_122] dark:[--viz-1:57_135_229] dark:[--viz-2:217_89_38] dark:[--viz-3:25_158_112]';

export const SERIES = [
  { key: 'mbps_direct_allow', label: 'Direct allow', color: 'rgb(var(--viz-1))', description: 'Requests that matched an allow rule' },
  { key: 'mbps_cdn_objects', label: 'Redirect objects', color: 'rgb(var(--viz-2))', description: 'Release assets and CDN blobs reached through follow-redirect lineage' },
  { key: 'mbps_tls_bypass', label: 'TLS passthrough', color: 'rgb(var(--viz-3))', description: 'Connections tunnelled without decryption' },
] as const;

type SeriesKey = (typeof SERIES)[number]['key'];

function niceStep(raw: number): number {
  const exp = Math.pow(10, Math.floor(Math.log10(raw)));
  const f = raw / exp;
  const nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
  return nf * exp;
}

function useWidth(ref: React.RefObject<HTMLElement>): number {
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setW(el.clientWidth);
    const ro = new ResizeObserver(() => setW(el.clientWidth));
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return w;
}

const PLOT_H = 260;
const AXIS_H = 26;
const LEFT = 48;
const TOP = 22;
const GAP = 2;

/** Stacked columns of throughput per traffic class with a hover/focus tooltip. */
export const ThroughputChart: React.FC<{ data: BandwidthSample[]; className?: string }> = ({ data, className }) => {
  const wrapRef = useRef<HTMLDivElement>(null);
  const width = useWidth(wrapRef);
  const [active, setActive] = useState<number | null>(null);

  const totals = data.map((d) => SERIES.reduce((s, x) => s + (d[x.key as SeriesKey] || 0), 0));
  const maxV = Math.max(1, ...totals);
  const { step, top } = useMemo(() => {
    const st = niceStep(maxV / 4);
    return { step: st, top: Math.ceil(maxV / st) * st };
  }, [maxV]);
  const ticks: number[] = [];
  for (let v = 0; v <= top + 1e-9; v += step) ticks.push(v);

  const plotW = Math.max(0, width - LEFT - 8);
  const n = data.length;
  const band = n ? plotW / n : 0;
  const barW = Math.max(4, Math.min(24, band * 0.62));
  const y = (v: number) => TOP + PLOT_H - (v / top) * PLOT_H;
  const labelEvery = Math.max(1, Math.ceil(44 / Math.max(1, band)));

  useEffect(() => {
    if (active !== null && active >= n) setActive(null);
  }, [n, active]);

  if (n === 0) {
    return <div className="flex h-40 items-center justify-center text-[13px] text-fg-subtle">No throughput samples yet.</div>;
  }

  const last = n - 1;
  const tipIdx = active;
  const tipX = tipIdx !== null ? LEFT + band * tipIdx + band / 2 : 0;

  return (
    <div ref={wrapRef} className={cn('relative select-none', VIZ_VARS, className)}>
      {width > 0 && (
        <svg
          width={width}
          height={TOP + PLOT_H + AXIS_H}
          role="img"
          aria-label={`Throughput by traffic class, ${data[0].time_label} to ${data[last].time_label}. Latest ${formatMbps(totals[last])}, peak ${formatMbps(maxV)}. Use the arrow keys to read each sample.`}
          tabIndex={0}
          className="block outline-hidden focus-visible:rounded-md focus-visible:ring-2 focus-visible:ring-ring/60"
          onPointerLeave={() => setActive(null)}
          onFocus={() => setActive((a) => (a === null ? last : a))}
          onBlur={() => setActive(null)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowLeft') {
              e.preventDefault();
              setActive((a) => Math.max(0, (a ?? last) - 1));
            } else if (e.key === 'ArrowRight') {
              e.preventDefault();
              setActive((a) => Math.min(last, (a ?? 0) + 1));
            } else if (e.key === 'Home') setActive(0);
            else if (e.key === 'End') setActive(last);
            else if (e.key === 'Escape') setActive(null);
          }}
        >
          {/* grid + y ticks */}
          {ticks.map((t) => (
            <g key={t}>
              <line x1={LEFT} x2={width - 8} y1={y(t)} y2={y(t)} stroke={t === 0 ? 'rgb(var(--c-border-strong))' : 'rgb(var(--c-border))'} strokeWidth={1} shapeRendering="crispEdges" />
              <text x={LEFT - 8} y={y(t)} dy="0.32em" textAnchor="end" className="fill-fg-subtle text-[11px] tabular">
                {t >= 1000 ? `${formatNumber(t / 1000)}K` : formatNumber(t)}
              </text>
            </g>
          ))}
          <text x={LEFT - 8} y={10} textAnchor="end" className="fill-fg-subtle text-[11px]">
            Mbps
          </text>

          {/* columns */}
          {data.map((d, i) => {
            const cx = LEFT + band * i + band / 2;
            const x0 = cx - barW / 2;
            let acc = 0;
            const segs = SERIES.map((s) => {
              const v = d[s.key as SeriesKey] || 0;
              const seg = { s, v, from: acc, to: acc + v };
              acc += v;
              return seg;
            }).filter((g) => g.v > 0);
            const dim = active !== null && active !== i;
            return (
              <g key={i} opacity={dim ? 0.45 : 1} style={{ transition: 'opacity .12s' }}>
                {segs.map((g, k) => {
                  const isTop = k === segs.length - 1;
                  const yTop = y(g.to) + (isTop ? 0 : GAP / 2);
                  const yBot = y(g.from) - (k === 0 ? 0 : GAP / 2);
                  const h = Math.max(0, yBot - yTop);
                  if (h <= 0) return null;
                  if (!isTop) return <rect key={g.s.key} x={x0} y={yTop} width={barW} height={h} fill={g.s.color} />;
                  const r = Math.min(4, h, barW / 2);
                  const path = `M${x0},${yBot} L${x0},${yTop + r} Q${x0},${yTop} ${x0 + r},${yTop} L${x0 + barW - r},${yTop} Q${x0 + barW},${yTop} ${x0 + barW},${yTop + r} L${x0 + barW},${yBot} Z`;
                  return <path key={g.s.key} d={path} fill={g.s.color} />;
                })}
                {/* x labels */}
                {(i % labelEvery === 0 || i === last) && (i === last || last - i >= labelEvery) && (
                  <text x={cx} y={TOP + PLOT_H + 17} textAnchor="middle" className="fill-fg-subtle text-[11px] tabular">
                    {d.time_label}
                  </text>
                )}
                {/* hit area: the whole band */}
                <rect x={LEFT + band * i} y={TOP} width={band} height={PLOT_H} fill="transparent" onPointerMove={() => setActive(i)} onPointerDown={() => setActive(i)} />
              </g>
            );
          })}

          {/* direct label: latest total */}
          {active === null && (
            <text x={Math.min(LEFT + band * last + band / 2, width - 30)} y={y(totals[last]) - 7} textAnchor="middle" className="fill-fg text-[11.5px] font-semibold tabular">
              {formatMbps(totals[last])}
            </text>
          )}
          {tipIdx !== null && <line x1={tipX} x2={tipX} y1={TOP} y2={TOP + PLOT_H} stroke="rgb(var(--c-border-strong))" strokeWidth={1} pointerEvents="none" />}
        </svg>
      )}

      {tipIdx !== null && width > 0 && (
        <div
          role="status"
          className="pointer-events-none absolute top-0 z-10 min-w-[190px] rounded-md border border-border bg-surface px-3 py-2 text-[12px] shadow-pop"
          style={{
            left: Math.min(Math.max(tipX + (tipX > width / 2 ? -14 : 14), 4), width - 4),
            transform: tipX > width / 2 ? 'translateX(-100%)' : undefined,
          }}
        >
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-[13px] font-semibold text-fg tabular">{formatMbps(totals[tipIdx])}</span>
            <span className="text-fg-subtle tabular">{data[tipIdx].time_label}</span>
          </div>
          <ul className="mt-1.5 space-y-1">
            {[...SERIES].reverse().map((s) => (
              <li key={s.key} className="flex items-center gap-2">
                <span className="h-0.5 w-3 shrink-0 rounded-full" style={{ background: s.color }} aria-hidden />
                <span className="flex-1 text-fg-muted">{s.label}</span>
                <span className="font-medium text-fg tabular">{formatMbps(data[tipIdx][s.key as SeriesKey] || 0)}</span>
              </li>
            ))}
          </ul>
          <div className="mt-1.5 border-t border-border pt-1.5 text-fg-subtle">
            <span className="font-medium text-fg tabular">{formatNumber(data[tipIdx].requests_per_sec)}</span> requests/s
          </div>
        </div>
      )}
    </div>
  );
};

/** Legend: one swatch per series (rects mirror the column marks). */
export const ThroughputLegend: React.FC<{ className?: string }> = ({ className }) => (
  <ul className={cn('flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[12.5px] text-fg-muted', VIZ_VARS, className)}>
    {SERIES.map((s) => (
      <li key={s.key} className="inline-flex items-center gap-1.5" title={s.description}>
        <span className="h-2.5 w-2.5 shrink-0 rounded-[3px]" style={{ background: s.color }} aria-hidden />
        {s.label}
      </li>
    ))}
  </ul>
);
