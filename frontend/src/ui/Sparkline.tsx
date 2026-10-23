import React, { useId, useMemo, useState } from 'react';
import { cn } from '../lib/cn';

export interface SparklinePoint {
  label: string;
  value: number;
}

/**
 * Single-series area sparkline (SVG): 2px line, ~10% area wash, end dot with surface ring,
 * crosshair + tooltip on hover/focus. Values are reachable without hover via `ariaLabel`/table.
 */
export const Sparkline: React.FC<{
  data: SparklinePoint[];
  height?: number;
  className?: string;
  /** formats tooltip values */
  format?: (v: number) => string;
  ariaLabel: string;
  /** CSS color (default accent token) */
  color?: string;
}> = ({ data, height = 56, className, format = (v) => String(v), ariaLabel, color = 'rgb(var(--c-accent))' }) => {
  const gid = useId();
  const [hover, setHover] = useState<number | null>(null);
  const width = 300;
  const pad = 4;
  const { points, min, max } = useMemo(() => {
    const vals = data.map((d) => d.value);
    const mn = Math.min(...vals, 0);
    const mx = Math.max(...vals, 1);
    const pts = data.map((d, i) => {
      const x = data.length === 1 ? width / 2 : pad + (i * (width - pad * 2)) / (data.length - 1);
      const y = height - pad - ((d.value - mn) / (mx - mn || 1)) * (height - pad * 2);
      return { x, y };
    });
    return { points: pts, min: mn, max: mx };
  }, [data, height]);

  if (data.length === 0) return <div className={cn('text-[12px] text-fg-subtle', className)}>No data</div>;

  const line = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const area = `${line} L${points[points.length - 1].x.toFixed(1)},${height} L${points[0].x.toFixed(1)},${height} Z`;
  const last = points[points.length - 1];
  const h = hover !== null ? points[hover] : null;

  const onMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * width;
    let best = 0;
    let bestD = Infinity;
    points.forEach((p, i) => {
      const d = Math.abs(p.x - x);
      if (d < bestD) {
        bestD = d;
        best = i;
      }
    });
    setHover(best);
  };

  return (
    <div className={cn('relative', className)}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="block h-auto w-full overflow-visible"
        style={{ height }}
        role="img"
        aria-label={`${ariaLabel}. Range ${format(min)} to ${format(max)}, latest ${format(data[data.length - 1].value)}.`}
        tabIndex={0}
        onPointerMove={onMove}
        onPointerLeave={() => setHover(null)}
        onFocus={() => setHover(data.length - 1)}
        onBlur={() => setHover(null)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowLeft') setHover((v) => Math.max(0, (v ?? data.length - 1) - 1));
          if (e.key === 'ArrowRight') setHover((v) => Math.min(data.length - 1, (v ?? 0) + 1));
        }}
      >
        <defs>
          <linearGradient id={gid} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.16" />
            <stop offset="100%" stopColor={color} stopOpacity="0.02" />
          </linearGradient>
        </defs>
        <path d={area} fill={`url(#${gid})`} />
        <path d={line} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
        {h && <line x1={h.x} x2={h.x} y1={0} y2={height} stroke="rgb(var(--c-border-strong))" strokeWidth={1} vectorEffect="non-scaling-stroke" />}
      </svg>
      {/* dots are HTML so they stay round with preserveAspectRatio=none */}
      {[h ?? last].map((p, i) => (
        <span
          key={i}
          aria-hidden
          className="pointer-events-none absolute h-2.5 w-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-surface"
          style={{ left: `${(p.x / width) * 100}%`, top: p.y, background: color }}
        />
      ))}
      {hover !== null && h && (
        <div
          className="pointer-events-none absolute -top-9 z-10 -translate-x-1/2 whitespace-nowrap rounded-md border border-border bg-surface px-2 py-1 text-[12px] shadow-pop"
          style={{ left: `${Math.min(88, Math.max(12, (h.x / width) * 100))}%` }}
        >
          <span className="font-semibold text-fg tabular">{format(data[hover].value)}</span>
          <span className="ml-1.5 text-fg-subtle">{data[hover].label}</span>
        </div>
      )}
    </div>
  );
};
