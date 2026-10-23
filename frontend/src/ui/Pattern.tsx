import React from 'react';
import { cn } from '../lib/cn';

function highlight(text: string, keyPrefix: string, inverse = false): React.ReactNode[] {
  // wildcards: ** , * (incl. leading "*." of hosts)
  const parts = text.split(/(\*\*|\*)/g).filter((p) => p !== '');
  return parts.map((p, i) =>
    p === '*' || p === '**' ? (
      <span
        key={`${keyPrefix}${i}`}
        className={cn('rounded-[3px] px-[1px] font-semibold', inverse ? 'bg-white/10 text-[#A9B8FF]' : 'bg-accent-soft text-accent')}
      >
        {p}
      </span>
    ) : (
      <React.Fragment key={`${keyPrefix}${i}`}>{p}</React.Fragment>
    )
  );
}

/**
 * Destination pattern as one token: host (strong) + path (muted), wildcards highlighted.
 * `github.com/acme/**` — the console's way of showing what a rule opens.
 */
export const PatternText: React.FC<{ host: string; path?: string; className?: string; wrap?: boolean; /** light text for dark panels */ inverse?: boolean }> = ({
  host,
  path,
  className,
  wrap,
  inverse,
}) => {
  const p = path && path !== '/**' ? path : path === '/**' ? '/**' : '';
  return (
    <span
      className={cn('font-mono text-[12.5px] leading-5', wrap ? 'break-all' : 'block truncate', className)}
      title={`${host}${p}`}
    >
      <span className={cn('font-semibold', inverse ? 'text-white' : 'text-fg')}>{highlight(host || '—', 'h', inverse)}</span>
      {p && <span className={inverse ? 'text-white/60' : 'text-fg-muted'}>{highlight(p, 'p', inverse)}</span>}
    </span>
  );
};

/** Companion pattern ("host/path" string). */
export const CompanionText: React.FC<{ value: string; className?: string }> = ({ value, className }) => {
  const i = value.indexOf('/');
  return <PatternText host={i >= 0 ? value.slice(0, i) : value} path={i >= 0 ? value.slice(i) : ''} className={className} wrap />;
};

/** HTTP methods as compact mono tokens. */
export const MethodList: React.FC<{ methods?: string[] | null; className?: string }> = ({ methods, className }) => {
  const list = methods && methods.length > 0 ? methods : ['GET', 'HEAD'];
  if (list.includes('*')) {
    return <span className={cn('font-mono text-[11.5px] text-fg-muted', className)}>ANY</span>;
  }
  return (
    <span className={cn('inline-flex flex-wrap gap-1', className)}>
      {list.map((m) => (
        <span key={m} className="rounded border border-border px-1 font-mono text-[10.5px] font-medium leading-4 text-fg-muted">
          {m}
        </span>
      ))}
    </span>
  );
};
