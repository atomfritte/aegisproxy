import React from 'react';
import { ChevronRight } from 'lucide-react';
import { cn } from '../lib/cn';
import { Link } from '../lib/router';

export interface Crumb {
  label: React.ReactNode;
  to?: string;
}

export interface PageHeaderProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  breadcrumbs?: Crumb[];
  /** Primary actions, right aligned (wrap below the title on phones). */
  actions?: React.ReactNode;
  /** Chips / metadata row under the title. */
  meta?: React.ReactNode;
  /** Element before the title (icon tile, avatar). */
  leading?: React.ReactNode;
  className?: string;
}

/** Page title block: breadcrumbs, title, description, meta chips and actions. */
export const PageHeader: React.FC<PageHeaderProps> = ({ title, description, breadcrumbs, actions, meta, leading, className }) => (
  <header className={cn('mb-6', className)}>
    {breadcrumbs && breadcrumbs.length > 0 && (
      <nav aria-label="Breadcrumb" className="mb-2">
        <ol className="flex flex-wrap items-center gap-1 text-[12.5px] text-fg-subtle">
          {breadcrumbs.map((c, i) => (
            <li key={i} className="flex min-w-0 items-center gap-1">
              {i > 0 && <ChevronRight className="h-3.5 w-3.5 shrink-0 opacity-60" aria-hidden />}
              {c.to ? (
                <Link to={c.to} className="truncate rounded hover:text-fg hover:underline">
                  {c.label}
                </Link>
              ) : (
                <span className="truncate text-fg-muted" aria-current={i === breadcrumbs.length - 1 ? 'page' : undefined}>
                  {c.label}
                </span>
              )}
            </li>
          ))}
        </ol>
      </nav>
    )}
    <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
      <div className="flex min-w-0 items-start gap-3">
        {leading}
        <div className="min-w-0">
          <h1 className="break-words text-[22px] font-semibold leading-8 tracking-[-0.01em] text-fg">{title}</h1>
          {description && <p className="mt-1 max-w-3xl text-[13.5px] leading-6 text-fg-muted">{description}</p>}
          {meta && <div className="mt-2.5 flex flex-wrap items-center gap-2">{meta}</div>}
        </div>
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  </header>
);
