import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../lib/cn';

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Adds the standard inner padding (var(--card-p)). */
  padded?: boolean;
  /** Hover affordance for clickable cards. */
  interactive?: boolean;
  as?: 'div' | 'section' | 'article';
}

/** Surface container with hairline border. Compose with CardHeader / CardBody / CardFooter. */
export const Card: React.FC<CardProps> = ({ padded, interactive, as: Tag = 'div', className, children, ...rest }) => (
  <Tag
    className={cn(
      'min-w-0 rounded-lg border border-border bg-surface shadow-card',
      padded && 'p-[var(--card-p)]',
      interactive && 'transition-colors hover:border-border-strong hover:bg-surface-2',
      className
    )}
    {...rest}
  >
    {children}
  </Tag>
);

export const CardHeader: React.FC<{
  title: React.ReactNode;
  description?: React.ReactNode;
  icon?: LucideIcon;
  actions?: React.ReactNode;
  className?: string;
  /** Renders a bottom border (use when the body is a table/list). */
  divider?: boolean;
}> = ({ title, description, icon: Icon, actions, className, divider }) => (
  <div
    className={cn(
      'flex flex-wrap items-start justify-between gap-x-4 gap-y-2 px-[var(--card-p)] pt-[calc(var(--card-p)-4px)]',
      divider ? 'border-b border-border pb-3' : 'pb-1',
      className
    )}
  >
    <div className="flex min-w-0 items-start gap-2.5">
      {Icon && (
        <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-surface-3 text-fg-muted">
          <Icon className="h-4 w-4" aria-hidden />
        </span>
      )}
      <div className="min-w-0">
        <h2 className="text-[14px] font-semibold leading-6 text-fg">{title}</h2>
        {description && <p className="mt-0.5 text-[12.5px] leading-5 text-fg-muted">{description}</p>}
      </div>
    </div>
    {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
  </div>
);

export const CardBody: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ className, ...rest }) => (
  <div className={cn('p-[var(--card-p)]', className)} {...rest} />
);

export const CardFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ className, ...rest }) => (
  <div
    className={cn('flex flex-wrap items-center justify-end gap-2 rounded-b-lg border-t border-border bg-surface-2 px-[var(--card-p)] py-3', className)}
    {...rest}
  />
);

/** Label/value list for detail panels. */
export const DescriptionList: React.FC<{
  items: Array<{ label: React.ReactNode; value: React.ReactNode; hidden?: boolean; full?: boolean }>;
  columns?: 1 | 2 | 3;
  className?: string;
}> = ({ items, columns = 2, className }) => (
  <dl
    className={cn(
      'grid gap-x-6 gap-y-4',
      columns === 1 ? 'grid-cols-1' : columns === 2 ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
      className
    )}
  >
    {items
      .filter((i) => !i.hidden)
      .map((i, idx) => (
        <div key={idx} className={cn('min-w-0', i.full && 'sm:col-span-full')}>
          <dt className="text-[12px] font-medium text-fg-subtle">{i.label}</dt>
          <dd className="mt-1 min-w-0 break-words text-[13px] text-fg">{i.value}</dd>
        </div>
      ))}
  </dl>
);
