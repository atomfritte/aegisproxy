import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { Inbox } from 'lucide-react';
import { cn } from '../lib/cn';

/** Friendly empty / no-results state with an optional call to action. */
export const EmptyState: React.FC<{
  icon?: LucideIcon;
  title: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
  size?: 'sm' | 'md';
  className?: string;
}> = ({ icon: Icon = Inbox, title, description, action, size = 'md', className }) => (
  <div className={cn('flex flex-col items-center justify-center text-center', size === 'md' ? 'px-6 py-14' : 'px-4 py-8', className)}>
    <span
      className={cn(
        'mb-3 flex items-center justify-center rounded-full border border-border bg-surface-2 text-fg-subtle',
        size === 'md' ? 'h-12 w-12' : 'h-9 w-9'
      )}
    >
      <Icon className={size === 'md' ? 'h-5 w-5' : 'h-4 w-4'} aria-hidden />
    </span>
    <p className={cn('font-semibold text-fg', size === 'md' ? 'text-[14px]' : 'text-[13px]')}>{title}</p>
    {description && <p className="mt-1 max-w-md text-[13px] leading-5 text-fg-muted">{description}</p>}
    {action && <div className="mt-4 flex flex-wrap justify-center gap-2">{action}</div>}
  </div>
);
