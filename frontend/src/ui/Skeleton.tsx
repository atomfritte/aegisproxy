import React from 'react';
import { cn } from '../lib/cn';

/** Shimmering placeholder block. */
export const Skeleton: React.FC<{ className?: string; style?: React.CSSProperties }> = ({ className, style }) => (
  <div
    aria-hidden
    style={style}
    className={cn(
      'animate-shimmer rounded-md bg-surface-3 bg-[length:800px_100%]',
      'bg-[linear-gradient(90deg,rgb(var(--c-surface-3))_0%,rgb(var(--c-surface-2))_40%,rgb(var(--c-surface-3))_80%)]',
      className
    )}
  />
);

export const SkeletonText: React.FC<{ lines?: number; className?: string }> = ({ lines = 3, className }) => (
  <div className={cn('space-y-2', className)} aria-hidden>
    {Array.from({ length: lines }).map((_, i) => (
      <Skeleton key={i} className="h-3" style={{ width: `${i === lines - 1 ? 60 : 100 - i * 7}%` }} />
    ))}
  </div>
);

/** Placeholder for a whole page while /api/state loads. */
export const PageSkeleton: React.FC = () => (
  <div className="space-y-6" role="status" aria-label="Loading">
    <div className="space-y-2">
      <Skeleton className="h-3 w-40" />
      <Skeleton className="h-7 w-72" />
      <Skeleton className="h-3 w-96 max-w-full" />
    </div>
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {Array.from({ length: 4 }).map((_, i) => (
        <Skeleton key={i} className="h-24" />
      ))}
    </div>
    <Skeleton className="h-72" />
  </div>
);
