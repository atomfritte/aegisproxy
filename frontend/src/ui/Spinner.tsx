import React from 'react';
import { cn } from '../lib/cn';

/** Inline loading indicator. */
export const Spinner: React.FC<{ className?: string; label?: string }> = ({ className, label = 'Loading' }) => (
  <svg
    className={cn('h-4 w-4 animate-spin', className)}
    viewBox="0 0 24 24"
    fill="none"
    role="status"
    aria-label={label}
  >
    <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.2" strokeWidth="3" />
    <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
  </svg>
);
