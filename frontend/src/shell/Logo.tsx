import React, { useId } from 'react';
import { cn } from '../lib/cn';

/** AegisProxy mark: a shield with a single egress lane leaving through a gate. */
export const LogoMark: React.FC<{ className?: string }> = ({ className }) => {
  // unique gradient id: several marks can be on the page, some inside display:none containers
  const gid = `aegis-mark-${useId().replace(/:/g, '')}`;
  return (
  <svg viewBox="0 0 32 32" className={cn('h-8 w-8', className)} aria-hidden>
    <defs>
      <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stopColor="#5B7BFF" />
        <stop offset="1" stopColor="#2B4ACB" />
      </linearGradient>
    </defs>
    <rect width="32" height="32" rx="8" fill={`url(#${gid})`} />
    <path d="M16 6.5 8.5 9.4v6.1c0 4.7 3.1 8.4 7.5 10 4.4-1.6 7.5-5.3 7.5-10V9.4L16 6.5Z" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinejoin="round" />
    <path d="M12.5 19.5 19 13" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" />
    <path d="M14.6 12.6H19.4V17.4" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
  );
};

export const Wordmark: React.FC<{ className?: string; sub?: string }> = ({ className, sub = 'Enterprise' }) => (
  <span className={cn('flex min-w-0 flex-col leading-tight', className)}>
    <span className="truncate text-[14px] font-semibold tracking-[-0.01em]">AegisProxy</span>
    <span className="truncate text-[11.5px] opacity-70">{sub}</span>
  </span>
);
