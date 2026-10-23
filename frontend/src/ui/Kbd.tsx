import React from 'react';
import { cn } from '../lib/cn';

/** Keyboard key hint: <Kbd>Ctrl</Kbd><Kbd>K</Kbd> */
export const Kbd: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <kbd
    className={cn(
      'inline-flex h-5 min-w-[20px] items-center justify-center rounded border border-border-strong bg-surface-2 px-1 font-sans text-[11px] font-medium text-fg-muted shadow-[inset_0_-1px_0_rgb(var(--c-border-strong))]',
      className
    )}
  >
    {children}
  </kbd>
);

/** "Ctrl" or "⌘" depending on the platform. */
export function modKey(): string {
  if (typeof navigator === 'undefined') return 'Ctrl';
  return /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent) ? '⌘' : 'Ctrl';
}
