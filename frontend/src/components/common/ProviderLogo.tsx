import React from 'react';
import { KeyRound } from 'lucide-react';
import { cn } from '../../lib/cn';

/** Identity provider mark for sign-in buttons: the Microsoft logo for Entra ID, a key otherwise. */
export const ProviderLogo: React.FC<{ provider?: string; className?: string }> = ({ provider, className }) =>
  provider === 'entra' || provider === '' || provider === undefined ? (
    <svg viewBox="0 0 21 21" className={cn('h-4 w-4 shrink-0', className)} aria-hidden focusable="false">
      <rect x="1" y="1" width="9" height="9" fill="#F25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7FBA00" />
      <rect x="1" y="11" width="9" height="9" fill="#00A4EF" />
      <rect x="11" y="11" width="9" height="9" fill="#FFB900" />
    </svg>
  ) : (
    <KeyRound className={cn('h-4 w-4 shrink-0', className)} aria-hidden />
  );
