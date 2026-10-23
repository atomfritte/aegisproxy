import React from 'react';
import { cn } from '../lib/cn';
import { initials } from '../lib/format';

function hue(name: string): number {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
  return h;
}

/** Initials avatar with a stable per-name color. */
export const Avatar: React.FC<{ name: string; size?: 'xs' | 'sm' | 'md' | 'lg'; className?: string; title?: string }> = ({
  name,
  size = 'sm',
  className,
  title,
}) => {
  const h = hue(name || '?');
  const dims = { xs: 'h-5 w-5 text-[9px]', sm: 'h-6 w-6 text-[10px]', md: 'h-8 w-8 text-[12px]', lg: 'h-10 w-10 text-[14px]' }[size];
  return (
    <span
      title={title}
      aria-hidden={!title}
      className={cn('inline-flex shrink-0 select-none items-center justify-center rounded-full font-semibold text-white', dims, className)}
      style={{ background: `linear-gradient(135deg, hsl(${h} 58% 48%), hsl(${(h + 30) % 360} 58% 40%))` }}
    >
      {initials(name)}
    </span>
  );
};

/** Avatar + name inline. */
export const UserTag: React.FC<{ name: string; sub?: React.ReactNode; className?: string }> = ({ name, sub, className }) => (
  <span className={cn('inline-flex min-w-0 items-center gap-2', className)}>
    <Avatar name={name} size="xs" />
    <span className="min-w-0 truncate text-fg">{name}</span>
    {sub && <span className="truncate text-fg-subtle">{sub}</span>}
  </span>
);
