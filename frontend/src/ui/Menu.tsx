import React, { useEffect, useRef, useState } from 'react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../lib/cn';
import { navigate } from '../lib/router';
import { Popover } from './Popover';

export interface MenuItem {
  id: string;
  label: React.ReactNode;
  icon?: LucideIcon;
  onSelect?: () => void;
  /** Navigate instead of onSelect. */
  to?: string;
  danger?: boolean;
  disabled?: boolean;
  /** Shown under the label (e.g. why it is disabled). */
  description?: React.ReactNode;
  /** Separator above this item. */
  separator?: boolean;
  hidden?: boolean;
}

/**
 * Dropdown menu. `trigger` receives props to spread on a button (ref, aria, onClick).
 * Keyboard: ArrowUp/Down, Home/End, Enter/Space, Esc.
 */
export const Menu: React.FC<{
  items: MenuItem[];
  trigger: (props: {
    ref: React.RefObject<HTMLButtonElement | null>;
    onClick: () => void;
    'aria-haspopup': 'menu';
    'aria-expanded': boolean;
    onKeyDown: (e: React.KeyboardEvent) => void;
  }) => React.ReactNode;
  align?: 'start' | 'end';
  header?: React.ReactNode;
  className?: string;
}> = ({ items, trigger, align = 'end', header, className }) => {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const anchor = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const visible = items.filter((i) => !i.hidden);
  const enabledIdx = visible.map((i, idx) => (i.disabled ? -1 : idx)).filter((i) => i >= 0);

  useEffect(() => {
    if (open) {
      setActive(enabledIdx[0] ?? 0);
      window.setTimeout(() => listRef.current?.focus(), 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const select = (it: MenuItem) => {
    if (it.disabled) return;
    setOpen(false);
    anchor.current?.focus();
    if (it.to) navigate(it.to);
    else it.onSelect?.();
  };

  const onListKey = (e: React.KeyboardEvent) => {
    const pos = enabledIdx.indexOf(active);
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive(enabledIdx[(pos + 1) % enabledIdx.length]);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive(enabledIdx[(pos - 1 + enabledIdx.length) % enabledIdx.length]);
    } else if (e.key === 'Home') {
      e.preventDefault();
      setActive(enabledIdx[0]);
    } else if (e.key === 'End') {
      e.preventDefault();
      setActive(enabledIdx[enabledIdx.length - 1]);
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      const it = visible[active];
      if (it) select(it);
    } else if (e.key === 'Tab') {
      setOpen(false);
    }
  };

  return (
    <>
      {trigger({
        ref: anchor,
        onClick: () => setOpen((o) => !o),
        'aria-haspopup': 'menu',
        'aria-expanded': open,
        onKeyDown: (e) => {
          if (e.key === 'ArrowDown' && !open) {
            e.preventDefault();
            setOpen(true);
          }
        },
      })}
      <Popover open={open} onClose={() => setOpen(false)} anchorRef={anchor} align={align} className={cn('min-w-[200px]', className)}>
        {header && <div className="border-b border-border px-2.5 pb-2 pt-1.5">{header}</div>}
        <div ref={listRef} role="menu" tabIndex={-1} onKeyDown={onListKey} className="outline-hidden">
          {visible.map((it, idx) => {
            const Icon = it.icon;
            return (
              <React.Fragment key={it.id}>
                {it.separator && <div role="separator" className="my-1 h-px bg-border" />}
                <div
                  role="menuitem"
                  aria-disabled={it.disabled || undefined}
                  onPointerEnter={() => !it.disabled && setActive(idx)}
                  onClick={() => select(it)}
                  className={cn(
                    'flex cursor-pointer select-none items-start gap-2.5 rounded-md px-2.5 py-2 text-[13px]',
                    it.disabled && 'cursor-not-allowed opacity-50',
                    idx === active && !it.disabled && (it.danger ? 'bg-danger-soft' : 'bg-surface-3'),
                    it.danger ? 'text-danger' : 'text-fg'
                  )}
                >
                  {Icon && <Icon className={cn('mt-0.5 h-4 w-4 shrink-0', it.danger ? 'text-danger' : 'text-fg-muted')} aria-hidden />}
                  <span className="min-w-0">
                    <span className="block">{it.label}</span>
                    {it.description && <span className="mt-0.5 block text-[12px] text-fg-subtle">{it.description}</span>}
                  </span>
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </Popover>
    </>
  );
};
