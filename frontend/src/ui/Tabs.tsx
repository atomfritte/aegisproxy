import React, { useEffect, useRef } from 'react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../lib/cn';
import { useSearchParams } from '../lib/router';
import { CountBadge, Tone } from './Badge';

export interface TabItem<T extends string = string> {
  id: T;
  label: React.ReactNode;
  icon?: LucideIcon;
  count?: number | null;
  countTone?: Tone;
  disabled?: boolean;
  hidden?: boolean;
}

export interface TabsProps<T extends string = string> {
  tabs: TabItem<T>[];
  value: T;
  onChange: (id: T) => void;
  className?: string;
  'aria-label'?: string;
  /** id prefix for aria-controls (panels use `${idPrefix}-panel-${id}`) */
  idPrefix?: string;
}

/** Underlined tab bar (role=tablist, arrow-key navigation, horizontally scrollable on phones). */
export function Tabs<T extends string = string>({ tabs, value, onChange, className, idPrefix = 'tabs', ...rest }: TabsProps<T>) {
  const ref = useRef<HTMLDivElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const visible = tabs.filter((t) => !t.hidden);
  // Phones: keep the active tab inside the horizontally scrolling bar (without scrolling the page).
  useEffect(() => {
    const sc = scroller.current;
    const tab = ref.current?.querySelector<HTMLElement>(`[data-tab="${value}"]`);
    if (!sc || !tab || sc.scrollWidth <= sc.clientWidth) return;
    const left = tab.offsetLeft;
    if (left < sc.scrollLeft + 8) sc.scrollLeft = Math.max(0, left - 24);
    else if (left + tab.offsetWidth > sc.scrollLeft + sc.clientWidth - 8) sc.scrollLeft = left + tab.offsetWidth - sc.clientWidth + 24;
  }, [value]);
  const onKey = (e: React.KeyboardEvent) => {
    const enabled = visible.filter((t) => !t.disabled);
    const i = enabled.findIndex((t) => t.id === value);
    let next: TabItem<T> | undefined;
    if (e.key === 'ArrowRight') next = enabled[(i + 1) % enabled.length];
    if (e.key === 'ArrowLeft') next = enabled[(i - 1 + enabled.length) % enabled.length];
    if (e.key === 'Home') next = enabled[0];
    if (e.key === 'End') next = enabled[enabled.length - 1];
    if (next) {
      e.preventDefault();
      onChange(next.id);
      window.setTimeout(() => ref.current?.querySelector<HTMLElement>(`[data-tab="${next!.id}"]`)?.focus(), 0);
    }
  };
  return (
    <div ref={scroller} className={cn('scroll-thin relative -mx-1 min-w-0 max-w-[calc(100%+0.5rem)] overflow-x-auto overscroll-x-contain px-1 pointer-coarse:[scrollbar-width:none] pointer-coarse:[&::-webkit-scrollbar]:hidden', className)}>
      <div ref={ref} role="tablist" aria-label={rest['aria-label']} onKeyDown={onKey} className="flex min-w-max gap-1 border-b border-border">
        {visible.map((t) => {
          const Icon = t.icon;
          const active = t.id === value;
          return (
            <button
              key={t.id}
              type="button"
              role="tab"
              data-tab={t.id}
              id={`${idPrefix}-tab-${t.id}`}
              aria-selected={active}
              aria-controls={`${idPrefix}-panel-${t.id}`}
              tabIndex={active ? 0 : -1}
              disabled={t.disabled}
              onClick={() => onChange(t.id)}
              className={cn(
                'relative -mb-px inline-flex h-10 items-center gap-2 whitespace-nowrap border-b-2 px-3 text-[13px] font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring/60 disabled:cursor-not-allowed disabled:opacity-50',
                active ? 'border-accent text-fg' : 'border-transparent text-fg-muted hover:border-border-strong hover:text-fg'
              )}
            >
              {Icon && <Icon className={cn('h-4 w-4', active ? 'text-accent' : 'text-fg-subtle')} aria-hidden />}
              {t.label}
              {t.count !== undefined && t.count !== null && <CountBadge count={t.count} tone={t.countTone} />}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export const TabPanel: React.FC<{ id: string; idPrefix?: string; className?: string; children: React.ReactNode }> = ({ id, idPrefix = 'tabs', className, children }) => (
  <div role="tabpanel" id={`${idPrefix}-panel-${id}`} aria-labelledby={`${idPrefix}-tab-${id}`} className={className}>
    {children}
  </div>
);

/** Tab state stored in the query string (?tab=…), so tabs are deep-linkable. */
export function useUrlTab<T extends string>(allowed: readonly T[], fallback: T, param = 'tab'): [T, (t: T) => void] {
  const [params, set] = useSearchParams();
  const raw = params.get(param) as T | null;
  const value = raw && allowed.includes(raw) ? raw : fallback;
  return [value, (t: T) => set({ [param]: t === fallback ? null : t })];
}
