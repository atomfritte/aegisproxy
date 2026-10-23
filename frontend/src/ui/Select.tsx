import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Check, ChevronsUpDown, Search, X } from 'lucide-react';
import { cn } from '../lib/cn';
import { Popover } from './Popover';

export interface PickOption {
  value: string;
  label: string;
  /** Secondary text (id, description). Searched as well. */
  description?: string;
  /** Section header the option is listed under. */
  group?: string;
  /** Color swatch (e.g. group color). */
  color?: string;
  disabled?: boolean;
}

interface ListProps {
  options: PickOption[];
  isSelected: (v: string) => boolean;
  onPick: (v: string) => void;
  multiple: boolean;
  searchPlaceholder: string;
  emptyText: string;
  footer?: React.ReactNode;
  autoFocus?: boolean;
}

/** Searchable option list with keyboard navigation (shared by MultiSelect and Combobox). */
const OptionList: React.FC<ListProps> = ({ options, isSelected, onPick, multiple, searchPlaceholder, emptyText, footer }) => {
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return options;
    return options.filter((o) => `${o.label} ${o.description || ''} ${o.value}`.toLowerCase().includes(s));
  }, [options, q]);

  useEffect(() => {
    window.setTimeout(() => inputRef.current?.focus(), 0);
  }, []);
  useEffect(() => setActive(0), [q]);
  useEffect(() => {
    listRef.current?.querySelector(`[data-idx="${active}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(filtered.length - 1, a + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(0, a - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const o = filtered[active];
      if (o && !o.disabled) onPick(o.value);
    }
  };

  let lastGroup: string | undefined;
  return (
    <div className="w-full" onKeyDown={onKey}>
      {options.length > 6 && (
        <div className="sticky top-0 z-[1] -mx-1 -mt-1 mb-1 flex items-center gap-2 border-b border-border bg-surface px-3 py-2">
          <Search className="h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={searchPlaceholder}
            aria-label={searchPlaceholder}
            className="min-w-0 flex-1 bg-transparent text-[13px] outline-hidden placeholder:text-fg-subtle"
          />
        </div>
      )}
      {options.length <= 6 && <input ref={inputRef} className="sr-only" aria-hidden tabIndex={-1} readOnly />}
      <div ref={listRef} role="listbox" aria-multiselectable={multiple || undefined}>
        {filtered.length === 0 && <div className="px-3 py-6 text-center text-[13px] text-fg-subtle">{emptyText}</div>}
        {filtered.map((o, idx) => {
          const header = o.group && o.group !== lastGroup ? o.group : null;
          lastGroup = o.group;
          const sel = isSelected(o.value);
          return (
            <React.Fragment key={o.value}>
              {header && <div className="px-2.5 pb-1 pt-2 text-[11.5px] font-semibold text-fg-subtle">{header}</div>}
              <div
                role="option"
                aria-selected={sel}
                aria-disabled={o.disabled || undefined}
                data-idx={idx}
                onPointerEnter={() => setActive(idx)}
                onClick={() => !o.disabled && onPick(o.value)}
                className={cn(
                  'flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px]',
                  idx === active && 'bg-surface-3',
                  o.disabled && 'cursor-not-allowed opacity-50'
                )}
              >
                {multiple ? (
                  <span
                    className={cn(
                      'flex h-4 w-4 shrink-0 items-center justify-center rounded border',
                      sel ? 'border-primary bg-primary text-primary-fg' : 'border-border-strong bg-surface'
                    )}
                  >
                    {sel && <Check className="h-3 w-3" strokeWidth={3} aria-hidden />}
                  </span>
                ) : (
                  <Check className={cn('h-4 w-4 shrink-0 text-accent', !sel && 'invisible')} aria-hidden />
                )}
                {o.color && <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: o.color }} aria-hidden />}
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-fg">{o.label}</span>
                  {o.description && <span className="block truncate text-[12px] text-fg-subtle">{o.description}</span>}
                </span>
              </div>
            </React.Fragment>
          );
        })}
      </div>
      {footer}
    </div>
  );
};

export interface MultiSelectProps {
  value: string[];
  onChange: (v: string[]) => void;
  options: PickOption[];
  placeholder?: string;
  searchPlaceholder?: string;
  emptyText?: string;
  disabled?: boolean;
  /** Chips shown in the trigger before "+n". */
  maxChips?: number;
  className?: string;
  id?: string;
  'aria-describedby'?: string;
  'aria-invalid'?: boolean;
}

/** Multi-select with search, checkboxes and removable chips. */
export const MultiSelect: React.FC<MultiSelectProps> = ({
  value,
  onChange,
  options,
  placeholder = 'Select…',
  searchPlaceholder = 'Search…',
  emptyText = 'No matches',
  disabled,
  maxChips = 4,
  className,
  id,
  ...aria
}) => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLButtonElement>(null);
  const byValue = useMemo(() => new Map(options.map((o) => [o.value, o])), [options]);
  const toggle = (v: string) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
  const shown = value.slice(0, maxChips);

  return (
    <>
      <button
        ref={ref}
        id={id}
        type="button"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            setOpen(true);
          }
        }}
        className={cn('control flex flex-wrap items-center gap-1 py-1 pl-1.5 pr-8 text-left relative', className)}
        {...aria}
      >
        {value.length === 0 && <span className="px-1.5 text-fg-subtle">{placeholder}</span>}
        {shown.map((v) => {
          const o = byValue.get(v);
          return (
            <span key={v} className="inline-flex max-w-[220px] items-center gap-1 rounded bg-surface-3 py-0.5 pl-1.5 pr-0.5 text-[12px] text-fg">
              {o?.color && <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: o.color }} aria-hidden />}
              <span className="truncate">{o?.label || v}</span>
              {!disabled && (
                <span
                  role="button"
                  tabIndex={-1}
                  aria-label={`Remove ${o?.label || v}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    toggle(v);
                  }}
                  className="rounded p-0.5 text-fg-subtle hover:bg-surface hover:text-fg"
                >
                  <X className="h-3 w-3" />
                </span>
              )}
            </span>
          );
        })}
        {value.length > maxChips && <span className="px-1 text-[12px] text-fg-muted">+{value.length - maxChips} more</span>}
        <ChevronsUpDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" aria-hidden />
      </button>
      <Popover open={open} onClose={() => setOpen(false)} anchorRef={ref} matchWidth className="min-w-[260px]">
        <OptionList
          options={options}
          isSelected={(v) => value.includes(v)}
          onPick={toggle}
          multiple
          searchPlaceholder={searchPlaceholder}
          emptyText={emptyText}
          footer={
            value.length > 0 ? (
              <div className="sticky bottom-0 -mx-1 -mb-1 mt-1 flex items-center justify-between border-t border-border bg-surface px-3 py-1.5 text-[12px]">
                <span className="text-fg-subtle">{value.length} selected</span>
                <button type="button" className="font-medium text-accent hover:underline" onClick={() => onChange([])}>
                  Clear
                </button>
              </div>
            ) : null
          }
        />
      </Popover>
    </>
  );
};

export interface ComboboxProps {
  value: string;
  onChange: (v: string) => void;
  options: PickOption[];
  placeholder?: string;
  searchPlaceholder?: string;
  emptyText?: string;
  disabled?: boolean;
  /** Show an "×" to reset to ''. */
  clearable?: boolean;
  className?: string;
  id?: string;
  size?: 'sm' | 'md';
  'aria-label'?: string;
  'aria-describedby'?: string;
  'aria-invalid'?: boolean;
}

/** Single select with search (long lists: servers, users, policy sets). */
export const Combobox: React.FC<ComboboxProps> = ({
  value,
  onChange,
  options,
  placeholder = 'Select…',
  searchPlaceholder = 'Search…',
  emptyText = 'No matches',
  disabled,
  clearable,
  className,
  id,
  size = 'md',
  ...aria
}) => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLButtonElement>(null);
  const current = options.find((o) => o.value === value);
  return (
    <>
      <button
        ref={ref}
        id={id}
        type="button"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            setOpen(true);
          }
        }}
        className={cn('control relative flex items-center gap-2 pl-3 pr-8 text-left', size === 'sm' && 'min-h-[var(--control-h-sm)] text-[12.5px]', className)}
        {...aria}
      >
        {current?.color && <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: current.color }} aria-hidden />}
        <span className={cn('min-w-0 flex-1 truncate', !current && 'text-fg-subtle')}>{current?.label || placeholder}</span>
        {clearable && value && !disabled ? (
          <span
            role="button"
            tabIndex={-1}
            aria-label="Clear selection"
            onClick={(e) => {
              e.stopPropagation();
              onChange('');
            }}
            className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-fg-subtle hover:text-fg"
          >
            <X className="h-3.5 w-3.5" />
          </span>
        ) : (
          <ChevronsUpDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" aria-hidden />
        )}
      </button>
      <Popover open={open} onClose={() => setOpen(false)} anchorRef={ref} matchWidth className="min-w-[240px]">
        <OptionList
          options={options}
          isSelected={(v) => v === value}
          onPick={(v) => {
            onChange(v);
            setOpen(false);
            ref.current?.focus();
          }}
          multiple={false}
          searchPlaceholder={searchPlaceholder}
          emptyText={emptyText}
        />
      </Popover>
    </>
  );
};
