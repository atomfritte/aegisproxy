import React, { forwardRef, useId } from 'react';
import type { LucideIcon } from 'lucide-react';
import { ChevronDown, Search, X } from 'lucide-react';
import { cn } from '../lib/cn';

// ---------------------------------------------------------------------------
// Field: label + control + hint/error. Pass the control as child; the id is wired automatically
// when the child accepts `id` (use the render prop for custom controls).
// ---------------------------------------------------------------------------

export interface FieldProps {
  label?: React.ReactNode;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  required?: boolean;
  optional?: boolean;
  /** Extra element after the label (e.g. HelpTip). */
  labelAside?: React.ReactNode;
  className?: string;
  children:
    | React.ReactElement<{ id?: string; 'aria-describedby'?: string; 'aria-invalid'?: boolean }>
    | ((ids: { id: string; describedBy?: string; invalid: boolean }) => React.ReactNode);
}

/** Label / hint / validation wrapper for any control. */
export const Field: React.FC<FieldProps> = ({ label, hint, error, required, optional, labelAside, className, children }) => {
  const id = useId();
  const hintId = `${id}-hint`;
  const describedBy = error || hint ? hintId : undefined;
  const invalid = !!error;
  const control =
    typeof children === 'function'
      ? children({ id, describedBy, invalid })
      : React.cloneElement(children, {
          id: children.props.id ?? id,
          'aria-describedby': describedBy,
          'aria-invalid': invalid || undefined,
        });
  return (
    <div className={cn('min-w-0', className)}>
      {label && (
        <div className="mb-1.5 flex items-center gap-1.5">
          <label htmlFor={typeof children === 'function' ? id : children.props.id ?? id} className="label">
            {label}
            {required && <span className="ml-0.5 text-danger" aria-hidden>*</span>}
            {optional && <span className="ml-1 font-normal text-fg-subtle">(optional)</span>}
          </label>
          {labelAside}
        </div>
      )}
      {control}
      {(error || hint) && (
        <p id={hintId} className={cn('mt-1.5 text-[12px] leading-5', error ? 'text-danger' : 'text-fg-subtle')}>
          {error || hint}
        </p>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  icon?: LucideIcon;
  /** Element at the right edge inside the control (unit, button). */
  trailing?: React.ReactNode;
  mono?: boolean;
  inputSize?: 'sm' | 'md';
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { icon: Icon, trailing, mono, inputSize = 'md', className, ...rest },
  ref
) {
  if (!Icon && !trailing) {
    return (
      <input
        ref={ref}
        className={cn('control px-3', inputSize === 'sm' && 'min-h-[var(--control-h-sm)] text-[12.5px]', mono && 'font-mono text-[12.5px]', className)}
        {...rest}
      />
    );
  }
  return (
    <div className={cn('control flex items-center gap-2 px-2.5', inputSize === 'sm' && 'min-h-[var(--control-h-sm)]', className)} aria-disabled={rest.disabled || undefined}>
      {Icon && <Icon className="h-4 w-4 shrink-0 text-fg-subtle" aria-hidden />}
      <input
        ref={ref}
        className={cn('h-full min-w-0 flex-1 bg-transparent py-1.5 text-[13px] outline-hidden placeholder:text-fg-subtle disabled:cursor-not-allowed', mono && 'font-mono text-[12.5px]')}
        {...rest}
      />
      {trailing}
    </div>
  );
});

/** Search box with clear button. */
export const SearchInput: React.FC<{
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
  autoFocus?: boolean;
  inputSize?: 'sm' | 'md';
  'aria-label'?: string;
}> = ({ value, onChange, placeholder = 'Search…', className, autoFocus, inputSize, ...rest }) => (
  <Input
    icon={Search}
    type="search"
    value={value}
    autoFocus={autoFocus}
    inputSize={inputSize}
    aria-label={rest['aria-label'] || placeholder}
    placeholder={placeholder}
    onChange={(e) => onChange(e.target.value)}
    onKeyDown={(e) => {
      if (e.key === 'Escape' && value) {
        e.stopPropagation();
        onChange('');
      }
    }}
    className={className}
    trailing={
      value ? (
        <button type="button" aria-label="Clear search" onClick={() => onChange('')} className="rounded p-0.5 text-fg-subtle hover:text-fg">
          <X className="h-3.5 w-3.5" />
        </button>
      ) : null
    }
  />
);

export const Textarea = forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean }>(
  function Textarea({ className, mono, rows = 3, ...rest }, ref) {
    return <textarea ref={ref} rows={rows} className={cn('control px-3 py-2 leading-5', mono && 'font-mono text-[12.5px]', className)} {...rest} />;
  }
);

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

/** Native select (best on mobile and for short lists). Use Combobox for searchable lists. */
export const Select = forwardRef<
  HTMLSelectElement,
  Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'children'> & { options: SelectOption[]; placeholder?: string; selectSize?: 'sm' | 'md' }
>(function Select({ options, placeholder, className, selectSize = 'md', ...rest }, ref) {
  return (
    <div className={cn('relative', className)}>
      <select
        ref={ref}
        className={cn('control appearance-none pl-3 pr-8', selectSize === 'sm' && 'min-h-[var(--control-h-sm)] text-[12.5px]')}
        {...rest}
      >
        {placeholder !== undefined && <option value="">{placeholder}</option>}
        {options.map((o) => (
          <option key={o.value} value={o.value} disabled={o.disabled}>
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-subtle" aria-hidden />
    </div>
  );
});

// ---------------------------------------------------------------------------
// Toggles
// ---------------------------------------------------------------------------

export const Checkbox = forwardRef<
  HTMLInputElement,
  Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> & { label?: React.ReactNode; description?: React.ReactNode; indeterminate?: boolean }
>(function Checkbox({ label, description, className, indeterminate, ...rest }, ref) {
  const inner = React.useRef<HTMLInputElement>(null);
  React.useImperativeHandle(ref, () => inner.current as HTMLInputElement);
  React.useEffect(() => {
    if (inner.current) inner.current.indeterminate = !!indeterminate;
  }, [indeterminate]);
  const box = (
    <input
      ref={inner}
      type="checkbox"
      className="mt-[1px] h-4 w-4 shrink-0 cursor-pointer rounded border-border-strong accent-[rgb(var(--c-primary))] disabled:cursor-not-allowed"
      {...rest}
    />
  );
  if (!label) return <span className={cn('inline-flex', className)}>{box}</span>;
  return (
    <label className={cn('flex cursor-pointer items-start gap-2.5 text-[13px]', rest.disabled && 'cursor-not-allowed opacity-60', className)}>
      {box}
      <span className="min-w-0 leading-5">
        <span className="font-medium text-fg">{label}</span>
        {description && <span className="block text-[12px] text-fg-muted">{description}</span>}
      </span>
    </label>
  );
});

/** On/off switch (role="switch"). */
export const Switch: React.FC<{
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: React.ReactNode;
  description?: React.ReactNode;
  disabled?: boolean;
  className?: string;
  id?: string;
}> = ({ checked, onChange, label, description, disabled, className, id }) => {
  const autoId = useId();
  const sid = id || autoId;
  const btn = (
    <button
      id={sid}
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-transparent transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring/60 disabled:cursor-not-allowed disabled:opacity-50',
        checked ? 'bg-primary' : 'bg-border-strong'
      )}
    >
      <span className={cn('inline-block h-4 w-4 rounded-full bg-white shadow transition-transform', checked ? 'translate-x-4' : 'translate-x-0.5')} />
    </button>
  );
  if (!label) return btn;
  return (
    <div className={cn('flex items-start justify-between gap-4', className)}>
      <label htmlFor={sid} className="min-w-0 cursor-pointer text-[13px] leading-5">
        <span className="font-medium text-fg">{label}</span>
        {description && <span className="block text-[12px] text-fg-muted">{description}</span>}
      </label>
      {btn}
    </div>
  );
};

export interface SegmentOption<T extends string> {
  value: T;
  label: React.ReactNode;
  icon?: LucideIcon;
  disabled?: boolean;
  title?: string;
}

/** Compact radio group rendered as a segmented control. */
export function SegmentedControl<T extends string>({
  value,
  onChange,
  options,
  size = 'md',
  className,
  'aria-label': ariaLabel,
}: {
  value: T;
  onChange: (v: T) => void;
  options: SegmentOption<T>[];
  size?: 'sm' | 'md';
  className?: string;
  'aria-label'?: string;
}) {
  return (
    <div role="radiogroup" aria-label={ariaLabel} className={cn('inline-flex rounded-md border border-border bg-surface-2 p-0.5', className)}>
      {options.map((o) => {
        const Icon = o.icon;
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={o.disabled}
            title={o.title}
            onClick={() => onChange(o.value)}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-[5px] px-2.5 font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50',
              size === 'sm' ? 'h-6 text-[12px]' : 'h-7 text-[12.5px]',
              active ? 'bg-surface text-fg shadow-xs ring-1 ring-border' : 'text-fg-muted hover:text-fg'
            )}
          >
            {Icon && <Icon className="h-3.5 w-3.5" aria-hidden />}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/** Large selectable cards (e.g. choosing the policy set kind). */
export function RadioCards<T extends string>({
  value,
  onChange,
  options,
  className,
  'aria-label': ariaLabel,
}: {
  value: T;
  onChange: (v: T) => void;
  options: Array<{ value: T; title: React.ReactNode; description?: React.ReactNode; icon?: LucideIcon; disabled?: boolean; disabledReason?: string }>;
  className?: string;
  'aria-label'?: string;
}) {
  return (
    <div role="radiogroup" aria-label={ariaLabel} className={cn('grid gap-2', className)}>
      {options.map((o) => {
        const Icon = o.icon;
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={o.disabled}
            onClick={() => onChange(o.value)}
            title={o.disabled ? o.disabledReason : undefined}
            className={cn(
              'flex items-start gap-3 rounded-lg border p-3 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50',
              active ? 'border-accent bg-accent-soft ring-1 ring-accent' : 'border-border bg-surface hover:border-border-strong hover:bg-surface-2'
            )}
          >
            {Icon && (
              <span className={cn('mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md', active ? 'bg-primary text-primary-fg' : 'bg-surface-3 text-fg-muted')}>
                <Icon className="h-4 w-4" aria-hidden />
              </span>
            )}
            <span className="min-w-0">
              <span className="block text-[13px] font-semibold text-fg">{o.title}</span>
              {o.description && <span className="mt-0.5 block text-[12px] leading-5 text-fg-muted">{o.disabled && o.disabledReason ? o.disabledReason : o.description}</span>}
            </span>
          </button>
        );
      })}
    </div>
  );
}
