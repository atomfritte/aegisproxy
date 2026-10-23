import React, { forwardRef } from 'react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../lib/cn';
import { Link, LinkProps } from '../lib/router';
import { Spinner } from './Spinner';
import { Tooltip } from './Tooltip';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-ghost' | 'link';
export type ButtonSize = 'xs' | 'sm' | 'md' | 'lg';

const base =
  'relative inline-flex select-none items-center justify-center gap-1.5 whitespace-nowrap rounded-md font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring/60 focus-visible:ring-offset-1 focus-visible:ring-offset-surface disabled:cursor-not-allowed disabled:opacity-55';

const variants: Record<ButtonVariant, string> = {
  primary: 'bg-primary text-primary-fg shadow-xs hover:bg-primary-hover active:bg-primary-hover',
  secondary:
    'border border-border-strong bg-surface text-fg shadow-xs hover:bg-surface-3 hover:border-fg-subtle/50 active:bg-surface-3',
  ghost: 'text-fg-muted hover:bg-surface-3 hover:text-fg',
  danger: 'bg-danger-solid text-white shadow-xs hover:brightness-110',
  'danger-ghost': 'text-danger hover:bg-danger-soft',
  link: 'text-accent underline-offset-4 hover:underline px-0',
};

const sizes: Record<ButtonSize, string> = {
  xs: 'h-6 px-2 text-[12px]',
  sm: 'h-[var(--control-h-sm)] px-2.5 text-[12.5px]',
  md: 'h-[var(--control-h)] px-3.5 text-[13px]',
  lg: 'h-11 px-5 text-[14px]',
};

const iconSizes: Record<ButtonSize, string> = { xs: 'h-3.5 w-3.5', sm: 'h-4 w-4', md: 'h-4 w-4', lg: 'h-[18px] w-[18px]' };

export function buttonClass(variant: ButtonVariant = 'secondary', size: ButtonSize = 'md', extra?: string) {
  return cn(base, variants[variant], variant === 'link' ? 'h-auto text-[13px]' : sizes[size], extra);
}

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Shows a spinner and disables the button. */
  loading?: boolean;
  icon?: LucideIcon;
  iconRight?: LucideIcon;
  fullWidth?: boolean;
}

/** Button with variants (primary/secondary/ghost/danger/danger-ghost/link), sizes and loading state. */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', loading, icon: Icon, iconRight: IconRight, fullWidth, className, children, disabled, type = 'button', ...rest },
  ref
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={buttonClass(variant, size, cn(fullWidth && 'w-full', className))}
      {...rest}
    >
      {loading ? <Spinner className={iconSizes[size]} /> : Icon ? <Icon className={cn(iconSizes[size], 'shrink-0')} aria-hidden /> : null}
      {children}
      {IconRight && !loading && <IconRight className={cn(iconSizes[size], 'shrink-0')} aria-hidden />}
    </button>
  );
});

export interface ButtonLinkProps extends LinkProps {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: LucideIcon;
  iconRight?: LucideIcon;
}

/** Router link styled as a button. */
export const ButtonLink: React.FC<ButtonLinkProps> = ({ variant = 'secondary', size = 'md', icon: Icon, iconRight: IconRight, className, children, ...rest }) => (
  <Link className={buttonClass(variant, size, className)} {...rest}>
    {Icon && <Icon className={cn(iconSizes[size], 'shrink-0')} aria-hidden />}
    {children}
    {IconRight && <IconRight className={cn(iconSizes[size], 'shrink-0')} aria-hidden />}
  </Link>
);

export interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  icon: LucideIcon;
  /** Accessible name; also shown as tooltip. */
  label: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  /** Hide the tooltip (e.g. when a visible label is next to it). */
  noTooltip?: boolean;
}

const squareSizes: Record<ButtonSize, string> = {
  xs: 'h-6 w-6',
  sm: 'h-[var(--control-h-sm)] w-[var(--control-h-sm)]',
  md: 'h-[var(--control-h)] w-[var(--control-h)]',
  lg: 'h-11 w-11',
};

/** Square icon-only button with aria-label and tooltip. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { icon: Icon, label, variant = 'ghost', size = 'md', loading, noTooltip, className, disabled, type = 'button', ...rest },
  ref
) {
  const btn = (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      disabled={disabled || loading}
      className={cn(base, variants[variant], squareSizes[size], 'px-0', className)}
      {...rest}
    >
      {loading ? <Spinner className={iconSizes[size]} /> : <Icon className={iconSizes[size]} aria-hidden />}
    </button>
  );
  return noTooltip ? btn : <Tooltip content={label}>{btn}</Tooltip>;
});
