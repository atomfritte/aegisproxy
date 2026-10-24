import React from 'react';
import type { LucideIcon } from 'lucide-react';
import { AlertTriangle, CheckCircle2, Info, OctagonAlert, HelpCircle } from 'lucide-react';
import { cn } from '../lib/cn';
import type { Tone } from './Badge';
import { Tooltip } from './Tooltip';

const toneCls: Record<Tone, string> = {
  neutral: 'bg-surface-2 border-border text-fg',
  accent: 'bg-accent-soft border-accent-border text-fg',
  success: 'bg-success-soft border-success-border text-fg',
  warning: 'bg-warning-soft border-warning-border text-fg',
  danger: 'bg-danger-soft border-danger-border text-fg',
  info: 'bg-info-soft border-info-border text-fg',
  violet: 'bg-violet-soft border-violet-border text-fg',
};
const iconCls: Record<Tone, string> = {
  neutral: 'text-fg-muted',
  accent: 'text-accent',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
  info: 'text-info',
  violet: 'text-violet',
};
const defaultIcons: Partial<Record<Tone, LucideIcon>> = {
  success: CheckCircle2,
  warning: AlertTriangle,
  danger: OctagonAlert,
};

/** Inline message / concept explanation. */
export const Callout: React.FC<{
  tone?: Tone;
  title?: React.ReactNode;
  icon?: LucideIcon;
  action?: React.ReactNode;
  className?: string;
  children?: React.ReactNode;
}> = ({ tone = 'info', title, icon, action, className, children }) => {
  const Icon = icon || defaultIcons[tone] || Info;
  return (
    <div role={tone === 'danger' ? 'alert' : undefined} className={cn('flex gap-3 rounded-lg border px-4 py-3 text-[13px]', toneCls[tone], className)}>
      <Icon className={cn('mt-0.5 h-4 w-4 shrink-0', iconCls[tone])} aria-hidden />
      <div className="min-w-0 flex-1 leading-5">
        {title && <p className="font-semibold">{title}</p>}
        {children && <div className={cn('text-fg-muted', title ? 'mt-0.5' : undefined)}>{children}</div>}
      </div>
      {action && <div className="shrink-0 self-center">{action}</div>}
    </div>
  );
};

/** Small "?" icon with an explanation tooltip, for concepts next to labels. */
export const HelpTip: React.FC<{ content: React.ReactNode; className?: string; label?: string }> = ({ content, className, label = 'More information' }) => (
  <Tooltip content={<span className="block max-w-[280px] font-normal">{content}</span>}>
    <button type="button" aria-label={label} className={cn('inline-flex rounded-full text-fg-subtle hover:text-fg', className)}>
      <HelpCircle className="h-3.5 w-3.5" aria-hidden />
    </button>
  </Tooltip>
);
