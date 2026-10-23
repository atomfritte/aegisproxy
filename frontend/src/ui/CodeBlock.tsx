import React, { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { cn } from '../lib/cn';
import { copyText } from '../utils';
import { Tooltip } from './Tooltip';

/** Copies `text` to the clipboard and shows a check mark for 1.5 s. */
export const CopyButton: React.FC<{ text: string; label?: string; className?: string; size?: 'xs' | 'sm' }> = ({ text, label = 'Copy', className, size = 'sm' }) => {
  const [copied, setCopied] = useState(false);
  return (
    <Tooltip content={copied ? 'Copied' : label}>
      <button
        type="button"
        aria-label={label}
        onClick={async (e) => {
          e.stopPropagation();
          if (await copyText(text)) {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          }
        }}
        className={cn(
          'inline-flex items-center justify-center rounded-md text-fg-subtle transition-colors hover:bg-surface-3 hover:text-fg',
          size === 'xs' ? 'h-6 w-6' : 'h-7 w-7',
          className
        )}
      >
        {copied ? <Check className="h-3.5 w-3.5 text-success" aria-hidden /> : <Copy className="h-3.5 w-3.5" aria-hidden />}
      </button>
    </Tooltip>
  );
};

/** Monospace block with title bar and copy button. */
export const CodeBlock: React.FC<{
  code: string;
  title?: React.ReactNode;
  /** wrap long lines instead of horizontal scroll */
  wrap?: boolean;
  maxHeight?: number;
  className?: string;
}> = ({ code, title, wrap, maxHeight = 360, className }) => (
  <div className={cn('min-w-0 max-w-full overflow-hidden rounded-lg border border-border bg-surface-2', className)}>
    <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-1.5">
      <span className="truncate text-[12px] font-medium text-fg-muted">{title || 'Snippet'}</span>
      <CopyButton text={code} label="Copy to clipboard" size="xs" />
    </div>
    <pre
      className={cn('scroll-thin overflow-auto p-3 font-mono text-[12px] leading-5 text-fg', wrap ? 'whitespace-pre-wrap [overflow-wrap:anywhere]' : 'whitespace-pre')}
      style={{ maxHeight }}
    >
      {code}
    </pre>
  </div>
);
