import React from 'react';
import { ExternalLink, Globe, Laptop, Lock, ShieldAlert, ShieldX, Smartphone, SquareTerminal } from 'lucide-react';
import { API_IS_CROSS_ORIGIN } from '../../../config';
import { cn } from '../../../lib/cn';
import { Callout, SegmentedControl, Spinner, Tooltip, buttonClass, useToast } from '../../../ui';
import type { Locale, Variant } from './model';
import { openSavedPreview, savedPreviewUrl } from './openPreview';
import { ScaledFrame } from './ScaledFrame';
import type { PreviewState } from './usePreview';

export interface PreviewView {
  mode: 'browser' | 'terminal';
  variant: Variant;
  locale: Locale;
  device: 'desktop' | 'phone';
}

const SAMPLE_URL = 'https://downloads.example.org/tools/v2.4/installer.tar.gz';

/** Live preview: toolbar (browser/terminal, policy/threat, en/de, desktop/phone) + sandboxed render. */
export const PreviewPane: React.FC<{
  preview: PreviewState;
  view: PreviewView;
  onViewChange: (v: PreviewView) => void;
  /** Saved template id: enables "Open full page" (renders the saved version). */
  savedId?: string;
  dirty?: boolean;
  className?: string;
}> = ({ preview, view, onViewChange, savedId, dirty, className }) => {
  const toast = useToast();
  const set = (patch: Partial<PreviewView>) => onViewChange({ ...view, ...patch });
  const opts = { locale: view.locale, variant: view.variant, format: view.mode === 'terminal' ? ('cli' as const) : ('html' as const) };
  const fullUrl = savedId ? savedPreviewUrl(savedId, opts) : '';

  // Same origin: the plain link carries the session cookie. Cross-origin API: fetch → blob.
  const open = (e: React.MouseEvent) => {
    if (!API_IS_CROSS_ORIGIN || !savedId) return;
    e.preventDefault();
    openSavedPreview(savedId, opts).catch((err) => toast.error(err, { title: 'Could not open the preview' }));
  };

  return (
    <div className={cn('flex min-h-0 flex-col overflow-hidden rounded-lg border border-border bg-surface shadow-card', className)}>
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-surface-2 px-3 py-2">
        <SegmentedControl
          size="sm"
          aria-label="Preview type"
          value={view.mode}
          onChange={(mode) => set({ mode })}
          options={[
            { value: 'browser', label: 'Browser', icon: Globe },
            { value: 'terminal', label: 'Terminal', icon: SquareTerminal },
          ]}
        />
        <SegmentedControl
          size="sm"
          aria-label="Block reason"
          value={view.variant}
          onChange={(variant) => set({ variant })}
          options={[
            { value: 'request', label: 'Policy block', icon: ShieldX, title: 'Default deny: no rule allows the destination (request form available)' },
            { value: 'threat', label: 'Threat block', icon: ShieldAlert, title: 'Threat protection or quarantine (no self-service)' },
          ]}
        />
        <SegmentedControl
          size="sm"
          aria-label="Language"
          value={view.locale}
          onChange={(locale) => set({ locale })}
          options={[
            { value: 'en', label: 'English' },
            { value: 'de', label: 'Deutsch' },
          ]}
        />
        {view.mode === 'browser' && (
          <SegmentedControl
            size="sm"
            aria-label="Viewport"
            value={view.device}
            onChange={(device) => set({ device })}
            options={[
              { value: 'desktop', label: 'Desktop', icon: Laptop },
              { value: 'phone', label: 'Phone', icon: Smartphone },
            ]}
          />
        )}
        <div className="ml-auto flex items-center gap-2">
          {preview.loading && (
            <span className="inline-flex items-center gap-1.5 text-[12px] text-fg-subtle" aria-live="polite">
              <Spinner className="h-3.5 w-3.5" label="Rendering preview" /> Rendering…
            </span>
          )}
          {savedId && (
            <Tooltip content={dirty ? 'Opens the last saved version in a new tab (scripts disabled)' : 'Opens this template in a new tab (scripts disabled)'}>
              <a href={fullUrl} target="_blank" rel="noopener noreferrer" onClick={open} className={buttonClass('ghost', 'xs')}>
                <ExternalLink className="h-3.5 w-3.5" aria-hidden />
                {dirty ? 'Open saved version' : 'Open full page'}
              </a>
            </Tooltip>
          )}
        </div>
      </div>

      {preview.error && (
        <Callout tone="danger" title="Preview not updated" className="m-3 mb-0">
          {preview.error}
        </Callout>
      )}

      <div className={cn('relative min-h-0 flex-1', preview.error && 'opacity-60')}>
        {!preview.html && !preview.error ? (
          <div className="flex h-full min-h-[320px] items-center justify-center gap-2 text-[13px] text-fg-subtle">
            <Spinner /> Rendering preview…
          </div>
        ) : view.mode === 'terminal' ? (
          <TerminalPreview cli={preview.cli} />
        ) : view.device === 'phone' ? (
          <div className="h-full bg-surface-3">
            <ScaledFrame html={preview.html} title="Block page preview (phone)" logicalWidth={390} device />
          </div>
        ) : (
          <div className="flex h-full flex-col bg-surface-3 p-3">
            <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border border-border-strong bg-surface shadow-pop">
              <div className="flex items-center gap-3 border-b border-border bg-surface-2 px-3 py-1.5">
                <span className="flex gap-1.5" aria-hidden>
                  <span className="h-2.5 w-2.5 rounded-full bg-danger-solid/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-warning-solid/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-success-solid/70" />
                </span>
                <span className="flex min-w-0 flex-1 items-center gap-1.5 rounded-md border border-border bg-surface px-2 py-0.5 font-mono text-[11.5px] text-fg-muted">
                  <Lock className="h-3 w-3 shrink-0 text-fg-subtle" aria-hidden />
                  <span className="truncate">{SAMPLE_URL}</span>
                </span>
              </div>
              <div className="min-h-0 flex-1">
                <ScaledFrame html={preview.html} title="Block page preview (desktop)" logicalWidth={1024} />
              </div>
            </div>
          </div>
        )}
      </div>
      <p className="border-t border-border px-3 py-1.5 text-[11.5px] text-fg-subtle">
        Sample data: build-agent-07.corp.example (10.20.4.17) requesting {SAMPLE_URL.replace('https://', '')}. Links and the form are inactive in the preview.
      </p>
    </div>
  );
};

/** CLI text as printed to curl / apt / pip, in a terminal frame (always dark). */
export const TerminalPreview: React.FC<{ cli: string; compact?: boolean }> = ({ cli, compact }) => (
  <div className={cn('flex h-full flex-col bg-surface-3', !compact && 'p-3')}>
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border border-sidebar-border bg-sidebar shadow-pop">
      <div className="flex items-center gap-3 border-b border-sidebar-border px-3 py-1.5">
        <span className="flex gap-1.5" aria-hidden>
          <span className="h-2.5 w-2.5 rounded-full bg-sidebar-active" />
          <span className="h-2.5 w-2.5 rounded-full bg-sidebar-active" />
          <span className="h-2.5 w-2.5 rounded-full bg-sidebar-active" />
        </span>
        <span className="truncate font-mono text-[11.5px] text-sidebar-muted">root@build-agent-07: ~</span>
      </div>
      <pre className="scroll-thin min-h-0 flex-1 overflow-auto whitespace-pre p-4 font-mono text-[11.5px] leading-[1.55] text-sidebar-fg">
        <span className="text-sidebar-muted">$ </span>
        <span className="text-white">curl -sS {SAMPLE_URL}</span>
        {'\n'}
        {cli}
      </pre>
    </div>
  </div>
);
