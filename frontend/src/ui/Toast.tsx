import React, { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Info, OctagonAlert, X } from 'lucide-react';
import { cn } from '../lib/cn';
import { errorMessage } from '../api/http';
import { Portal } from './Portal';

export type ToastTone = 'success' | 'error' | 'info' | 'warning';

interface ToastItem {
  id: number;
  tone: ToastTone;
  title: string;
  description?: React.ReactNode;
  action?: { label: string; onClick: () => void };
}

export interface ToastOptions {
  description?: React.ReactNode;
  action?: { label: string; onClick: () => void };
  /** ms; 0 = sticky. Defaults: 5 s, errors 9 s. */
  duration?: number;
}

export interface ToastApi {
  success: (title: string, opts?: ToastOptions) => void;
  info: (title: string, opts?: ToastOptions) => void;
  warning: (title: string, opts?: ToastOptions) => void;
  /** Accepts an Error/ApiError (shows the server message) or a string. */
  error: (err: unknown, opts?: ToastOptions & { title?: string }) => void;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const icons = { success: CheckCircle2, error: OctagonAlert, info: Info, warning: AlertTriangle };
const iconCls = { success: 'text-success', error: 'text-danger', info: 'text-info', warning: 'text-warning' };
const barCls = { success: 'bg-success-solid', error: 'bg-danger-solid', info: 'bg-info-solid', warning: 'bg-warning-solid' };

/** Provides useToast(). Toasts stack bottom-right (bottom on phones), aria-live polite/assertive. */
export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  const timers = useRef(new Map<number, number>());

  const dismiss = useCallback((id: number) => {
    setItems((list) => list.filter((t) => t.id !== id));
    const t = timers.current.get(id);
    if (t) window.clearTimeout(t);
    timers.current.delete(id);
  }, []);

  const push = useCallback(
    (tone: ToastTone, title: string, opts: ToastOptions = {}) => {
      const id = ++seq.current;
      setItems((list) => [...list.slice(-4), { id, tone, title, description: opts.description, action: opts.action }]);
      const duration = opts.duration ?? (tone === 'error' ? 9000 : 5000);
      if (duration > 0) timers.current.set(id, window.setTimeout(() => dismiss(id), duration));
    },
    [dismiss]
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (t, o) => push('success', t, o),
      info: (t, o) => push('info', t, o),
      warning: (t, o) => push('warning', t, o),
      error: (err, o = {}) => {
        const msg = errorMessage(err, 'Something went wrong');
        if (o.title) push('error', o.title, { ...o, description: o.description ?? msg });
        else push('error', msg, o);
      },
      dismiss,
    }),
    [push, dismiss]
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <Portal>
        <div className="pointer-events-none fixed inset-x-0 bottom-16 z-[120] flex flex-col items-center gap-2 p-3 sm:inset-x-auto sm:bottom-16 sm:right-0 sm:items-end sm:px-5">
          {items.map((t) => {
            const Icon = icons[t.tone];
            return (
              <div
                key={t.id}
                role={t.tone === 'error' ? 'alert' : 'status'}
                aria-live={t.tone === 'error' ? 'assertive' : 'polite'}
                className="pointer-events-auto relative flex w-full max-w-[400px] gap-3 overflow-hidden rounded-lg border border-border bg-surface py-3 pl-4 pr-3 shadow-pop animate-toast-in"
              >
                <span className={cn('absolute inset-y-0 left-0 w-[3px]', barCls[t.tone])} aria-hidden />
                <Icon className={cn('mt-0.5 h-4 w-4 shrink-0', iconCls[t.tone])} aria-hidden />
                <div className="min-w-0 flex-1 text-[13px] leading-5">
                  <p className="break-words font-medium text-fg">{t.title}</p>
                  {t.description && <div className="mt-0.5 break-words text-fg-muted">{t.description}</div>}
                  {t.action && (
                    <button
                      type="button"
                      className="mt-1.5 font-medium text-accent hover:underline"
                      onClick={() => {
                        t.action!.onClick();
                        dismiss(t.id);
                      }}
                    >
                      {t.action.label}
                    </button>
                  )}
                </div>
                <button type="button" aria-label="Dismiss notification" onClick={() => dismiss(t.id)} className="h-6 w-6 shrink-0 rounded text-fg-subtle hover:bg-surface-3 hover:text-fg">
                  <X className="mx-auto h-3.5 w-3.5" />
                </button>
              </div>
            );
          })}
        </div>
      </Portal>
    </ToastContext.Provider>
  );
};

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
}
