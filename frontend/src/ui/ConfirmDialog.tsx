import React, { createContext, useCallback, useContext, useRef, useState } from 'react';
import { AlertTriangle, ShieldCheck } from 'lucide-react';
import { cn } from '../lib/cn';
import { Button } from './Button';
import { Field, Input, Textarea } from './Form';
import { Modal } from './Overlay';
import { useToast } from './Toast';

export interface ConfirmOptions {
  title: React.ReactNode;
  description?: React.ReactNode;
  /** Extra content between description and inputs (summary, warnings). */
  body?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: 'danger' | 'primary';
  /** User must type this exact text (e.g. the policy set name) to enable the confirm button. */
  typeToConfirm?: string;
  /** Asks for a reason / comment; passed to onConfirm. */
  reason?: {
    label: string;
    placeholder?: string;
    required?: boolean;
    minLength?: number;
    hint?: React.ReactNode;
    multiline?: boolean;
    defaultValue?: string;
  };
  /**
   * Runs while the dialog shows a spinner. Throwing keeps the dialog open and toasts the error
   * (server message). Return value is ignored.
   */
  onConfirm?: (reason: string) => unknown | Promise<unknown>;
}

export interface ConfirmDialogProps extends ConfirmOptions {
  open: boolean;
  onClose: () => void;
  /** Called after onConfirm succeeded. */
  onDone?: (reason: string) => void;
}

/** Confirmation dialog with optional typed confirmation and reason field. */
export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  onClose,
  onDone,
  title,
  description,
  body,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  tone = 'primary',
  typeToConfirm,
  reason,
  onConfirm,
}) => {
  const toast = useToast();
  const [typed, setTyped] = useState('');
  const [text, setText] = useState(reason?.defaultValue ?? '');
  const [busy, setBusy] = useState(false);

  React.useEffect(() => {
    if (open) {
      setTyped('');
      setText(reason?.defaultValue ?? '');
      setBusy(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const minLen = reason?.minLength ?? (reason?.required ? 1 : 0);
  const reasonOk = !reason || text.trim().length >= minLen;
  const typedOk = !typeToConfirm || typed.trim() === typeToConfirm;
  const can = reasonOk && typedOk && !busy;

  const submit = async () => {
    if (!can) return;
    setBusy(true);
    try {
      await onConfirm?.(text.trim());
      onDone?.(text.trim());
      onClose();
    } catch (err) {
      toast.error(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      dismissible={!busy}
      title={title}
      description={description}
      size="sm"
      icon={
        <span
          className={cn(
            'flex h-9 w-9 shrink-0 items-center justify-center rounded-full',
            tone === 'danger' ? 'bg-danger-soft text-danger' : 'bg-accent-soft text-accent'
          )}
        >
          {tone === 'danger' ? <AlertTriangle className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />}
        </span>
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            {cancelLabel}
          </Button>
          <Button variant={tone === 'danger' ? 'danger' : 'primary'} onClick={submit} disabled={!can} loading={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      {(body || reason || typeToConfirm) && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          {body}
          {reason && (
            <Field
              label={reason.label}
              required={reason.required}
              hint={
                reason.hint ??
                (minLen > 1 && text.trim().length < minLen
                  ? `At least ${minLen} characters (${minLen - text.trim().length} more).`
                  : undefined)
              }
            >
              {reason.multiline === false ? (
                <Input value={text} onChange={(e) => setText(e.target.value)} placeholder={reason.placeholder} data-autofocus />
              ) : (
                <Textarea value={text} onChange={(e) => setText(e.target.value)} placeholder={reason.placeholder} rows={3} data-autofocus />
              )}
            </Field>
          )}
          {typeToConfirm && (
            <Field
              label={
                <>
                  Type <span className="rounded bg-surface-3 px-1 py-0.5 font-mono text-[12px]">{typeToConfirm}</span> to confirm
                </>
              }
            >
              <Input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} {...(!reason ? { 'data-autofocus': true } : {})} />
            </Field>
          )}
          <button type="submit" hidden />
        </form>
      )}
    </Modal>
  );
};

// ---------------------------------------------------------------------------
// Imperative API:  const confirm = useConfirm();  if (await confirm({...})) ...
// ---------------------------------------------------------------------------

type ConfirmFn = (opts: ConfirmOptions) => Promise<false | { reason: string }>;
const ConfirmContext = createContext<ConfirmFn | null>(null);

export const ConfirmProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = useState<(ConfirmOptions & { open: boolean }) | null>(null);
  const resolver = useRef<((v: false | { reason: string }) => void) | null>(null);
  const done = useRef(false);

  const confirm = useCallback<ConfirmFn>((opts) => {
    done.current = false;
    setState({ ...opts, open: true });
    return new Promise((resolve) => {
      resolver.current = resolve;
    });
  }, []);

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {state && (
        <ConfirmDialog
          {...state}
          onDone={(reason) => {
            done.current = true;
            resolver.current?.({ reason });
          }}
          onClose={() => {
            if (!done.current) resolver.current?.(false);
            setState((s) => (s ? { ...s, open: false } : s));
          }}
        />
      )}
    </ConfirmContext.Provider>
  );
};

/** Returns confirm(opts) → Promise<false | {reason}>. */
export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error('useConfirm must be used inside <ConfirmProvider>');
  return ctx;
}
