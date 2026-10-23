// Write-only secrets (client secrets, API keys): never displayed after saving, shown once on issue.
import React, { useEffect, useState } from 'react';
import { AlertTriangle, Eye, EyeOff, KeyRound, Undo2 } from 'lucide-react';
import { cn } from '../../lib/cn';
import { Button, Checkbox, CopyButton, Field, IconButton, Input, Modal } from '../../ui';

/**
 * Write-only secret input. With a stored value it shows "Stored ••••" and a Replace button;
 * `value` is the new secret ('' = keep the stored one). The stored secret is never shown.
 */
export const SecretField: React.FC<{
  label: React.ReactNode;
  /** A value is stored on the server (has_client_secret …). */
  stored: boolean;
  value: string;
  onChange: (v: string) => void;
  hint?: React.ReactNode;
  error?: React.ReactNode;
  required?: boolean;
  optional?: boolean;
  disabled?: boolean;
  placeholder?: string;
  /** Change it (e.g. after saving) to return to the "stored" state. */
  resetKey?: unknown;
  className?: string;
}> = ({ label, stored, value, onChange, hint, error, required, optional, disabled, placeholder = 'Paste the secret', resetKey, className }) => {
  const [replacing, setReplacing] = useState(false);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    setReplacing(false);
    setVisible(false);
  }, [stored, resetKey]);
  const editing = !stored || replacing;
  const keep = () => {
    onChange('');
    setReplacing(false);
  };
  return (
    <Field
      label={label}
      required={required}
      optional={optional}
      error={error}
      hint={hint ?? (stored ? 'Write-only: the stored value is never shown. Replace it to rotate the secret.' : 'Write-only: it cannot be displayed again after saving.')}
      className={className}
    >
      {({ id, describedBy, invalid }) =>
        editing ? (
          <Input
            id={id}
            aria-describedby={describedBy}
            aria-invalid={invalid || undefined}
            type={visible ? 'text' : 'password'}
            autoComplete="new-password"
            spellCheck={false}
            mono
            value={value}
            disabled={disabled}
            placeholder={stored ? 'New value — leave empty to keep the stored one' : placeholder}
            onChange={(e) => onChange(e.target.value)}
            data-autofocus={replacing || undefined}
            trailing={
              <span className="-mr-1 flex items-center gap-0.5">
                <IconButton
                  icon={visible ? EyeOff : Eye}
                  label={visible ? 'Hide the value' : 'Show the value while typing'}
                  size="xs"
                  variant="ghost"
                  disabled={disabled || !value}
                  onClick={() => setVisible((v) => !v)}
                />
                {stored && (
                  <Button size="xs" variant="ghost" icon={Undo2} onClick={keep} disabled={disabled}>
                    Keep stored
                  </Button>
                )}
              </span>
            }
          />
        ) : (
          <div
            id={id}
            aria-describedby={describedBy}
            className={cn('flex min-h-[var(--control-h)] items-center gap-2 rounded-md border border-border bg-surface-2 py-1 pl-3 pr-1', disabled && 'opacity-80')}
          >
            <KeyRound className="h-4 w-4 shrink-0 text-success" aria-hidden />
            <span className="min-w-0 flex-1 text-[13px] text-fg">
              Stored <span className="font-mono tracking-[0.2em] text-fg-muted" aria-hidden>••••••••</span>
              <span className="sr-only">(value hidden)</span>
            </span>
            {!disabled && (
              <Button size="xs" variant="ghost" onClick={() => setReplacing(true)}>
                Replace
              </Button>
            )}
          </div>
        )
      }
    </Field>
  );
};

/**
 * Shows a newly issued secret exactly once (API keys, tokens). The dialog can only be closed after
 * confirming that the value was stored.
 */
export const OneTimeSecretModal: React.FC<{
  open: boolean;
  title: React.ReactNode;
  description?: React.ReactNode;
  secret: string;
  secretLabel?: string;
  onClose: () => void;
  children?: React.ReactNode;
  confirmLabel?: string;
}> = ({ open, title, description, secret, secretLabel = 'API key', onClose, children, confirmLabel = 'Close — I have stored the key' }) => {
  const [ack, setAck] = useState(false);
  useEffect(() => {
    if (open) setAck(false);
  }, [open, secret]);
  return (
    <Modal
      open={open}
      onClose={() => ack && onClose()}
      dismissible={false}
      size="lg"
      title={title}
      description={description}
      icon={
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-warning-soft text-warning">
          <KeyRound className="h-4 w-4" aria-hidden />
        </span>
      }
      footer={
        <>
          <Checkbox checked={ack} onChange={(e) => setAck(e.target.checked)} label="I have copied the key to a secure place" className="mr-auto" />
          <Button variant="primary" onClick={onClose} disabled={!ack}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="flex items-start gap-2.5 rounded-lg border border-warning-border bg-warning-soft px-3.5 py-3 text-[13px]">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
          <p className="leading-5 text-fg">
            <span className="font-semibold">You won’t see this {secretLabel} again.</span> AegisProxy stores only a hash. If it is lost, rotate the key and update the
            automation that uses it.
          </p>
        </div>
        <div>
          <div className="mb-1.5 text-[12.5px] font-medium text-fg">{secretLabel}</div>
          <div className="flex items-center gap-2 rounded-lg border border-border-strong bg-surface-2 p-2 pl-3">
            <code className="min-w-0 flex-1 select-all font-mono text-[13.5px] font-semibold text-fg [overflow-wrap:anywhere]" data-testid="one-time-secret">
              {secret}
            </code>
            <CopyButton text={secret} label={`Copy ${secretLabel}`} />
          </div>
        </div>
        {children}
      </div>
    </Modal>
  );
};
