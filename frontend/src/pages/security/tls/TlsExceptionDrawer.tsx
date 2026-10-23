import React, { useEffect, useMemo, useState } from 'react';
import { Globe2, Lock, Plus, Target } from 'lucide-react';
import { api } from '../../../api';
import { useAction, useConsoleState } from '../../../data/AppData';
import { formatDateTime } from '../../../lib/format';
import { Button, Callout, Drawer, Field, Input, MultiSelect, RadioCards, Textarea } from '../../../ui';

/** Mirrors the control-plane check (store/validate.go isBroadWildcard). */
export function isBroadWildcard(p: string): boolean {
  if (!p.startsWith('*.')) return false;
  const labels = p.slice(2).split('.');
  return labels.length < 2 || (labels.length === 2 && labels[0].length <= 3 && labels[1].length === 2);
}

/** Client-side hint only; the server validates again. */
export function patternProblem(raw: string): string | null {
  const p = raw.trim().toLowerCase();
  if (!p) return null;
  if (/^[a-z]+:\/\//.test(p) || p.includes('/')) return 'Enter a host name only, without https:// or a path.';
  if (/\s/.test(p)) return 'Host names cannot contain spaces.';
  if (p === '*' || p === '*.*') return 'Catch-all patterns would disable inspection for every destination.';
  if (p.includes('*') && !p.startsWith('*.')) return 'Wildcards are only supported as a leading “*.” (e.g. *.windowsupdate.com).';
  if (p.slice(2).includes('*')) return 'Only one leading wildcard is supported.';
  if (isBroadWildcard(p)) return 'Top-level-domain wildcards (like *.com or *.co.uk) are rejected because they would disable inspection for large parts of the internet.';
  return null;
}

const CATEGORY_SUGGESTIONS = ['Certificate pinning', 'Mutual TLS', 'OS updates', 'Regulatory', 'Identity provider'];

function toLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Drawer to add a TLS no-break exception (InfoSec / Super Admin). */
export const TlsExceptionDrawer: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const state = useConsoleState();
  const { run, pending } = useAction();
  const [pattern, setPattern] = useState('');
  const [category, setCategory] = useState('');
  const [reason, setReason] = useState('');
  const [expires, setExpires] = useState('');
  const [scope, setScope] = useState<'global' | 'scoped'>('global');
  const [groups, setGroups] = useState<string[]>([]);
  const [servers, setServers] = useState<string[]>([]);
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    if (open) {
      setPattern('');
      setCategory('');
      setReason('');
      setExpires('');
      setScope('global');
      setGroups([]);
      setServers([]);
      setTouched(false);
    }
  }, [open]);

  const categories = useMemo(() => {
    const existing = (state.tls_bypass ?? []).map((t) => t.category).filter(Boolean);
    const seen = new Set<string>();
    const out: string[] = [];
    for (const c of [...existing, ...CATEGORY_SUGGESTIONS]) {
      const k = c.trim().toLowerCase();
      if (!k || seen.has(k)) continue;
      seen.add(k);
      out.push(c.trim());
    }
    return out.slice(0, 7);
  }, [state.tls_bypass]);

  const problem = patternProblem(pattern);
  const p = pattern.trim().toLowerCase();
  const expiresDate = expires ? new Date(expires) : null;
  const expiryError = expiresDate && Number.isFinite(expiresDate.getTime()) && expiresDate.getTime() <= Date.now() ? 'Choose a time in the future.' : null;
  const scopeError = scope === 'scoped' && groups.length === 0 && servers.length === 0 ? 'Select at least one group or server, or apply the exception to all servers.' : null;
  const valid = !!p && !problem && reason.trim().length > 0 && !expiryError && !scopeError;

  const quick = (days: number) => setExpires(toLocalInput(new Date(Date.now() + days * 86_400_000)));

  const submit = async () => {
    setTouched(true);
    if (!valid) return;
    const r = await run(
      () =>
        api.tlsBypass.add({
          pattern: p,
          match_type: p.startsWith('*.') ? 'wildcard' : 'exact',
          category: category.trim(),
          reason: reason.trim(),
          ...(expiresDate ? { expires_at: expiresDate.toISOString() } : {}),
          ...(scope === 'scoped' ? { group_ids: groups, server_ids: servers } : {}),
        }),
      { key: 'add', success: (x) => `TLS exception for ${x.pattern} added`, errorTitle: 'Could not add the exception' }
    );
    if (r) onClose();
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={pending !== 'add'}
      title="Add TLS exception"
      description="Connections to this destination pass through the proxy without being decrypted."
      footer={
        <>
          <Button onClick={onClose} disabled={pending === 'add'}>
            Cancel
          </Button>
          <Button variant="primary" icon={Plus} loading={pending === 'add'} onClick={submit} disabled={touched && !valid}>
            Add exception
          </Button>
        </>
      }
    >
      <form
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Field
          label="Destination host"
          required
          error={problem || (touched && !p ? 'Enter a host name or a *.domain wildcard.' : null)}
          hint={
            p && !problem
              ? p.startsWith('*.')
                ? `Matches every subdomain of ${p.slice(2)}.`
                : `Matches exactly ${p}.`
              : 'A host name (login.microsoftonline.com) or a leading wildcard (*.windowsupdate.com). Use the narrowest pattern that works.'
          }
        >
          <Input mono value={pattern} onChange={(e) => setPattern(e.target.value)} placeholder="*.windowsupdate.com" autoComplete="off" spellCheck={false} data-autofocus />
        </Field>

        <Field label="Category" optional hint="Groups exceptions in the list, e.g. why inspection is not possible.">
          {({ id, describedBy }) => (
            <div className="space-y-2">
              <Input id={id} aria-describedby={describedBy} value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Certificate pinning" />
              <div className="flex flex-wrap gap-1.5">
                {categories
                  .filter((c) => c !== category)
                  .map((c) => (
                    <button
                      key={c}
                      type="button"
                      onClick={() => setCategory(c)}
                      className="rounded-md border border-dashed border-border-strong px-2 py-0.5 text-[12px] text-fg-muted hover:border-accent hover:text-accent"
                    >
                      {c}
                    </button>
                  ))}
              </div>
            </div>
          )}
        </Field>

        <Field label="Reason" required error={touched && !reason.trim() ? 'Explain why this destination cannot be inspected.' : null} hint="Shown to reviewers and recorded in the audit trail.">
          <Textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3} placeholder="The update agent pins its certificate and fails behind TLS inspection." />
        </Field>

        <Field label="Expires" optional error={expiryError} hint={expiresDate && !expiryError ? `Inspection resumes automatically on ${formatDateTime(expiresDate.toISOString())}.` : 'Temporary exceptions are removed automatically.'}>
          {({ id, describedBy }) => (
            <div className="space-y-2">
              <Input id={id} aria-describedby={describedBy} type="datetime-local" value={expires} min={toLocalInput(new Date())} onChange={(e) => setExpires(e.target.value)} />
              <div className="flex flex-wrap gap-1.5">
                {[7, 30, 90].map((d) => (
                  <Button key={d} size="xs" variant="ghost" onClick={() => quick(d)}>
                    In {d} days
                  </Button>
                ))}
                {expires && (
                  <Button size="xs" variant="ghost" onClick={() => setExpires('')}>
                    No expiry
                  </Button>
                )}
              </div>
            </div>
          )}
        </Field>

        <div className="space-y-3">
          <div className="label">Applies to</div>
          <RadioCards<'global' | 'scoped'>
            aria-label="Scope"
            value={scope}
            onChange={setScope}
            className="sm:grid-cols-2"
            options={[
              { value: 'global', title: 'All servers', description: 'Every server skips inspection for this host.', icon: Globe2 },
              { value: 'scoped', title: 'Selected groups or servers', description: 'Other servers keep inspecting it.', icon: Target },
            ]}
          />
          {scope === 'scoped' && (
            <div className="grid gap-4">
              <Field label="Server groups">
                <MultiSelect
                  value={groups}
                  onChange={setGroups}
                  placeholder="Choose groups…"
                  options={(state.groups ?? []).map((g) => ({ value: g.id, label: g.name, description: g.id, color: g.color }))}
                />
              </Field>
              <Field label="Servers" error={touched ? scopeError : null}>
                <MultiSelect
                  value={servers}
                  onChange={setServers}
                  placeholder="Choose servers…"
                  options={(state.servers ?? []).map((s) => ({ value: s.id, label: s.hostname, description: `${s.ip} · ${s.id}` }))}
                />
              </Field>
            </div>
          )}
        </div>

        <Callout tone="warning" icon={Lock} title="What you give up">
          Without decryption the proxy only sees the host name: path rules, malware scanning and data loss prevention cannot inspect this traffic.
        </Callout>
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
};
