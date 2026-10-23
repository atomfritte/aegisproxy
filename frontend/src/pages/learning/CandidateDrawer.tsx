import React, { useEffect, useState } from 'react';
import type { CompiledRuleCandidate } from '../../types';
import { Button, Checkbox, Drawer, Field, Input, Switch, TagInput } from '../../ui';
import { HTTP_METHODS, validateCompanion, validateHostPattern, validatePathPattern } from '../../components/policy/policyUtils';

/** Edit one compiled candidate before publishing (patterns, methods, redirects, companions). */
export const CandidateDrawer: React.FC<{ candidate: CompiledRuleCandidate | null; onClose: () => void; onSave: (c: CompiledRuleCandidate) => void }> = ({ candidate, onClose, onSave }) => {
  const [c, setC] = useState<CompiledRuleCandidate | null>(candidate);
  useEffect(() => setC(candidate), [candidate]);
  if (!c) return <Drawer open={false} onClose={onClose} title="" children={null} />;
  const set = <K extends keyof CompiledRuleCandidate>(k: K, v: CompiledRuleCandidate[K]) => setC((p) => (p ? { ...p, [k]: v } : p));
  const methods = c.methods ?? [];
  const any = methods.includes('*');
  const hostErr = validateHostPattern(c.host_pattern);
  const pathErr = validatePathPattern(c.path_pattern);
  const methodsErr = methods.length === 0 ? 'Select at least one method.' : null;
  const ok = !hostErr && !pathErr && !methodsErr;
  return (
    <Drawer
      open={!!candidate}
      onClose={onClose}
      width="md"
      title="Edit candidate"
      description="Generalize or narrow the pattern before publishing. Changes stay in this browser until you publish."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!ok} onClick={() => ok && onSave({ ...c, host_pattern: c.host_pattern.trim(), path_pattern: c.path_pattern.trim() || '/**' })}>
            Apply
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Host pattern" error={hostErr}>
            <Input value={c.host_pattern} onChange={(e) => set('host_pattern', e.target.value)} mono spellCheck={false} data-autofocus />
          </Field>
          <Field label="Path pattern" error={pathErr} hint={!pathErr ? '* one segment, ** any depth' : undefined}>
            <Input value={c.path_pattern} onChange={(e) => set('path_pattern', e.target.value)} mono spellCheck={false} />
          </Field>
        </div>
        <Field label="Methods" error={methodsErr}>
          {({ id }) => (
            <div id={id} className="flex flex-wrap gap-x-4 gap-y-2">
              {HTTP_METHODS.filter((m) => m !== 'CONNECT').map((m) => (
                <Checkbox
                  key={m}
                  label={<span className="font-mono text-[12px]">{m}</span>}
                  checked={any || methods.includes(m)}
                  disabled={any}
                  onChange={() => set('methods', methods.includes(m) ? methods.filter((x) => x !== m) : [...methods, m])}
                />
              ))}
              <Checkbox label="Any" checked={any} onChange={() => set('methods', any ? ['GET', 'HEAD'] : ['*'])} />
            </div>
          )}
        </Field>
        <Switch checked={c.follow_redirects} onChange={(v) => set('follow_redirects', v)} label="Follow redirects" description="Also allow the objects matching responses redirect to." />
        <Field label="Companion patterns" optional hint="Extra host/path patterns allowed together with this rule, e.g. codeload.github.com/acme/**.">
          <TagInput value={c.companion_rules ?? []} onChange={(v) => set('companion_rules', v)} validate={validateCompanion} mono placeholder="host/path, then Enter" />
        </Field>
        {(c.sample_urls ?? []).length > 0 && (
          <div>
            <p className="label mb-1.5">Recorded requests</p>
            <ul className="space-y-1 rounded-lg border border-border bg-surface-2 p-2.5">
              {(c.sample_urls ?? []).map((u) => (
                <li key={u} className="break-all font-mono text-[11.5px] leading-5 text-fg-muted">
                  {u}
                </li>
              ))}
            </ul>
          </div>
        )}
        {(c.redirect_targets ?? []).length > 0 && (
          <p className="text-[12.5px] text-fg-muted">
            Redirects observed to <span className="font-mono text-[12px] text-fg">{(c.redirect_targets ?? []).join(', ')}</span>.
          </p>
        )}
      </div>
    </Drawer>
  );
};
