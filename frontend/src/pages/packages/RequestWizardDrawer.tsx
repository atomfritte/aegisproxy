import React, { useEffect, useMemo, useState } from 'react';
import { PackageSearch, Send, Sparkles } from 'lucide-react';
import { api } from '../../api';
import { useConsoleState } from '../../data/AppData';
import { useDebouncedValue } from '../../lib/hooks';
import { navigate } from '../../lib/router';
import type { PackageEcosystem, PackageLookupResult } from '../../types';
import { Badge, Button, Callout, Drawer, Field, Input, MultiSelect, Select, Spinner, Textarea, useToast } from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { AdvisorySummary, NodeStateChip, RiskBadge } from '../../components/packages';
import { PackageVerificationChip } from '../../components/packages/PackageVerificationChip';
import { ageHours, ECOSYSTEM_META, ECOSYSTEMS, humanHours, nodeStateMeta } from '../../components/packages/packageUtils';

/** Request-a-package wizard: ecosystem, name + version/range, groups, reason, with a live assessment preview. */
export const RequestWizardDrawer: React.FC<{ open: boolean; onClose: () => void; onCreated: () => void }> = ({ open, onClose, onCreated }) => {
  const state = useConsoleState();
  const toast = useToast();
  const [ecosystem, setEcosystem] = useState<PackageEcosystem>('npm');
  const [name, setName] = useState('');
  const [version, setVersion] = useState('');
  const [groupIds, setGroupIds] = useState<string[]>(['*']);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // reset when reopened
  useEffect(() => {
    if (open) {
      setEcosystem('npm');
      setName('');
      setVersion('');
      setGroupIds(['*']);
      setReason('');
      setSubmitting(false);
    }
  }, [open]);

  const groupOptions = useMemo(
    () => [{ value: '*', label: 'All groups', description: 'Every client the ecosystem applies to' }, ...state.groups.map((g) => ({ value: g.id, label: g.name, description: g.environment || g.id, color: g.color }))],
    [state.groups]
  );

  // Live assessment preview (debounced).
  const probe = useDebouncedValue(`${ecosystem}|${name.trim()}|${version.trim()}`, 400);
  const [preview, setPreview] = useState<PackageLookupResult | null>(null);
  const [previewErr, setPreviewErr] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);
  useEffect(() => {
    const [eco, nm, ver] = probe.split('|');
    if (!open || !nm) {
      setPreview(null);
      setPreviewErr(null);
      return;
    }
    let cancelled = false;
    setPreviewing(true);
    setPreviewErr(null);
    api.packages
      .lookup({ ecosystem: eco, name: nm, version: ver || undefined })
      .then((r) => !cancelled && setPreview(r))
      .catch((e) => !cancelled && (setPreview(null), setPreviewErr(e instanceof Error ? e.message : String(e))))
      .finally(() => !cancelled && setPreviewing(false));
    return () => {
      cancelled = true;
    };
  }, [probe, open]);

  const canSubmit = !!name.trim() && groupIds.length > 0 && !submitting;

  const submit = async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      const req = await api.packages.requests.create({ ecosystem, name: name.trim(), version: version.trim(), group_ids: groupIds, reason: reason.trim() || undefined });
      toast.success('Package request opened', { description: 'Resolution and analysis have started.' });
      onCreated();
      onClose();
      navigate(`/packages/requests/${encodeURIComponent(req.id)}`);
    } catch (e) {
      toast.error(e, { title: 'The request was not opened' });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Drawer
      open={open}
      onClose={onClose}
      width="md"
      title="Request a package"
      description="Opens a request that resolves the full dependency graph and analyzes every version before a decision."
      dismissible={!submitting}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button variant="primary" icon={Send} onClick={submit} loading={submitting} disabled={!canSubmit}>
            Submit request
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <Field label="Ecosystem" hint={ECOSYSTEM_META[ecosystem]?.clients}>
          <Select
            value={ecosystem}
            onChange={(e) => setEcosystem(e.target.value as PackageEcosystem)}
            options={ECOSYSTEMS.map((id) => ({ value: id, label: ECOSYSTEM_META[id].label }))}
          />
        </Field>
        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_200px]">
          <Field label="Package name" required hint={ecosystem === 'npm' ? 'e.g. lodash or @scope/name' : ecosystem === 'pypi' ? 'e.g. requests' : 'e.g. Newtonsoft.Json'}>
            <Input mono value={name} onChange={(e) => setName(e.target.value)} placeholder="package" spellCheck={false} data-autofocus />
          </Field>
          <Field label="Version or range" optional hint="Blank = newest">
            <Input mono value={version} onChange={(e) => setVersion(e.target.value)} placeholder={ecosystem === 'npm' ? '^4.17.0' : '2.32.3'} spellCheck={false} />
          </Field>
        </div>

        <Field label="Server groups" required hint="The groups the approval will apply to. Dependencies inherit the root's scope.">
          <MultiSelect value={groupIds} onChange={setGroupIds} options={groupOptions} placeholder="Select groups" />
        </Field>

        <Field label="Reason" optional hint="Why is this package needed? Shown to the reviewer and recorded.">
          <Textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3} placeholder="e.g. Needed for the new reporting service." />
        </Field>

        <section aria-label="Assessment preview">
          <div className="mb-1.5 flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-fg-subtle" aria-hidden />
            <span className="text-[13px] font-semibold text-fg">Assessment preview</span>
            {previewing && <Spinner className="h-3.5 w-3.5 text-fg-subtle" />}
          </div>
          <PreviewCard name={name.trim()} previewing={previewing} preview={preview} error={previewErr} />
        </section>
      </div>
    </Drawer>
  );
};

const PreviewCard: React.FC<{ name: string; previewing: boolean; preview: PackageLookupResult | null; error: string | null }> = ({ name, previewing, preview, error }) => {
  if (!name) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-dashed border-border-strong bg-surface-2 px-3 py-4 text-[12.5px] text-fg-subtle">
        <PackageSearch className="h-4 w-4" aria-hidden /> Type a package name to preview its risk, advisories, signatures and cooldown.
      </div>
    );
  }
  if (error) {
    return (
      <Callout tone="warning" title="Could not preview this package">
        {error}
      </Callout>
    );
  }
  if (!preview) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 px-3 py-4 text-[12.5px] text-fg-muted">
        <Spinner className="h-4 w-4" /> {previewing ? 'Looking up the registry and advisory sources…' : 'No preview available.'}
      </div>
    );
  }
  const a = preview.assessment;
  const age = ageHours(a?.published_at);
  return (
    <div className="space-y-3 rounded-lg border border-border bg-surface p-3 shadow-card">
      <div className="flex flex-wrap items-center gap-2">
        <span className="break-all font-mono text-[13px] font-medium text-fg">
          {preview.display_name || preview.name}
          {preview.version ? `@${preview.version}` : ''}
        </span>
        <RiskBadge risk={a?.risk} />
        {preview.state && <NodeStateChip state={preview.state} />}
        {preview.already_approved_id && <Badge tone="success" size="sm">already approved</Badge>}
      </div>
      {a?.summary && <p className="text-[12.5px] leading-5 text-fg-muted">{a.summary}</p>}
      <div className="flex flex-wrap items-center gap-1.5">
        <AdvisorySummary assessment={a} />
        <PackageVerificationChip label="Signature" verification={a?.signature} />
        <PackageVerificationChip label="Provenance" verification={a?.provenance} />
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[12px]">
        <div>
          <dt className="text-fg-subtle">Published</dt>
          <dd className="text-fg">{a?.published_at ? <RelativeTime value={a.published_at} /> : '—'}</dd>
        </div>
        <div>
          <dt className="text-fg-subtle">Cooldown age</dt>
          <dd className="text-fg">{age !== null ? humanHours(age) : '—'}</dd>
        </div>
        {preview.cooldown_hours !== undefined && (
          <div>
            <dt className="text-fg-subtle">Rule cooldown</dt>
            <dd className="text-fg">{humanHours(preview.cooldown_hours)}</dd>
          </div>
        )}
        {preview.dependency_count !== undefined && (
          <div>
            <dt className="text-fg-subtle">Dependencies</dt>
            <dd className="text-fg">{preview.dependency_count}</dd>
          </div>
        )}
      </dl>
      {preview.state && (
        <p className="text-[11.5px] text-fg-subtle">
          {nodeStateMeta(preview.state).label === 'Approved'
            ? 'This exact version is already approved for some groups; requesting it can extend the scope.'
            : 'Submitting opens a request; the full graph is resolved and analyzed before a decision.'}
        </p>
      )}
    </div>
  );
};
