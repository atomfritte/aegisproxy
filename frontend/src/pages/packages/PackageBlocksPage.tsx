import React, { useEffect, useMemo, useState } from 'react';
import { Ban, Plus, Trash2 } from 'lucide-react';
import { api } from '../../api';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { useUrlFilters } from '../../lib/useUrlFilters';
import type { PackageBlock, PackageEcosystem } from '../../types';
import { Badge, Button, Callout, Column, DataTable, EmptyState, FacetDef, Field, IconButton, Input, Modal, PageHeader, Select, Textarea, useConfirm, useToast } from '../../ui';
import { RelativeTime } from '../../ui/Time';
import { UserName } from '../../components/common/EntityChips';
import { EcosystemBadge } from '../../components/packages';
import { ecosystemLabel, ECOSYSTEM_META, ECOSYSTEMS } from '../../components/packages/packageUtils';

/** /packages/blocks — explicit block list (denied regardless of approvals). */
export const PackageBlocksPage: React.FC = () => {
  useDocumentTitle('Package block list');
  const state = useConsoleState();
  const perms = usePermissions();
  const confirm = useConfirm();
  const toast = useToast();
  const f = useUrlFilters(['ecosystem']);
  const { data, error, loading, reload } = useAsync(() => api.packages.blocks.list(), [state.revision]);
  const [addOpen, setAddOpen] = useState(false);

  const rows = useMemo(() => (data ?? []).slice().sort((a, b) => (b.created_at || '').localeCompare(a.created_at || '')), [data]);

  const remove = (b: PackageBlock) =>
    confirm({
      title: 'Remove from the block list?',
      description: `${b.name} (${b.versions}) will no longer be denied for this reason. Approvals and rules then decide again.`,
      tone: 'danger',
      confirmLabel: 'Remove block',
      onConfirm: async () => {
        await api.packages.blocks.delete(b.id);
        await reload();
        toast.success('Block removed');
      },
    });

  const facets: FacetDef<PackageBlock>[] = [
    { id: 'ecosystem', label: 'Ecosystem', getValue: (b) => b.ecosystem, options: ECOSYSTEMS.map((e) => ({ value: e, label: ecosystemLabel(e) })) },
  ];

  const columns: Column<PackageBlock>[] = [
    {
      id: 'package',
      header: 'Package',
      cell: (b) => (
        <div className="flex items-start gap-2">
          <EcosystemBadge ecosystem={b.ecosystem} short className="mt-0.5" />
          <div className="min-w-0">
            <div className="break-all font-mono text-[12.5px] font-medium text-fg">{b.name}</div>
            <div className="font-mono text-[11.5px] text-fg-subtle">versions {b.versions}</div>
          </div>
        </div>
      ),
      sortValue: (b) => b.name,
    },
    { id: 'reason', header: 'Reason', cell: (b) => <span className="text-[12.5px] text-fg">{b.reason || '—'}</span> },
    { id: 'source', header: 'Source', cell: (b) => <Badge tone={b.source === 'manual' ? 'neutral' : b.source === 'advisory' ? 'warning' : 'violet'} size="sm">{b.source || 'manual'}</Badge>, hideBelow: 'lg' },
    { id: 'created', header: 'Added', cell: (b) => <span className="text-[12px] text-fg-muted"><RelativeTime value={b.created_at} /> by <UserName username={b.created_by} avatar={false} /></span>, hideBelow: 'xl' },
    {
      id: 'actions',
      header: '',
      cell: (b) =>
        perms.canManageSystem ? (
          <span onClick={(e) => e.stopPropagation()}>
            <IconButton icon={Trash2} label="Remove block" size="sm" variant="danger-ghost" onClick={() => remove(b)} />
          </span>
        ) : null,
      width: 48,
      align: 'right',
    },
  ];

  return (
    <>
      <PageHeader
        title="Block list"
        description="Versions denied regardless of approvals. A block takes precedence and the data-plane refuses the artifact even if it was previously approved."
        actions={perms.canManageSystem ? <Button variant="primary" icon={Plus} onClick={() => setAddOpen(true)}>Add block</Button> : undefined}
      />

      {error && !data && (
        <Callout tone="danger" title="The block list could not be loaded" action={<Button size="sm" onClick={() => reload()}>Try again</Button>}>
          {error}
        </Callout>
      )}

      <DataTable<PackageBlock>
        rows={rows}
        columns={columns}
        getRowId={(b) => b.id}
        getSearchText={(b) => `${b.name} ${b.versions} ${b.reason} ${b.ecosystem}`}
        searchPlaceholder="Search package, reason…"
        search={f.search}
        onSearchChange={f.setSearch}
        facetValues={f.values}
        onFacetChange={f.onChange}
        facets={facets}
        loading={loading}
        empty={
          <EmptyState
            icon={Ban}
            title="The block list is empty"
            description="Add a package to deny specific versions outright — for example a known-malicious release — regardless of any approval."
            action={perms.canManageSystem ? <Button size="sm" variant="primary" icon={Plus} onClick={() => setAddOpen(true)}>Add block</Button> : undefined}
          />
        }
      />

      <AddBlockDialog open={addOpen} onClose={() => setAddOpen(false)} onAdded={() => reload()} />
    </>
  );
};

const AddBlockDialog: React.FC<{ open: boolean; onClose: () => void; onAdded: () => void | Promise<void> }> = ({ open, onClose, onAdded }) => {
  const toast = useToast();
  const [ecosystem, setEcosystem] = useState<PackageEcosystem>('npm');
  const [name, setName] = useState('');
  const [versions, setVersions] = useState('*');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (open) {
      setEcosystem('npm');
      setName('');
      setVersions('*');
      setReason('');
      setBusy(false);
    }
  }, [open]);

  const submit = async () => {
    if (!name.trim() || !reason.trim()) return;
    setBusy(true);
    try {
      await api.packages.blocks.add({ ecosystem, name: name.trim(), versions: versions.trim() || '*', reason: reason.trim() });
      await onAdded();
      toast.success('Added to the block list');
      onClose();
    } catch (e) {
      toast.error(e, { title: 'The block was not added' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      dismissible={!busy}
      size="md"
      title="Add to the block list"
      description="Denies the matching versions for every client, taking precedence over approvals."
      icon={<span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-danger-soft text-danger"><Ban className="h-4 w-4" aria-hidden /></span>}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="danger" onClick={submit} loading={busy} disabled={!name.trim() || !reason.trim()}>Add block</Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Ecosystem">
            <Select value={ecosystem} onChange={(e) => setEcosystem(e.target.value as PackageEcosystem)} options={ECOSYSTEMS.map((id) => ({ value: id, label: ECOSYSTEM_META[id].label }))} />
          </Field>
          <Field label="Versions" hint={'"*" for all, or a range such as "<4.17.21"'}>
            <Input mono value={versions} onChange={(e) => setVersions(e.target.value)} placeholder="*" spellCheck={false} />
          </Field>
        </div>
        <Field label="Package name" required>
          <Input mono value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. event-stream" spellCheck={false} data-autofocus />
        </Field>
        <Field label="Reason" required hint="Shown in the client's error output and recorded.">
          <Textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} placeholder="e.g. Known malicious (MAL-2018-1)" />
        </Field>
      </div>
    </Modal>
  );
};
