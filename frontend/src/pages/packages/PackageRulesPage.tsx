import React, { useEffect, useMemo, useState } from 'react';
import { MoreVertical, Pencil, Plus, ScrollText, Trash2 } from 'lucide-react';
import { api } from '../../api';
import { useConsoleState, usePermissions } from '../../data/AppData';
import { useAsync, useDocumentTitle } from '../../lib/hooks';
import { useQueryParam } from '../../lib/router';
import type { PackageRule } from '../../types';
import { Badge, Button, Callout, Column, DataTable, EmptyState, IconButton, Menu, PageHeader, Switch, Tone, useConfirm, useToast } from '../../ui';
import { ChipList, GroupChip } from '../../components/common/EntityChips';
import { EcosystemBadge } from '../../components/packages';
import { humanHours } from '../../components/packages/packageUtils';
import { RuleFormDrawer } from './RuleFormDrawer';

const ACTION_META: Record<string, { label: string; tone: Tone }> = {
  auto_approve: { label: 'Auto-approve', tone: 'success' },
  review: { label: 'Review', tone: 'warning' },
  block: { label: 'Block', tone: 'danger' },
};

/** /packages/rules — ordered rule list with create / edit / toggle / delete. */
export const PackageRulesPage: React.FC = () => {
  useDocumentTitle('Package rules');
  const state = useConsoleState();
  const perms = usePermissions();
  const confirm = useConfirm();
  const toast = useToast();
  const { data, error, loading, reload } = useAsync(() => api.packages.rules.list(), [state.revision]);
  const [editing, setEditing] = useState<PackageRule | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [ruleParam, setRuleParam] = useQueryParam('rule');
  const [newParam, setNewParam] = useQueryParam('new');
  const [busyId, setBusyId] = useState<string | null>(null);

  const rules = useMemo(() => (data ?? []).slice().sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name)), [data]);

  // Deep links: ?new=1 opens the create drawer, ?rule=<id> opens that rule.
  useEffect(() => {
    if (newParam === '1') {
      setEditing(null);
      setFormOpen(true);
    }
  }, [newParam]);
  useEffect(() => {
    if (ruleParam && data) {
      const r = data.find((x) => x.id === ruleParam);
      if (r) {
        setEditing(r);
        setFormOpen(true);
      }
    }
  }, [ruleParam, data]);

  const closeForm = () => {
    setFormOpen(false);
    setEditing(null);
    if (newParam) setNewParam(null);
    if (ruleParam) setRuleParam(null);
  };
  const openCreate = () => {
    setEditing(null);
    setFormOpen(true);
  };
  const openEdit = (r: PackageRule) => {
    setEditing(r);
    setFormOpen(true);
  };

  const toggle = async (r: PackageRule) => {
    setBusyId(r.id);
    try {
      await api.packages.rules.toggle(r.id, !r.enabled);
      await reload();
    } catch (e) {
      toast.error(e, { title: 'The rule was not toggled' });
    } finally {
      setBusyId(null);
    }
  };

  const remove = (r: PackageRule) =>
    confirm({
      title: 'Delete this rule?',
      description: `“${r.name}” will no longer be evaluated. Existing approvals it created are kept.`,
      tone: 'danger',
      confirmLabel: 'Delete rule',
      onConfirm: async () => {
        await api.packages.rules.delete(r.id);
        await reload();
        toast.success('Rule deleted');
      },
    });

  const columns: Column<PackageRule>[] = [
    { id: 'priority', header: '#', cell: (r) => <span className="tabular text-fg-muted">{r.priority}</span>, sortValue: (r) => r.priority, width: 48, align: 'right' },
    {
      id: 'name',
      header: 'Rule',
      cell: (r) => (
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-medium text-fg">{r.name}</span>
            <Badge tone={ACTION_META[r.action]?.tone ?? 'neutral'} size="sm">{ACTION_META[r.action]?.label ?? r.action}</Badge>
            {!r.enabled && <Badge tone="neutral" size="sm">disabled</Badge>}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[11.5px] text-fg-subtle">
            {(r.ecosystems ?? []).length ? (r.ecosystems ?? []).map((e) => <EcosystemBadge key={e} ecosystem={e} short />) : <span>all ecosystems</span>}
            <span className="font-mono">{(r.packages ?? ['*']).join(', ')}</span>
          </div>
        </div>
      ),
      sortValue: (r) => r.name,
    },
    { id: 'trigger', header: 'Trigger', cell: (r) => <span className="text-[12px] text-fg-muted">{r.trigger === 'updates' ? `updates${(r.update_types ?? []).length ? ` (${(r.update_types ?? []).join('/')})` : ''}` : 'any version'}</span>, hideBelow: 'lg' },
    { id: 'cooldown', header: 'Cooldown', cell: (r) => <span className="text-[12px] text-fg-muted">{r.action === 'auto_approve' ? humanHours(r.min_age_hours) : '—'}</span>, hideBelow: 'lg' },
    {
      id: 'limits',
      header: 'Limits',
      cell: (r) =>
        r.action === 'auto_approve' ? (
          <span className="flex flex-wrap gap-1 text-[11.5px]">
            <Badge tone="neutral" size="sm">≤ {r.max_severity || 'none'} sev</Badge>
            <Badge tone="neutral" size="sm">≤ {r.max_risk || 'none'} risk</Badge>
            {r.require_sandbox && <Badge tone="info" size="sm">sandbox</Badge>}
            {r.require_signature && <Badge tone="info" size="sm">signed</Badge>}
          </span>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
      hideBelow: 'xl',
    },
    {
      id: 'scope',
      header: 'Scope',
      cell: (r) => <ChipList max={2}>{(r.group_ids ?? []).map((g) => (g === '*' ? <Badge key="*" tone="violet" size="sm">All</Badge> : <GroupChip key={g} id={g} />))}</ChipList>,
      hideBelow: 'xl',
    },
    {
      id: 'enabled',
      header: 'On',
      cell: (r) =>
        perms.canManageSystem ? (
          <span onClick={(e) => e.stopPropagation()}>
            <Switch checked={r.enabled} onChange={() => toggle(r)} disabled={busyId === r.id} aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.name}`} />
          </span>
        ) : (
          <Badge tone={r.enabled ? 'success' : 'neutral'} size="sm">{r.enabled ? 'on' : 'off'}</Badge>
        ),
      width: 64,
    },
    {
      id: 'actions',
      header: '',
      cell: (r) =>
        perms.canManageSystem ? (
          <span onClick={(e) => e.stopPropagation()}>
            <Menu
              items={[
                { id: 'edit', label: 'Edit rule', icon: Pencil, onSelect: () => openEdit(r) },
                { id: 'del', label: 'Delete rule', icon: Trash2, danger: true, separator: true, onSelect: () => remove(r) },
              ]}
              trigger={(p) => <IconButton {...p} icon={MoreVertical} label="Rule actions" size="sm" variant="ghost" noTooltip />}
            />
          </span>
        ) : null,
      width: 48,
      align: 'right',
    },
  ];

  return (
    <>
      <PageHeader
        title="Rules"
        description="Cooldown (Karenz), auto-approve, review and block rules. Dependencies pulled in by an approved root are evaluated against the same rules."
        actions={perms.canManageSystem ? <Button variant="primary" icon={Plus} onClick={openCreate}>New rule</Button> : undefined}
      />

      <Callout tone="info" title="How rules are evaluated" className="mb-4">
        Rules are ordered by priority (lowest first); the <strong>first matching rule wins</strong>. A package that no rule matches falls through to <strong>human review</strong>. An auto-approve rule approves a version only when its cooldown, severity, risk and the require-checks all pass; critical advisories and malware always fail.
      </Callout>

      {error && !data && (
        <Callout tone="danger" title="Rules could not be loaded" action={<Button size="sm" onClick={() => reload()}>Try again</Button>}>
          {error}
        </Callout>
      )}

      <DataTable<PackageRule>
        rows={rules}
        columns={columns}
        getRowId={(r) => r.id}
        getSearchText={(r) => `${r.name} ${r.description ?? ''} ${(r.packages ?? []).join(' ')} ${(r.ecosystems ?? []).join(' ')} ${r.action}`}
        searchPlaceholder="Search rules…"
        loading={loading}
        groupBy={{ key: () => 'order', label: () => 'In priority order — first match wins' }}
        onRowClick={perms.canManageSystem ? (r) => openEdit(r) : undefined}
        empty={
          <EmptyState
            icon={ScrollText}
            title="No rules yet"
            description="Without rules, every package waits for human review. Add a rule to auto-approve trusted packages after a cooldown, or to block or force review on others."
            action={perms.canManageSystem ? <Button size="sm" variant="primary" icon={Plus} onClick={openCreate}>New rule</Button> : undefined}
          />
        }
      />

      <RuleFormDrawer open={formOpen} rule={editing} onClose={closeForm} onSaved={() => reload()} />
    </>
  );
};
