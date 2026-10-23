import React, { useMemo, useState } from 'react';
import { AlertTriangle, Cpu, FileCode2, MoreHorizontal, Pencil, Plus, RefreshCw, SlidersHorizontal, Trash2 } from 'lucide-react';
import { api } from '../../../api';
import { useConsoleState } from '../../../data/AppData';
import { formatBytes, pluralize } from '../../../lib/format';
import { useAsync, type AsyncState } from '../../../lib/hooks';
import { Link, navigate } from '../../../lib/router';
import type { YaraResponse, YaraRuleSet } from '../../../types';
import {
  Badge,
  Button,
  ButtonLink,
  Callout,
  Card,
  CardHeader,
  Column,
  DataTable,
  EmptyState,
  IconButton,
  Menu,
  RelativeTime,
  Skeleton,
  StatusChip,
  Switch,
  Tooltip,
  useConfirm,
  useToast,
} from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { ModeBadge } from './components';
import { useThreatData } from './useThreatData';
import { countRules, errorForSet, setsInError, yaraFleet, yaraPath } from './yara';
import { YaraEditor } from './YaraEditor';

/** /threats/yara — YARA rule sets (list) and /threats/yara/:id (editor, `new` creates). */
export const YaraTab: React.FC<{ id?: string }> = ({ id }) => {
  const state = useConsoleState();
  const data = useAsync(() => api.yara.list(), [state.revision]);
  if (id) return <YaraEditor id={id} data={data} />;
  return <YaraList data={data} />;
};

export type YaraData = AsyncState<YaraResponse>;

const YaraList: React.FC<{ data: YaraData }> = ({ data }) => {
  const d = useThreatData();
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState<string | null>(null);
  const sets = useMemo(() => [...(data.data?.rule_sets ?? [])].sort((a, b) => a.name.localeCompare(b.name)), [data.data]);
  const planes = data.data?.data_planes ?? d.planes;
  const fleet = yaraFleet(planes);
  const mode = d.policy?.yara_mode ?? 'off';
  const enabledSets = sets.filter((s) => s.enabled);
  const enabledRules = enabledSets.reduce((n, s) => n + countRules(s.source), 0);

  const toggle = async (rs: YaraRuleSet) => {
    setBusy(rs.id);
    try {
      await api.yara.update(rs.id, { ...rs, enabled: !rs.enabled });
      toast.success(rs.enabled ? `Disabled “${rs.name}”` : `Enabled “${rs.name}”`, { description: 'Workers recompile the rules with their next bundle sync.' });
      await data.reload();
    } catch (e) {
      toast.error(e, { title: `Could not change “${rs.name}”` });
    } finally {
      setBusy(null);
    }
  };

  const remove = (rs: YaraRuleSet) =>
    confirm({
      title: `Delete rule set “${rs.name}”?`,
      description: 'Workers stop matching its rules with their next bundle sync. This cannot be undone.',
      tone: 'danger',
      confirmLabel: 'Delete rule set',
      typeToConfirm: rs.name,
      onConfirm: async () => {
        await api.yara.remove(rs.id);
        toast.success(`Deleted rule set “${rs.name}”`);
        await data.reload();
      },
    });

  const columns: Column<YaraRuleSet>[] = [
    {
      id: 'name',
      header: 'Rule set',
      sortValue: (r) => r.name.toLowerCase(),
      cell: (r) => {
        const broken = fleet.errors.some((e) => setsInError(e.st.error || '', [r]).length > 0);
        const skipped = fleet.errors.some((e) => setsInError(e.st.error || '', [r]).length > 0 && errorForSet(e.st.error || '', r).includes('rule set skipped'));
        return (
          <div className="min-w-0 max-w-[520px]">
            <div className="flex flex-wrap items-center gap-1.5">
              <Link to={yaraPath(r.id)} className="font-medium text-fg hover:text-accent hover:underline">
                {r.name}
              </Link>
              {broken && (
                <Tooltip content={skipped ? 'Not active on at least one worker: fix the rules.' : 'The previous version stays active until the error is fixed.'}>
                  <Badge tone={skipped ? 'danger' : 'warning'} icon={AlertTriangle}>
                    {skipped ? 'Compile error — skipped' : 'Compile error — previous version active'}
                  </Badge>
                </Tooltip>
              )}
            </div>
            {r.description && <p className="mt-0.5 line-clamp-2 text-[12px] leading-5 text-fg-muted">{r.description}</p>}
          </div>
        );
      },
    },
    {
      id: 'rules',
      header: 'Rules',
      width: 90,
      align: 'right',
      sortValue: (r) => countRules(r.source),
      cell: (r) => (
        <div className="leading-tight">
          <div className="tabular text-fg">{countRules(r.source)}</div>
          <div className="text-[11.5px] text-fg-subtle">{formatBytes(new Blob([r.source]).size)}</div>
        </div>
      ),
    },
    {
      id: 'updated',
      header: 'Last change',
      width: 170,
      hideBelow: 'lg',
      sortValue: (r) => r.updated_at || r.created_at,
      cell: (r) => (
        <div className="leading-tight">
          <RelativeTime value={r.updated_at || r.created_at} className="text-[13px] text-fg" />
          {r.updated_by && (
            <div className="mt-0.5 text-[12px] text-fg-subtle">
              by <UserName username={r.updated_by} avatar={false} />
            </div>
          )}
        </div>
      ),
    },
    {
      id: 'enabled',
      header: 'Enabled',
      width: 80,
      sortValue: (r) => (r.enabled ? 0 : 1),
      cell: (r) => (
        <Tooltip content={d.canManage ? (r.enabled ? 'Disable rule set' : 'Enable rule set') : 'Only InfoSec can change rule sets'}>
          <span className="inline-flex">
            <Switch checked={r.enabled} onChange={() => toggle(r)} disabled={!d.canManage || busy === r.id} />
          </span>
        </Tooltip>
      ),
    },
    {
      id: 'actions',
      header: <span className="sr-only">Actions</span>,
      width: 48,
      align: 'right',
      hideOnMobile: true,
      cell: (r) => (
        <Menu
          items={[
            { id: 'edit', label: d.canManage ? 'Edit' : 'View', icon: Pencil, onSelect: () => navigate(yaraPath(r.id)) },
            { id: 'delete', label: 'Delete…', icon: Trash2, danger: true, separator: true, hidden: !d.canManage, onSelect: () => remove(r) },
          ]}
          trigger={(p) => <IconButton {...p} icon={MoreHorizontal} label={`Actions for ${r.name}`} size="sm" noTooltip />}
        />
      ),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <p className="max-w-3xl text-[13px] leading-6 text-fg-muted">
          Custom YARA rules matched against downloaded files by every worker (YARA-X engine), in <ModeBadge mode={mode} className="align-middle" /> mode
          {d.policy ? ` for files up to ${formatBytes(d.policy.yara_max_bytes || 0)}` : ''}. Use them for detections your antivirus misses — in-house malware families,
          leaked-document markers or threat-hunting rules.
        </p>
        <div className="flex shrink-0 flex-wrap gap-2">
          <Button icon={RefreshCw} onClick={() => data.reload()} loading={data.loading && !!data.data}>
            Refresh
          </Button>
          {d.canManage && (
            <ButtonLink to={yaraPath('new')} variant="primary" icon={Plus}>
              New rule set
            </ButtonLink>
          )}
        </div>
      </div>

      {mode === 'off' && enabledSets.length > 0 && (
        <Callout
          tone="warning"
          title="YARA scanning is off"
          action={
            <ButtonLink size="sm" to="/threats/policy#yara" icon={SlidersHorizontal}>
              Protection policy
            </ButtonLink>
          }
        >
          {enabledSets.length} enabled {enabledSets.length === 1 ? 'rule set is' : 'rule sets are'} compiled but not applied. Switch YARA to monitor or block in the protection policy.
        </Callout>
      )}
      {!d.canManage && <Callout tone="neutral">Only InfoSec Approvers and Super Admins can change YARA rules.</Callout>}

      {data.error && !data.data && (
        <Callout tone="danger" title="YARA rule sets could not be loaded" action={<Button size="sm" onClick={() => data.reload()}>Try again</Button>}>
          {data.error}
        </Callout>
      )}

      <Card>
        <CardHeader
          icon={Cpu}
          title="Engine status"
          description={`${pluralize(enabledSets.length, 'enabled set')} with ${pluralize(enabledRules, 'rule')} · reported by each worker with its heartbeat`}
          actions={
            planes.length > 0 ? (
              <StatusChip
                tone={fleet.failedAll ? 'danger' : fleet.errors.length ? 'warning' : fleet.ok === planes.length ? 'success' : 'neutral'}
                label={fleet.errors.length ? `Problems on ${fleet.errors.length} of ${planes.length}` : `Compiled on ${fleet.ok} of ${planes.length}`}
              />
            ) : undefined
          }
          divider
        />
        {!data.data && !data.error ? (
          <div className="p-[var(--card-p)]">
            <Skeleton className="h-10" />
          </div>
        ) : planes.length === 0 ? (
          <p className="p-[var(--card-p)] text-[13px] text-fg-subtle">No data-plane worker has reported yet. Status appears after the first policy sync.</p>
        ) : (
          <ul className="divide-y divide-border" data-testid="yara-engine-status">
            {fleet.states.map(({ plane, st }) => (
              <li key={plane.id} className="flex flex-col gap-1.5 px-[var(--card-p)] py-2.5 sm:flex-row sm:items-start sm:gap-3">
                <span className="w-56 shrink-0 truncate font-mono text-[12.5px] text-fg" title={plane.id}>
                  {plane.id}
                </span>
                <Tooltip content={st.description}>
                  <StatusChip tone={st.tone} label={st.label} />
                </Tooltip>
                {st.error && (
                  <ul className={`min-w-0 flex-1 space-y-0.5 font-mono text-[12px] [overflow-wrap:anywhere] ${st.key === 'partial' ? 'text-warning' : 'text-danger'}`}>
                    {st.error.split('; ').map((m, i) => (
                      <li key={i}>{m}</li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <DataTable
        aria-label="YARA rule sets"
        rows={sets}
        loading={!data.data && !data.error}
        columns={columns}
        getRowId={(r) => r.id}
        getSearchText={(r) => `${r.name} ${r.description}`}
        searchPlaceholder="Search rule sets…"
        rowClassName={(r) => (r.enabled ? undefined : 'opacity-75')}
        mobileCard={(r) => (
          <div className="min-w-0 space-y-1.5">
            <div className="flex items-start justify-between gap-3">
              <Link to={yaraPath(r.id)} className="min-w-0 font-medium text-fg">
                {r.name}
              </Link>
              <Switch checked={r.enabled} onChange={() => toggle(r)} disabled={!d.canManage || busy === r.id} />
            </div>
            {r.description && <p className="line-clamp-2 text-[12px] text-fg-muted">{r.description}</p>}
            <div className="flex flex-wrap items-center gap-1.5 text-[12px] text-fg-subtle">
              {pluralize(countRules(r.source), 'rule')} · <RelativeTime value={r.updated_at || r.created_at} />
              {fleet.errors.some((e) => setsInError(e.st.error || '', [r]).length > 0) && (
                <Badge tone="warning" icon={AlertTriangle}>
                  Compile error
                </Badge>
              )}
            </div>
          </div>
        )}
        empty={
          <EmptyState
            icon={FileCode2}
            title="No YARA rule sets yet"
            description={d.canManage ? 'Paste rules from your threat-intel team or a trusted repository; they are validated when saved and compiled by every worker.' : 'No custom YARA rules are configured.'}
            action={
              d.canManage && (
                <ButtonLink to={yaraPath('new')} variant="primary" icon={Plus}>
                  New rule set
                </ButtonLink>
              )
            }
          />
        }
      />
    </div>
  );
};

