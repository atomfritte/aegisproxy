import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronRight, FolderOpen, Lock, MoreHorizontal, Pencil, Plus, RefreshCw, ScrollText, Send, Server, Trash2 } from 'lucide-react';
import { api } from '../../../../api';
import { usePermissions } from '../../../../data/AppData';
import { cn } from '../../../../lib/cn';
import { formatBytes, formatCompact, formatNumber } from '../../../../lib/format';
import { useAsync } from '../../../../lib/hooks';
import { useSearchParams } from '../../../../lib/router';
import type { ExportSink, ExportSinkStatus } from '../../../../types';
import {
  Badge,
  Button,
  Callout,
  Card,
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
} from '../../../../ui';
import { SectionTitle } from '../shared';
import { FORMAT_LABELS, stateOf, STREAMS, TYPE_ICONS, TYPE_SHORT, typeId } from './catalog';
import { fromSink, toPayload } from './form';
import { SinkDrawer } from './SinkDrawer';

const REFRESH_MS = 10_000;

const Counter: React.FC<{ label: string; value: number; tone?: 'danger' | 'warning'; hint: string }> = ({ label, value, tone, hint }) => (
  <Tooltip content={hint}>
    <div className="min-w-0">
      <div className="text-[11.5px] text-fg-subtle">{label}</div>
      <div className={cn('text-[14px] font-semibold tabular', value > 0 && tone === 'danger' ? 'text-danger' : value > 0 && tone === 'warning' ? 'text-warning' : 'text-fg')}>
        {formatCompact(value)}
      </div>
    </div>
  </Tooltip>
);

const SinkCard: React.FC<{
  sink: ExportSink;
  status?: ExportSinkStatus;
  canEdit: boolean;
  typeLabel: string;
  busy: boolean;
  onEdit: () => void;
  onToggle: (v: boolean) => void;
  onTest: () => void;
  onDelete: () => void;
}> = ({ sink, status, canEdit, typeLabel, busy, onEdit, onToggle, onTest, onDelete }) => {
  const [showError, setShowError] = useState(false);
  const Icon = TYPE_ICONS[sink.type] ?? Send;
  const st = stateOf(sink, status);
  const streams = sink.streams ?? [];
  return (
    <Card as="article" aria-labelledby={`sink-${sink.id}`} className={cn(!sink.enabled && 'opacity-80')}>
      <div className="flex flex-col gap-4 p-[var(--card-p)] md:flex-row md:items-start">
        <div className="flex min-w-0 flex-1 items-start gap-3">
          <span className={cn('flex h-10 w-10 shrink-0 items-center justify-center rounded-lg', sink.enabled ? 'bg-accent-soft text-accent' : 'bg-surface-3 text-fg-subtle')}>
            <Icon className="h-5 w-5" aria-hidden />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <button id={`sink-${sink.id}`} type="button" onClick={onEdit} className="truncate text-left text-[14px] font-semibold text-fg hover:text-accent hover:underline">
                {sink.name}
              </button>
              <Tooltip content={st.description}>
                <StatusChip tone={st.tone} label={st.label} pulse={status?.state === 'retrying'} />
              </Tooltip>
            </div>
            <div className="mt-0.5 text-[12.5px] text-fg-muted">
              {typeLabel} · {FORMAT_LABELS[sink.format]?.label ?? sink.format}
            </div>
            <div className="mt-1 truncate font-mono text-[12px] text-fg-subtle" title={sink.endpoint}>
              {sink.type === 'syslog' && sink.transport ? `${sink.transport}://` : ''}
              {sink.endpoint || '—'}
            </div>
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {STREAMS.filter((s) => streams.includes(s.value)).map((s) => (
                <Badge key={s.value} tone="neutral">
                  {s.label}
                </Badge>
              ))}
              {streams.includes('traffic') && sink.traffic_filter !== 'all' && <Badge tone="info">Traffic: {sink.traffic_filter}</Badge>}
              {streams.includes('security') && sink.min_severity !== 'low' && <Badge tone="info">Severity ≥ {sink.min_severity}</Badge>}
              {streams.includes('traffic') && sink.redact_query && <Badge tone="neutral">Query strings removed</Badge>}
              {sink.tls_skip_verify && (
                <Badge tone="danger" icon={AlertTriangle}>
                  TLS not verified
                </Badge>
              )}
            </div>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2 self-end md:self-start">
          {canEdit && (
            <Tooltip content={sink.enabled ? 'Pause this destination' : 'Resume this destination'}>
              <span className="inline-flex">
                <Switch checked={sink.enabled} disabled={busy} onChange={onToggle} />
              </span>
            </Tooltip>
          )}
          <Button size="sm" icon={Send} onClick={onTest} loading={busy}>
            Test
          </Button>
          <Menu
            items={[
              { id: 'edit', label: canEdit ? 'Edit' : 'View settings', icon: Pencil, onSelect: onEdit },
              { id: 'test', label: 'Send test record', icon: Send, onSelect: onTest },
              { id: 'delete', label: 'Delete…', icon: Trash2, danger: true, separator: true, hidden: !canEdit, onSelect: onDelete },
            ]}
            trigger={(p) => <IconButton {...p} icon={MoreHorizontal} label={`Actions for ${sink.name}`} size="sm" noTooltip />}
          />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-x-4 gap-y-3 border-t border-border bg-surface-2 px-[var(--card-p)] py-3 sm:grid-cols-6">
        <Counter label="Sent" value={status?.sent ?? 0} hint="Records delivered since this replica started." />
        <Counter label="Failed" value={status?.failed ?? 0} tone="danger" hint="Rejected permanently (e.g. invalid credentials) — not retried." />
        <Counter label="Dropped" value={status?.dropped ?? 0} tone="danger" hint="Discarded because the spool was full." />
        <Counter label="Queued" value={status?.queued ?? 0} tone="warning" hint="Waiting in memory for the next batch." />
        <Tooltip content={`${formatNumber(status?.spool_records ?? 0)} records waiting on disk for redelivery`}>
          <div className="min-w-0">
            <div className="text-[11.5px] text-fg-subtle">Spool</div>
            <div className={cn('text-[14px] font-semibold tabular', (status?.spool_bytes ?? 0) > 0 ? 'text-warning' : 'text-fg')}>{formatBytes(status?.spool_bytes ?? 0)}</div>
          </div>
        </Tooltip>
        <div className="min-w-0">
          <div className="text-[11.5px] text-fg-subtle">Last success</div>
          <div className="text-[13px] font-medium text-fg">{status?.last_success_at ? <RelativeTime value={status.last_success_at} /> : <span className="text-fg-subtle">Never</span>}</div>
        </div>
      </div>
      {status?.last_error && (
        <div className="border-t border-danger-border bg-danger-soft px-[var(--card-p)] py-2.5 text-[12.5px]">
          <button type="button" onClick={() => setShowError((v) => !v)} aria-expanded={showError} className="flex w-full min-w-0 items-center gap-1.5 text-left text-danger">
            {showError ? <ChevronDown className="h-3.5 w-3.5 shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" />}
            <span className="shrink-0 font-medium">Last error</span>
            {status.last_error_at && (
              <span className="shrink-0 text-fg-muted">
                <RelativeTime value={status.last_error_at} />
              </span>
            )}
            {!showError && <span className="min-w-0 truncate text-fg-muted">{status.last_error}</span>}
          </button>
          {showError && <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-[12px] leading-5 text-fg">{status.last_error}</pre>}
        </div>
      )}
    </Card>
  );
};

/** SIEM / observability destinations with live delivery status (Settings → Log export). */
export const LogExportSection: React.FC = () => {
  const perms = usePermissions();
  if (!perms.canManageSystem) {
    return (
      <>
        <SectionTitle title="Log export" description="Audit, traffic and security records forwarded to SIEM and observability systems." />
        <Card>
          <EmptyState icon={Lock} title="Restricted" description="Only InfoSec Approvers and Super Admins can view log export destinations. Ask them which systems receive AegisProxy logs." />
        </Card>
      </>
    );
  }
  return <LogExport />;
};

const LogExport: React.FC = () => {
  const toast = useToast();
  const confirm = useConfirm();
  const data = useAsync(() => api.exports.list(), []);
  const [params, setParams] = useSearchParams();
  const [drawer, setDrawer] = useState<{ open: boolean; sink: ExportSink | null }>({ open: false, sink: null });
  const [busy, setBusy] = useState<string | null>(null);
  const [lastLoad, setLastLoad] = useState<number>(Date.now());

  // auto-refresh while visible
  useEffect(() => {
    const t = window.setInterval(() => {
      if (document.visibilityState === 'visible') data.reload().then(() => setLastLoad(Date.now()));
    }, REFRESH_MS);
    return () => window.clearInterval(t);
  }, [data.reload]); // eslint-disable-line react-hooks/exhaustive-deps

  // deep link: /settings/log-export?edit=<id> or ?new=1
  const res = data.data;
  useEffect(() => {
    if (!res) return;
    const edit = params.get('edit');
    if (edit) {
      const s = res.sinks.find((x) => x.id === edit);
      if (s) setDrawer({ open: true, sink: s });
      setParams({ edit: null });
    } else if (params.get('new') && res.can_edit) {
      setDrawer({ open: true, sink: null });
      setParams({ new: null });
    }
  }, [res, params, setParams]);

  const statusById = useMemo(() => new Map((res?.status ?? []).map((s) => [s.id, s])), [res?.status]);
  const nodes = [...new Set((res?.status ?? []).map((s) => s.node).filter(Boolean))];
  const types = res?.types ?? [];
  const typeLabel = (t: string) => TYPE_SHORT[t] ?? types.find((x) => typeId(x) === t)?.label ?? t;
  const sinks = res?.sinks ?? [];
  const canEdit = !!res?.can_edit;
  const problems = sinks.filter((s) => s.enabled && ['error', 'retrying'].includes(statusById.get(s.id)?.state || '')).length;

  const reload = async () => {
    await data.reload();
    setLastLoad(Date.now());
  };

  const toggle = async (s: ExportSink, enabled: boolean) => {
    setBusy(s.id);
    try {
      await api.exports.update(s.id, { ...toPayload(fromSink(s), types.find((t) => typeId(t) === s.type)?.fields ?? []), enabled });
      toast.success(enabled ? `Resumed ${s.name}` : `Paused ${s.name}`);
      await reload();
    } catch (err) {
      toast.error(err, { title: `Could not ${enabled ? 'resume' : 'pause'} ${s.name}` });
    } finally {
      setBusy(null);
    }
  };

  const test = async (s: ExportSink) => {
    setBusy(s.id);
    try {
      const r = await api.exports.test({ ...toPayload(fromSink(s), types.find((t) => typeId(t) === s.type)?.fields ?? []), id: s.id });
      if (r.ok) toast.success(`Test record delivered to ${s.name}`, { description: 'Look for a synthetic audit record with action EXPORT_TEST.' });
      else toast.error(r.error || 'The destination did not accept the record.', { title: `Test failed for ${s.name}` });
    } catch (err) {
      toast.error(err, { title: `Test failed for ${s.name}` });
    } finally {
      setBusy(null);
    }
  };

  const remove = async (s: ExportSink) => {
    const ok = await confirm({
      title: `Delete ${s.name}?`,
      description: 'Records stop flowing to this destination immediately. Records waiting in its spool are discarded.',
      tone: 'danger',
      confirmLabel: 'Delete destination',
      typeToConfirm: s.name,
      onConfirm: () => api.exports.remove(s.id),
    });
    if (ok) {
      toast.success(`Deleted ${s.name}`);
      reload();
    }
  };

  return (
    <>
      <SectionTitle
        title="Log export"
        description="Forward audit, traffic and security records to SIEM and observability systems — syslog (QRadar, ArcSight), Splunk, Elastic, Sentinel, Datadog, Loki, OpenTelemetry, webhooks or files."
        actions={
          <>
            <Tooltip content={`Refreshes every ${REFRESH_MS / 1000} s`}>
              <Button icon={RefreshCw} onClick={reload} loading={data.loading && !!res}>
                Refresh
              </Button>
            </Tooltip>
            {canEdit && (
              <Button variant="primary" icon={Plus} onClick={() => setDrawer({ open: true, sink: null })}>
                Add destination
              </Button>
            )}
          </>
        }
      />

      {data.error && !res && (
        <Callout tone="danger" title="Log export settings could not be loaded" action={<Button size="sm" onClick={reload}>Try again</Button>}>
          {data.error}
        </Callout>
      )}

      {!res && !data.error && (
        <div className="space-y-3">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      )}

      {res && (
        <div className="space-y-4">
          {!canEdit && <Callout tone="neutral">Only Super Admins can add or change destinations. You can view them and send test records.</Callout>}
          {problems > 0 && (
            <Callout tone="warning" title={`${problems} ${problems === 1 ? 'destination has' : 'destinations have'} delivery problems`}>
              Records are spooled to disk and retried; permanent rejections are counted as failed. Open the error below for details.
            </Callout>
          )}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-fg-subtle">
            <span className="min-w-0">
              <Server className="mr-1.5 inline h-3.5 w-3.5 align-[-2px]" aria-hidden />
              Status of replica {nodes.length ? <span className="font-mono text-fg-muted">{nodes.join(', ')}</span> : 'answering this request'} — each replica exports the records it
              produced.
            </span>
            <span>
              Updated <RelativeTime value={new Date(lastLoad).toISOString()} />
            </span>
            {res.export_dir && (
              <span className="inline-flex min-w-0 max-w-full items-center gap-1.5">
                <FolderOpen className="h-3.5 w-3.5 shrink-0" aria-hidden />
                <span className="shrink-0">File destinations in</span>
                <Tooltip content={res.export_dir} className="min-w-0">
                  <span className="truncate font-mono text-fg-muted">{res.export_dir}</span>
                </Tooltip>
              </span>
            )}
          </div>

          {sinks.length === 0 ? (
            <Card>
              <EmptyState
                icon={ScrollText}
                title="No destinations yet"
                description={
                  canEdit
                    ? 'Logs stay inside AegisProxy until you add a destination. Start with your SIEM — the test button checks the connection before you save.'
                    : 'No logs are forwarded yet. A Super Admin can add destinations.'
                }
                action={
                  canEdit && (
                    <Button variant="primary" icon={Plus} onClick={() => setDrawer({ open: true, sink: null })}>
                      Add destination
                    </Button>
                  )
                }
              />
            </Card>
          ) : (
            sinks.map((s) => (
              <SinkCard
                key={s.id}
                sink={s}
                status={statusById.get(s.id)}
                canEdit={canEdit}
                typeLabel={typeLabel(s.type)}
                busy={busy === s.id}
                onEdit={() => setDrawer({ open: true, sink: s })}
                onToggle={(v) => toggle(s, v)}
                onTest={() => test(s)}
                onDelete={() => remove(s)}
              />
            ))
          )}
        </div>
      )}

      <SinkDrawer
        open={drawer.open}
        sink={drawer.sink}
        types={types}
        canEdit={canEdit}
        exportDir={res?.export_dir || ''}
        onClose={() => setDrawer({ open: false, sink: null })}
        onSaved={(saved, created) => {
          setDrawer({ open: false, sink: null });
          toast.success(created ? `Added ${saved.name}` : `Saved ${saved.name}`, { description: saved.enabled ? 'Delivery starts within seconds.' : 'The destination is paused.' });
          reload();
        }}
      />
    </>
  );
};
