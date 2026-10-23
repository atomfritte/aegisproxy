import React, { useEffect, useMemo, useState } from 'react';
import { BellRing, Link2, MessageSquare, Send, ShieldAlert } from 'lucide-react';
import { api } from '../../../api';
import { useConsole, useConsoleState, usePermissions } from '../../../data/AppData';
import { formatDateTime } from '../../../lib/format';
import { Link, useNavigationBlocker } from '../../../lib/router';
import { useUrlFilters } from '../../../lib/useUrlFilters';
import type { NotificationConfig, NotificationLog } from '../../../types';
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  CodeBlock,
  Column,
  DataTable,
  DescriptionList,
  Drawer,
  EmptyState,
  Field,
  Input,
  RelativeTime,
  StatusChip,
  Switch,
  Tone,
  useToast,
} from '../../../ui';
import { SaveBar, SectionTitle } from './shared';

const CHANNEL: Record<string, { label: string; tone: Tone }> = {
  teams: { label: 'Microsoft Teams', tone: 'violet' },
  slack: { label: 'Slack', tone: 'success' },
};

function deliveryState(l: NotificationLog): { label: string; tone: Tone } {
  if (l.delivered) return { label: 'Delivered', tone: 'success' };
  if (/placeholder|logged only|demo|disabled|not configured/i.test(l.status_note || '')) return { label: 'Logged only', tone: 'neutral' };
  return { label: 'Failed', tone: 'danger' };
}

function prettyJSON(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

const ChannelCard: React.FC<{
  kind: 'teams' | 'slack';
  cfg: NotificationConfig;
  set: (patch: Partial<NotificationConfig>) => void;
  ro: boolean;
}> = ({ kind, cfg, set, ro }) => {
  const enabled = kind === 'teams' ? cfg.teams_enabled : cfg.slack_enabled;
  const url = kind === 'teams' ? cfg.teams_webhook_url : cfg.slack_webhook_url;
  const channel = kind === 'teams' ? cfg.teams_channel : cfg.slack_channel;
  return (
    <Card>
      <CardHeader
        icon={MessageSquare}
        title={CHANNEL[kind].label}
        description={kind === 'teams' ? 'Incoming webhook with Adaptive Cards.' : 'Incoming webhook with Block Kit messages.'}
        actions={<Switch checked={enabled} disabled={ro} onChange={(v) => set(kind === 'teams' ? { teams_enabled: v } : { slack_enabled: v })} />}
        divider
      />
      <div className="grid gap-4 p-[var(--card-p)] sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <Field label="Channel name" hint="Shown in the console only.">
          <Input
            value={channel}
            disabled={ro}
            placeholder={kind === 'teams' ? '#secops-approvals' : '#infosec-requests'}
            onChange={(e) => set(kind === 'teams' ? { teams_channel: e.target.value } : { slack_channel: e.target.value })}
          />
        </Field>
        <Field label="Webhook URL" hint={ro ? 'Masked for your role.' : kind === 'teams' ? 'Teams: channel → Connectors / Workflows → Incoming webhook.' : 'Slack: app → Incoming webhooks → Add new webhook.'}>
          <Input
            type={ro ? 'text' : 'url'}
            mono
            value={url}
            disabled={ro}
            placeholder={kind === 'teams' ? 'https://….webhook.office.com/…' : 'https://hooks.slack.com/services/…'}
            onChange={(e) => set(kind === 'teams' ? { teams_webhook_url: e.target.value } : { slack_webhook_url: e.target.value })}
          />
        </Field>
      </div>
    </Card>
  );
};

/** Teams/Slack webhooks, security event notifications, test message and delivery log. */
export const NotificationsSection: React.FC = () => {
  const state = useConsoleState();
  const { refresh } = useConsole();
  const perms = usePermissions();
  const toast = useToast();
  const ro = !perms.canManageSystem;
  const serverKey = JSON.stringify(state.notify_config);
  const [cfg, setCfg] = useState<NotificationConfig>(state.notify_config);
  useEffect(() => setCfg(state.notify_config), [serverKey]); // eslint-disable-line react-hooks/exhaustive-deps
  const dirty = JSON.stringify(cfg) !== serverKey;
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [open, setOpen] = useState<NotificationLog | null>(null);
  const f = useUrlFilters(['channel', 'status']);
  useNavigationBlocker(dirty && !ro, 'Discard unsaved notification settings?');

  const set = (patch: Partial<NotificationConfig>) => setCfg((c) => ({ ...c, ...patch }));
  const save = async () => {
    setSaving(true);
    try {
      await api.settings.notifications(cfg);
      await refresh();
      toast.success('Notification settings saved');
    } catch (err) {
      toast.error(err, { title: 'Notification settings not saved' });
    } finally {
      setSaving(false);
    }
  };
  const test = async () => {
    setTesting(true);
    try {
      await api.settings.testNotification();
      await refresh();
      toast.success('Test notification sent', { description: 'A sample access request was sent to every enabled channel. Check the delivery log below.' });
    } catch (err) {
      toast.error(err, { title: 'Test notification failed' });
    } finally {
      setTesting(false);
    }
  };

  const logs = useMemo(() => [...(state.notification_logs ?? [])].sort((a, b) => b.timestamp.localeCompare(a.timestamp)), [state.notification_logs]);
  const anyEnabled = cfg.teams_enabled || cfg.slack_enabled;

  const columns: Column<NotificationLog>[] = [
    { id: 'time', header: 'Sent', width: 96, sortValue: (l) => l.timestamp, cell: (l) => <RelativeTime value={l.timestamp} className="text-fg-muted" /> },
    { id: 'channel', header: 'Channel', width: 140, cell: (l) => <Badge tone={CHANNEL[l.channel]?.tone ?? 'neutral'}>{CHANNEL[l.channel]?.label ?? l.channel}</Badge> },
    {
      id: 'message',
      header: 'Message',
      cell: (l) => (
        <div className="min-w-0">
          <div className="line-clamp-1 font-medium text-fg [overflow-wrap:anywhere]">{l.title}</div>
          <div className="line-clamp-1 text-[12px] text-fg-subtle [overflow-wrap:anywhere]">{l.summary}</div>
        </div>
      ),
    },
    {
      id: 'status',
      header: 'Delivery',
      width: 130,
      cell: (l) => {
        const s = deliveryState(l);
        return <StatusChip tone={s.tone} label={s.label} title={l.status_note || undefined} />;
      },
    },
  ];

  return (
    <>
      <SectionTitle
        title="Notifications"
        description="Access requests, change requests awaiting review, security events and the daily digest are posted to Microsoft Teams and Slack, with links back to the console."
        actions={
          perms.canManageSystem ? (
            <Button icon={Send} onClick={test} loading={testing} disabled={dirty || !anyEnabled} title={dirty ? 'Save your changes first' : !anyEnabled ? 'Enable a channel first' : undefined}>
              Send test notification
            </Button>
          ) : null
        }
      />
      {ro && (
        <Callout tone="neutral" className="mb-5">
          Only InfoSec Approvers and Super Admins can change notification settings. Webhook URLs are masked for your role.
        </Callout>
      )}
      <div className="space-y-5">
        <div className="grid gap-5 xl:grid-cols-2">
          <ChannelCard kind="teams" cfg={cfg} set={set} ro={ro} />
          <ChannelCard kind="slack" cfg={cfg} set={set} ro={ro} />
        </div>
        <Card>
          <CardHeader icon={BellRing} title="What is sent" divider />
          <div className="space-y-5 p-[var(--card-p)]">
            <Field
              label="Console URL for links"
              hint="Buttons in messages open requests, change requests and security events here, e.g. https://aegis.corp.example. Leave empty to send messages without links."
            >
              <Input type="url" mono value={cfg.dashboard_base_url} disabled={ro} placeholder="https://aegis.corp.example" icon={Link2} onChange={(e) => set({ dashboard_base_url: e.target.value })} />
            </Field>
            <Switch
              checked={!!cfg.notify_security_events}
              disabled={ro}
              onChange={(v) => set({ notify_security_events: v })}
              label="Notify on security events"
              description="High and critical threat-protection events (malware, threat intelligence, data loss prevention) with a link to the event."
            />
            <p className="flex items-start gap-2 text-[12.5px] text-fg-muted">
              <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-subtle" aria-hidden />
              <span>
                New access requests and change requests are always sent to enabled channels. The daily digest is configured under{' '}
                <Link to="/settings/governance" className="font-medium text-accent hover:underline">
                  Governance
                </Link>
                .
              </span>
            </p>
          </div>
        </Card>
        {!ro && <SaveBar dirty={dirty} saving={saving} onSave={save} onReset={() => setCfg(state.notify_config)} />}

        <div>
          <h3 className="mb-3 text-[14px] font-semibold text-fg">Delivery log</h3>
          <DataTable
            rows={logs}
            columns={columns}
            getRowId={(l) => l.id}
            onRowClick={setOpen}
            getSearchText={(l) => `${l.title} ${l.summary} ${l.event_type} ${l.status_note}`}
            searchPlaceholder="Search messages…"
            search={f.search}
            onSearchChange={f.setSearch}
            facetValues={f.values}
            onFacetChange={f.onChange}
            facets={[
              { id: 'channel', label: 'Channel', getValue: (l) => l.channel, optionLabel: (v) => CHANNEL[v]?.label ?? v },
              { id: 'status', label: 'Delivery', getValue: (l) => deliveryState(l).label },
            ]}
            pageSize={25}
            mobileCard={(l) => {
              const s = deliveryState(l);
              return (
                <div className="min-w-0 space-y-1.5">
                  <div className="flex items-start justify-between gap-2">
                    <span className="min-w-0 font-medium text-fg">{l.title}</span>
                    <StatusChip tone={s.tone} label={s.label} />
                  </div>
                  <p className="line-clamp-2 text-[12.5px] text-fg-subtle">{l.summary}</p>
                  <div className="flex items-center gap-2 text-[12px] text-fg-muted">
                    <Badge tone={CHANNEL[l.channel]?.tone ?? 'neutral'}>{CHANNEL[l.channel]?.label ?? l.channel}</Badge>
                    <RelativeTime value={l.timestamp} />
                  </div>
                </div>
              );
            }}
            empty={<EmptyState size="sm" icon={BellRing} title="No notifications sent yet" description="Messages appear here once a request arrives or you send a test notification." />}
          />
        </div>
      </div>

      <Drawer open={!!open} onClose={() => setOpen(null)} title={open?.title || 'Notification'} width="lg" description={open ? `${CHANNEL[open.channel]?.label ?? open.channel} · ${formatDateTime(open.timestamp)}` : undefined}>
        {open && (
          <div className="space-y-5">
            <DescriptionList
              items={[
                { label: 'Event', value: <span className="font-mono text-[12.5px]">{open.event_type}</span> },
                { label: 'Delivery', value: <StatusChip tone={deliveryState(open).tone} label={deliveryState(open).label} /> },
                { label: 'Status note', value: open.status_note || '—', full: true },
                { label: 'Summary', value: open.summary, full: true },
              ]}
            />
            <CodeBlock title="Payload sent to the webhook" code={prettyJSON(open.payload_json)} maxHeight={480} />
          </div>
        )}
      </Drawer>
    </>
  );
};
