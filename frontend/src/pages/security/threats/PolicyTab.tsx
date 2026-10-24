import React, { useEffect, useMemo, useState } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Ban, Bug, Database, EyeOff, FileCode2, Globe, KeyRound, Network, Plus, RotateCcw, Siren, Trash2 } from 'lucide-react';
import { api } from '../../../api';
import { useAction, useConsoleState } from '../../../data/AppData';
import { useLookups } from '../../../data/lookups';
import { Link } from '../../../lib/router';
import { cn } from '../../../lib/cn';
import { pluralize } from '../../../lib/format';
import { useAsync } from '../../../lib/hooks';
import { useNavigationBlocker } from '../../../lib/router';
import type { SecurityPolicy, TelemetryQueryRedaction, ThreatMode } from '../../../types';
import {
  Badge,
  Button,
  Callout,
  Card,
  Combobox,
  EmptyState,
  Field,
  HelpTip,
  IconButton,
  Input,
  RadioCards,
  RelativeTime,
  SegmentedControl,
  Select,
  Switch,
  TagInput,
  Textarea,
} from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { DLP_LABELS, FILE_TYPE_LABELS, KIB, MIB, MODE_META } from './meta';
import { useThreatData } from './useThreatData';
import { icapState, yaraFleet } from './yara';

/** Form state: numbers as strings so users can type freely; converted on save. */
interface Draft {
  threat_intel_mode: ThreatMode;
  av_enabled: boolean;
  av_mode: 'monitor' | 'block';
  av_fail_mode: 'open' | 'closed';
  av_max_scan_mib: string;
  av_oversize_action: 'allow' | 'block';
  dlp_mode: ThreatMode;
  dlp_max_scan_kib: string;
  dlp_oversize_action: 'allow' | 'block';
  dlp_detectors: string[];
  blocked_file_types: string[];
  group_blocked_file_types: Record<string, string[]>;
  block_ip_literals: boolean;
  block_private_destinations: boolean;
  block_raw_tcp: boolean;
  allowed_ports: string[];
  punycode_mode: ThreatMode;
  max_upload_mib: string;
  blocked_burst_threshold: string;
  telemetry_query_redaction: TelemetryQueryRedaction;
  icap_respmod_url: string;
  icap_reqmod_url: string;
  icap_mode: 'monitor' | 'block';
  icap_fail_mode: 'open' | 'closed';
  icap_timeout_seconds: string;
  icap_max_mib: string;
  icap_allow_modified: boolean;
  icap_tls_skip_verify: boolean;
  icap_ca_cert_pem: string;
  yara_mode: ThreatMode;
  yara_max_mib: string;
}

const round = (n: number) => String(Math.round(n * 100) / 100);

const toDraft = (p: SecurityPolicy): Draft => ({
  threat_intel_mode: p.threat_intel_mode,
  av_enabled: p.av_enabled,
  av_mode: p.av_mode,
  av_fail_mode: p.av_fail_mode,
  av_max_scan_mib: round((p.av_max_scan_bytes || 0) / MIB),
  av_oversize_action: p.av_oversize_action,
  dlp_mode: p.dlp_mode,
  dlp_max_scan_kib: round((p.dlp_max_scan_bytes || 0) / KIB),
  dlp_oversize_action: p.dlp_oversize_action === 'block' ? 'block' : 'allow',
  dlp_detectors: [...(p.dlp_detectors ?? [])],
  blocked_file_types: [...(p.blocked_file_types ?? [])],
  group_blocked_file_types: Object.fromEntries(Object.entries(p.group_blocked_file_types ?? {}).map(([k, v]) => [k, [...(v ?? [])]])),
  block_ip_literals: p.block_ip_literals,
  block_private_destinations: p.block_private_destinations,
  block_raw_tcp: p.block_raw_tcp,
  allowed_ports: (p.allowed_ports ?? []).map(String),
  punycode_mode: p.punycode_mode,
  max_upload_mib: round((p.max_upload_bytes || 0) / MIB),
  blocked_burst_threshold: String(p.blocked_burst_threshold ?? 0),
  telemetry_query_redaction: p.telemetry_query_redaction === 'none' || p.telemetry_query_redaction === 'all' ? p.telemetry_query_redaction : 'sensitive',
  icap_respmod_url: p.icap_respmod_url ?? '',
  icap_reqmod_url: p.icap_reqmod_url ?? '',
  icap_mode: p.icap_mode === 'monitor' ? 'monitor' : 'block',
  icap_fail_mode: p.icap_fail_mode === 'closed' ? 'closed' : 'open',
  icap_timeout_seconds: String(p.icap_timeout_seconds || 30),
  icap_max_mib: round((p.icap_max_bytes || 25 * MIB) / MIB),
  icap_allow_modified: p.icap_allow_modified ?? true,
  icap_tls_skip_verify: !!p.icap_tls_skip_verify,
  icap_ca_cert_pem: p.icap_ca_cert_pem ?? '',
  yara_mode: p.yara_mode || 'off',
  yara_max_mib: round((p.yara_max_bytes || 25 * MIB) / MIB),
});

const ICAP_RE = /^icaps?:\/\/[^\s/?#@]+(:\d+)?(\/[^\s?#]*)?$/i;

function validate(d: Draft) {
  const num = (s: string) => (s.trim() === '' ? NaN : Number(s));
  const av = num(d.av_max_scan_mib);
  const dlp = num(d.dlp_max_scan_kib);
  const up = num(d.max_upload_mib);
  const burst = num(d.blocked_burst_threshold);
  const icapTimeout = num(d.icap_timeout_seconds);
  const icapMax = num(d.icap_max_mib);
  const yaraMax = num(d.yara_max_mib);
  const pem = d.icap_ca_cert_pem.trim();
  return {
    icap_respmod_url: d.icap_respmod_url.trim() && !ICAP_RE.test(d.icap_respmod_url.trim()) ? 'Use icap://host:1344/service or icaps://host:11344/service (no credentials or query).' : null,
    icap_reqmod_url: d.icap_reqmod_url.trim() && !ICAP_RE.test(d.icap_reqmod_url.trim()) ? 'Use icap://host:1344/service or icaps://host:11344/service (no credentials or query).' : null,
    icap_timeout_seconds: !(Number.isInteger(icapTimeout) && icapTimeout >= 1 && icapTimeout <= 600) ? 'A whole number between 1 and 600 seconds.' : null,
    icap_max_mib: !(icapMax >= 1 && icapMax <= 2048) ? 'Between 1 and 2048 MiB.' : null,
    icap_ca_cert_pem: pem && (!pem.includes('BEGIN CERTIFICATE') || pem.length > 65536) ? 'Paste a PEM certificate (-----BEGIN CERTIFICATE-----).' : null,
    yara_max_mib: !(yaraMax >= 1 && yaraMax <= 2048) ? 'Between 1 and 2048 MiB.' : null,
    av_max_scan_mib: !(av >= 1 && av <= 2048) ? 'Between 1 and 2048 MiB.' : null,
    dlp_max_scan_kib: !(dlp >= 4 && dlp <= 65536) ? 'Between 4 KiB and 65536 KiB (64 MiB).' : null,
    max_upload_mib: !(up >= 0) ? 'Zero (unlimited) or more.' : null,
    blocked_burst_threshold: !(Number.isInteger(burst) && burst >= 0 && burst <= 100000) ? 'A whole number between 0 and 100000.' : null,
    allowed_ports: d.allowed_ports.length === 0 ? 'At least one port, usually 80 and 443.' : null,
  };
}

function fromDraft(d: Draft): SecurityPolicy {
  const groups: Record<string, string[]> = {};
  for (const [g, list] of Object.entries(d.group_blocked_file_types)) groups[g] = [...list];
  return {
    threat_intel_mode: d.threat_intel_mode,
    av_enabled: d.av_enabled,
    av_mode: d.av_mode,
    av_fail_mode: d.av_fail_mode,
    av_max_scan_bytes: Math.round(Number(d.av_max_scan_mib) * MIB),
    av_oversize_action: d.av_oversize_action,
    dlp_mode: d.dlp_mode,
    dlp_max_scan_bytes: Math.round(Number(d.dlp_max_scan_kib) * KIB),
    dlp_oversize_action: d.dlp_oversize_action,
    dlp_detectors: [...d.dlp_detectors],
    blocked_file_types: [...d.blocked_file_types],
    group_blocked_file_types: Object.keys(groups).length ? groups : undefined,
    block_ip_literals: d.block_ip_literals,
    block_private_destinations: d.block_private_destinations,
    block_raw_tcp: d.block_raw_tcp,
    allowed_ports: [...new Set(d.allowed_ports.map(Number))],
    punycode_mode: d.punycode_mode,
    max_upload_bytes: Math.round(Number(d.max_upload_mib) * MIB),
    blocked_burst_threshold: Number(d.blocked_burst_threshold),
    telemetry_query_redaction: d.telemetry_query_redaction,
    icap_respmod_url: d.icap_respmod_url.trim(),
    icap_reqmod_url: d.icap_reqmod_url.trim(),
    icap_mode: d.icap_mode,
    icap_fail_mode: d.icap_fail_mode,
    icap_timeout_seconds: Number(d.icap_timeout_seconds),
    icap_max_bytes: Math.round(Number(d.icap_max_mib) * MIB),
    icap_allow_modified: d.icap_allow_modified,
    icap_tls_skip_verify: d.icap_tls_skip_verify,
    icap_ca_cert_pem: d.icap_ca_cert_pem.trim() ? d.icap_ca_cert_pem.trim() + '\n' : '',
    yara_mode: d.yara_mode,
    yara_max_bytes: Math.round(Number(d.yara_max_mib) * MIB),
  };
}

const same = (a: Draft, b: Draft) => JSON.stringify(fromDraftSafe(a)) === JSON.stringify(fromDraftSafe(b));
function fromDraftSafe(d: Draft) {
  const p = fromDraft(d) as unknown as Record<string, unknown>;
  // order-insensitive comparison for lists
  for (const k of ['dlp_detectors', 'blocked_file_types', 'allowed_ports']) p[k] = [...(p[k] as Array<string | number>)].sort();
  const g = (p.group_blocked_file_types || {}) as Record<string, string[]>;
  p.group_blocked_file_types = Object.fromEntries(Object.keys(g).sort().map((k) => [k, [...g[k]].sort()]));
  return p;
}

const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

/** Policy section card with an icon header. */
const Section: React.FC<{ id: string; icon: LucideIcon; title: string; description: React.ReactNode; status?: React.ReactNode; children: React.ReactNode }> = ({
  id,
  icon: Icon,
  title,
  description,
  status,
  children,
}) => (
  <Card as="section" aria-labelledby={`${id}-title`} id={id} className="scroll-mt-20">
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-[var(--card-p)] py-4">
      <div className="flex min-w-0 items-start gap-3">
        <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-accent-soft text-accent">
          <Icon className="h-4 w-4" aria-hidden />
        </span>
        <div className="min-w-0">
          <h2 id={`${id}-title`} className="text-[14px] font-semibold leading-6 text-fg">
            {title}
          </h2>
          <p className="mt-0.5 max-w-2xl text-[12.5px] leading-5 text-fg-muted">{description}</p>
        </div>
      </div>
      {status}
    </div>
    <div className="space-y-5 p-[var(--card-p)]">{children}</div>
  </Card>
);

/** Selectable chip (detectors, file types). */
const Chip: React.FC<{ active: boolean; onClick: () => void; label: string; hint?: string; tone?: 'accent' | 'danger' }> = ({ active, onClick, label, hint, tone = 'accent' }) => (
  <button
    type="button"
    role="checkbox"
    aria-checked={active}
    onClick={onClick}
    title={hint}
    className={cn(
      'inline-flex min-h-[30px] items-center gap-1.5 rounded-md border px-2.5 text-left text-[12.5px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60',
      active
        ? tone === 'danger'
          ? 'border-danger-border bg-danger-soft text-danger'
          : 'border-accent-border bg-accent-soft text-accent'
        : 'border-border-strong bg-surface text-fg-muted hover:border-fg-subtle/60 hover:text-fg'
    )}
  >
    <span className={cn('flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-[3px] border', active ? 'border-current bg-current' : 'border-border-strong')} aria-hidden>
      {active && <span className="h-1.5 w-1.5 rounded-[1px] bg-surface" />}
    </span>
    {label}
  </button>
);

const modeOptions = (blockLabel: string, monitorLabel = 'Log a security event, allow the request', offLabel = 'Not evaluated') =>
  [
    { value: 'block' as ThreatMode, title: 'Block', description: blockLabel },
    { value: 'monitor' as ThreatMode, title: 'Monitor', description: monitorLabel },
    { value: 'off' as ThreatMode, title: 'Off', description: offLabel },
  ];

const unit = (u: string) => <span className="text-[12px] text-fg-subtle">{u}</span>;

const REDACTION_LABEL: Record<TelemetryQueryRedaction, string> = { sensitive: 'Credentials masked', all: 'Queries dropped', none: 'Unredacted' };

/** /threats/policy — the threat protection policy (InfoSec), read-only for everyone else. */
export const PolicyTab: React.FC = () => {
  const state = useConsoleState();
  const d = useThreatData();
  const { groupName } = useLookups();
  const { run, pending } = useAction();
  const policy = d.policy;
  const base = useMemo(() => (policy ? toDraft(policy) : null), [policy]);
  const [draft, setDraft] = useState<Draft | null>(base);
  const [touched, setTouched] = useState(false);
  const [addGroup, setAddGroup] = useState('');
  const yaraData = useAsync(() => api.yara.list(), [state.revision]);
  const yaraSets = yaraData.data?.rule_sets ?? [];
  const ro = !d.canManage;

  const dirty = !!draft && !!base && !same(draft, base);
  // adopt server changes while there are no local edits
  useEffect(() => {
    if (base && (!draft || !dirty)) setDraft(base);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [base]);
  useNavigationBlocker(dirty, 'You have unsaved changes to the protection policy. Leave without saving?', (next) => next.pathname === '/threats/policy');
  // deep links such as /threats/policy#yara
  const hasDraft = !!draft;
  useEffect(() => {
    const h = window.location.hash.slice(1);
    if (hasDraft && h) window.setTimeout(() => document.getElementById(h)?.scrollIntoView({ block: 'start' }), 50);
  }, [hasDraft]);

  if (!policy || !draft || !base) {
    return <EmptyState title="No protection policy" description="The control plane did not return a threat protection policy." />;
  }

  const errors = validate(draft);
  const invalid = Object.values(errors).some(Boolean);
  const set = (patch: Partial<Draft>) => setDraft((p) => (p ? { ...p, ...patch } : p));
  const err = (k: keyof typeof errors) => (touched || draft[k as keyof Draft] !== base[k as keyof Draft] ? errors[k] : null);
  const planes = state.data_planes ?? [];
  const clam = planes.filter((p) => p.clamav_available === 'yes').length;
  const overrideGroups = Object.keys(draft.group_blocked_file_types);
  const icapOn = !!(draft.icap_respmod_url.trim() || draft.icap_reqmod_url.trim());
  const icapPlanes = planes.filter((p) => icapState(p.icap_status).parts.length > 0);
  const icapDown = icapPlanes.filter((p) => icapState(p.icap_status).tone === 'danger').length;
  const yara = yaraFleet(planes);
  const yaraEnabled = yaraSets.filter((r) => r.enabled).length;

  const save = async () => {
    setTouched(true);
    if (invalid) return;
    const saved = await run(() => api.security.updatePolicy(fromDraft(draft)), {
      key: 'policy',
      success: 'Protection policy saved — workers apply it with their next bundle sync',
      errorTitle: 'The policy could not be saved',
    });
    if (saved) {
      setDraft(toDraft(saved));
      setTouched(false);
    }
  };

  return (
    <div className="space-y-6 pb-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <p className="max-w-3xl text-[13px] leading-6 text-fg-muted">
          One fleet-wide policy for every data-plane worker. Start new detections in monitor mode, review the events, then switch to block.
        </p>
        {policy.updated_at && (
          <p className="shrink-0 text-[12.5px] text-fg-subtle">
            Changed <RelativeTime value={policy.updated_at} />
            {policy.updated_by && (
              <>
                {' '}by <UserName username={policy.updated_by} avatar={false} />
              </>
            )}
          </p>
        )}
      </div>
      {ro && <Callout tone="neutral">You can view the policy. Only InfoSec Approvers and Super Admins can change it.</Callout>}

      <fieldset disabled={ro} className="min-w-0 space-y-6">
        <Section
          id="threat-intel"
          icon={Database}
          title="Threat intelligence"
          description="Requests to domains, URLs and IPs from enabled feeds and custom indicators, and downloads with known-malicious hashes."
          status={<Badge tone={MODE_META[draft.threat_intel_mode].tone} dot>{MODE_META[draft.threat_intel_mode].label}</Badge>}
        >
          <RadioCards<ThreatMode>
            aria-label="Threat intelligence mode"
            className="sm:grid-cols-3"
            value={draft.threat_intel_mode}
            onChange={(v) => set({ threat_intel_mode: v })}
            options={modeOptions('Deny matching requests and log a security event', 'Allow, log a security event', 'Feeds are still downloaded but not enforced')}
          />
        </Section>

        <Section
          id="antivirus"
          icon={Bug}
          title="Antivirus (ClamAV)"
          description="Workers stream downloaded content to clamd before delivering it."
          status={
            <Badge tone={planes.length === 0 ? 'neutral' : clam === planes.length ? 'success' : 'warning'}>
              {planes.length === 0 ? 'No worker reported' : `ClamAV on ${clam} of ${pluralize(planes.length, 'worker')}`}
            </Badge>
          }
        >
          <Switch checked={draft.av_enabled} onChange={(v) => set({ av_enabled: v })} label="Scan downloads" description="Buffered response bodies are scanned with INSTREAM." />
          <div className={cn('grid gap-5 sm:grid-cols-2', !draft.av_enabled && 'opacity-60')}>
            <Field label="When malware is found">
              {() => (
                <SegmentedControl<'block' | 'monitor'>
                  aria-label="Antivirus mode"
                  value={draft.av_mode}
                  onChange={(v) => set({ av_mode: v })}
                  options={[
                    { value: 'block', label: 'Block' },
                    { value: 'monitor', label: 'Log only' },
                  ]}
                />
              )}
            </Field>
            <Field
              label="If the scanner is unavailable"
              labelAside={<HelpTip content="Fail open delivers unscanned content and logs AV_ERROR. Fail closed answers 503 until clamd is back." />}
            >
              <Select
                value={draft.av_fail_mode}
                onChange={(e) => set({ av_fail_mode: e.target.value as 'open' | 'closed' })}
                options={[
                  { value: 'open', label: 'Fail open — deliver unscanned, log an event' },
                  { value: 'closed', label: 'Fail closed — block until the scanner is back' },
                ]}
              />
            </Field>
            <Field label="Largest file to scan" error={err('av_max_scan_mib')} hint={err('av_max_scan_mib') ? undefined : 'Keep in line with clamd StreamMaxLength (1–2048 MiB).'}>
              <Input type="number" min={1} max={2048} step="any" value={draft.av_max_scan_mib} onChange={(e) => set({ av_max_scan_mib: e.target.value })} trailing={unit('MiB')} />
            </Field>
            <Field label="Files above the limit">
              <Select
                value={draft.av_oversize_action}
                onChange={(e) => set({ av_oversize_action: e.target.value as 'allow' | 'block' })}
                options={[
                  { value: 'allow', label: 'Deliver unscanned (flagged)' },
                  { value: 'block', label: 'Block' },
                ]}
              />
            </Field>
          </div>
        </Section>

        <Section
          id="icap"
          icon={Network}
          title="External scanning engines (ICAP)"
          description={
            <>
              Send content to your antivirus, sandbox or DLP engine over ICAP (RFC 3507) — Symantec Content Analysis, Kaspersky Scan Engine, Trend Micro, Sophos, OPSWAT
              MetaDefender, Trellix or c-icap with ClamAV. Runs in addition to the built-in ClamAV scan.
            </>
          }
          status={
            <Badge tone={!icapOn ? 'neutral' : icapPlanes.length === 0 ? 'neutral' : icapDown ? 'danger' : 'success'} dot={icapOn}>
              {!icapOn ? 'Not configured' : icapPlanes.length === 0 ? 'No worker reported' : icapDown ? `Unreachable from ${icapDown} of ${pluralize(icapPlanes.length, 'worker')}` : `Connected from ${icapPlanes.length} ${icapPlanes.length === 1 ? 'worker' : 'workers'}`}
            </Badge>
          }
        >
          <div className="grid gap-5 sm:grid-cols-2">
            <Field
              label="RESPMOD service (downloads)"
              optional
              error={err('icap_respmod_url')}
              hint={err('icap_respmod_url') ? undefined : 'Antivirus and sandbox verdicts for downloaded content. Empty = off.'}
            >
              <Input mono value={draft.icap_respmod_url} onChange={(e) => set({ icap_respmod_url: e.target.value })} placeholder="icap://av.corp.example:1344/respmod" spellCheck={false} />
            </Field>
            <Field
              label="REQMOD service (uploads)"
              optional
              error={err('icap_reqmod_url')}
              hint={err('icap_reqmod_url') ? undefined : 'Data loss prevention for request bodies (Symantec DLP, Forcepoint …). Empty = off.'}
            >
              <Input mono value={draft.icap_reqmod_url} onChange={(e) => set({ icap_reqmod_url: e.target.value })} placeholder="icap://dlp.corp.example:1344/reqmod" spellCheck={false} />
            </Field>
          </div>
          <div className={cn('space-y-5', !icapOn && 'opacity-60')}>
            <div className="grid gap-5 sm:grid-cols-2">
              <Field label="When the engine reports a threat">
                {() => (
                  <SegmentedControl<'block' | 'monitor'>
                    aria-label="ICAP mode"
                    value={draft.icap_mode}
                    onChange={(v) => set({ icap_mode: v })}
                    options={[
                      { value: 'block', label: 'Block' },
                      { value: 'monitor', label: 'Log only' },
                    ]}
                  />
                )}
              </Field>
              <Field label="If the engine is unavailable" labelAside={<HelpTip content="Fail open delivers unscanned content and logs an event. Fail closed blocks until the engine answers again." />}>
                <Select
                  value={draft.icap_fail_mode}
                  onChange={(e) => set({ icap_fail_mode: e.target.value as 'open' | 'closed' })}
                  options={[
                    { value: 'open', label: 'Fail open — deliver, log an event' },
                    { value: 'closed', label: 'Fail closed — block until the engine is back' },
                  ]}
                />
              </Field>
              <Field label="Timeout" error={err('icap_timeout_seconds')} hint={err('icap_timeout_seconds') ? undefined : 'Per request, 1–600 seconds. Sandboxes need longer.'}>
                <Input type="number" min={1} max={600} value={draft.icap_timeout_seconds} onChange={(e) => set({ icap_timeout_seconds: e.target.value })} trailing={unit('seconds')} />
              </Field>
              <Field label="Largest body sent to the engine" error={err('icap_max_mib')} hint={err('icap_max_mib') ? undefined : 'Larger bodies are not sent (1–2048 MiB).'}>
                <Input type="number" min={1} max={2048} step="any" value={draft.icap_max_mib} onChange={(e) => set({ icap_max_mib: e.target.value })} trailing={unit('MiB')} />
              </Field>
            </div>
            <Switch
              checked={draft.icap_allow_modified}
              onChange={(v) => set({ icap_allow_modified: v })}
              label="Deliver sanitized content"
              description="When the engine returns a modified file (content disarm and reconstruction), deliver that version instead of blocking."
            />
            <div className="space-y-4 rounded-lg border border-border p-4">
              <p className="text-[12.5px] leading-5 text-fg-muted">
                <span className="font-medium text-fg">TLS (icaps://).</span> Verify the engine certificate against the system trust store or a private CA.
              </p>
              <Field label="Private CA certificate" optional error={err('icap_ca_cert_pem')} hint={err('icap_ca_cert_pem') ? undefined : 'PEM, for engines with an internal certificate.'}>
                <Textarea mono rows={3} value={draft.icap_ca_cert_pem} onChange={(e) => set({ icap_ca_cert_pem: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} />
              </Field>
              <Switch
                checked={draft.icap_tls_skip_verify}
                onChange={(v) => set({ icap_tls_skip_verify: v })}
                label="Skip certificate verification"
                description={draft.icap_tls_skip_verify ? <span className="text-danger">Insecure: content can be intercepted or verdicts forged. Use only in a lab.</span> : 'Not recommended.'}
              />
            </div>
          </div>
        </Section>

        <Section
          id="yara"
          icon={FileCode2}
          title="YARA rules"
          description={
            <>
              Match downloaded files against your own YARA rule sets (YARA-X engine on every worker).{' '}
              <Link to="/threats/yara" className="font-medium text-accent hover:underline">
                Manage rule sets
              </Link>
            </>
          }
          status={
            <Badge tone={yara.failedAll ? 'danger' : yara.errors.length ? 'warning' : MODE_META[draft.yara_mode].tone} dot>
              {yara.errors.length ? 'Compile errors on workers' : `${MODE_META[draft.yara_mode].label} · ${yaraEnabled} ${yaraEnabled === 1 ? 'set' : 'sets'}`}
            </Badge>
          }
        >
          <RadioCards<ThreatMode>
            aria-label="YARA mode"
            className="sm:grid-cols-3"
            value={draft.yara_mode}
            onChange={(v) => set({ yara_mode: v })}
            options={modeOptions('Deny downloads that match a rule', 'Allow, log a security event per match', 'Rule sets are kept but not applied')}
          />
          {draft.yara_mode !== 'off' && yaraEnabled === 0 && (
            <Callout tone="warning">
              No YARA rule set is enabled yet.{' '}
              <Link to="/threats/yara/new" className="font-medium text-accent hover:underline">
                Create one
              </Link>
              .
            </Callout>
          )}
          <Field label="Largest file to scan" error={err('yara_max_mib')} hint={err('yara_max_mib') ? undefined : '1–2048 MiB. Larger downloads are delivered unscanned by YARA.'} className="sm:max-w-[280px]">
            <Input type="number" min={1} max={2048} step="any" value={draft.yara_max_mib} onChange={(e) => set({ yara_max_mib: e.target.value })} trailing={unit('MiB')} />
          </Field>
        </Section>

        <Section
          id="dlp"
          icon={KeyRound}
          title="Data loss prevention"
          description="Scans URL query strings and request bodies for credentials and secrets leaving the fleet. Authorization headers are not scanned."
          status={<Badge tone={MODE_META[draft.dlp_mode].tone} dot>{MODE_META[draft.dlp_mode].label}</Badge>}
        >
          <RadioCards<ThreatMode>
            aria-label="DLP mode"
            className="sm:grid-cols-3"
            value={draft.dlp_mode}
            onChange={(v) => set({ dlp_mode: v })}
            options={modeOptions('Deny requests that contain secrets')}
          />
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Largest request body to scan" error={err('dlp_max_scan_kib')} hint={err('dlp_max_scan_kib') ? undefined : 'Scanned completely up to this size; 4 KiB to 64 MiB (65536 KiB).'}>
              <Input type="number" min={4} max={65536} step="any" value={draft.dlp_max_scan_kib} onChange={(e) => set({ dlp_max_scan_kib: e.target.value })} trailing={unit('KiB')} />
            </Field>
            <Field label="Uploads above the limit" hint="Also applies to the ICAP REQMOD size limit.">
              <Select
                value={draft.dlp_oversize_action}
                onChange={(e) => set({ dlp_oversize_action: e.target.value as 'allow' | 'block' })}
                options={[
                  { value: 'allow', label: 'Forward unscanned (flagged)' },
                  { value: 'block', label: 'Block (413)' },
                ]}
              />
            </Field>
          </div>
          <div>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <span className="label">
                Detectors <span className="font-normal text-fg-subtle">({draft.dlp_detectors.length} of {d.dlpDetectors.length})</span>
              </span>
              {!ro && (
                <span className="flex gap-3 text-[12px] font-medium">
                  <button type="button" className="text-accent hover:underline" onClick={() => set({ dlp_detectors: [...d.dlpDetectors] })}>
                    Select all
                  </button>
                  <button type="button" className="text-accent hover:underline" onClick={() => set({ dlp_detectors: [] })}>
                    Clear
                  </button>
                </span>
              )}
            </div>
            <div className="flex flex-wrap gap-1.5" role="group" aria-label="DLP detectors">
              {d.dlpDetectors.map((x) => (
                <Chip key={x} active={draft.dlp_detectors.includes(x)} label={DLP_LABELS[x] ?? x} hint={x} onClick={() => set({ dlp_detectors: toggle(draft.dlp_detectors, x) })} />
              ))}
            </div>
          </div>
        </Section>

        <Section
          id="downloads"
          icon={Ban}
          title="Download control"
          description="Blocks file types detected by magic bytes and URL extensions — everywhere, or only for selected server groups."
          status={
            <Badge tone={draft.blocked_file_types.length || overrideGroups.length ? 'success' : 'neutral'}>
              {draft.blocked_file_types.length ? `${pluralize(draft.blocked_file_types.length, 'type')} blocked` : 'Nothing blocked everywhere'}
            </Badge>
          }
        >
          <div>
            <span className="label mb-2">Blocked on every server</span>
            <div className="flex flex-wrap gap-1.5" role="group" aria-label="File types blocked on every server">
              {d.fileTypes.map((t) => (
                <Chip
                  key={t}
                  tone="danger"
                  active={draft.blocked_file_types.includes(t)}
                  label={FILE_TYPE_LABELS[t]?.label ?? t}
                  hint={FILE_TYPE_LABELS[t]?.hint}
                  onClick={() => set({ blocked_file_types: toggle(draft.blocked_file_types, t) })}
                />
              ))}
            </div>
          </div>
          <div className="space-y-3">
            <div className="flex items-center gap-1.5">
              <span className="label">Additional blocks per server group</span>
              <HelpTip content="Types blocked for a group are added to the fleet-wide list for servers in that group, e.g. no executables or scripts on the database tier." />
            </div>
            {overrideGroups.length === 0 && <p className="text-[12.5px] text-fg-subtle">No group-specific blocks.</p>}
            {overrideGroups.map((gid) => {
              const list = draft.group_blocked_file_types[gid];
              const g = state.groups.find((x) => x.id === gid);
              return (
                <div key={gid} className="rounded-lg border border-border bg-surface-2 p-3">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <span className="flex min-w-0 items-center gap-2 text-[13px] font-medium text-fg">
                      <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: g?.color || 'rgb(var(--c-fg-subtle))' }} aria-hidden />
                      <span className="truncate">{groupName(gid)}</span>
                      <span className="shrink-0 text-[12px] font-normal text-fg-subtle">{list.length ? `+${list.length}` : 'none yet'}</span>
                    </span>
                    {!ro && (
                      <IconButton
                        icon={Trash2}
                        size="sm"
                        variant="danger-ghost"
                        label={`Remove the override for ${groupName(gid)}`}
                        onClick={() => {
                          const next = { ...draft.group_blocked_file_types };
                          delete next[gid];
                          set({ group_blocked_file_types: next });
                        }}
                      />
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {d.fileTypes.map((t) => {
                      const global = draft.blocked_file_types.includes(t);
                      return (
                        <Chip
                          key={t}
                          tone="danger"
                          active={global || list.includes(t)}
                          label={FILE_TYPE_LABELS[t]?.label ?? t}
                          hint={global ? 'Already blocked on every server' : FILE_TYPE_LABELS[t]?.hint}
                          onClick={() => !global && set({ group_blocked_file_types: { ...draft.group_blocked_file_types, [gid]: toggle(list, t) } })}
                        />
                      );
                    })}
                  </div>
                </div>
              );
            })}
            {!ro && (
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <Combobox
                  value={addGroup}
                  onChange={setAddGroup}
                  placeholder="Choose a server group…"
                  aria-label="Server group for an override"
                  className="sm:max-w-[320px]"
                  options={state.groups.filter((g) => !(g.id in draft.group_blocked_file_types)).map((g) => ({ value: g.id, label: g.name, description: g.id, color: g.color }))}
                />
                <Button
                  icon={Plus}
                  disabled={!addGroup}
                  onClick={() => {
                    set({ group_blocked_file_types: { ...draft.group_blocked_file_types, [addGroup]: [] } });
                    setAddGroup('');
                  }}
                >
                  Add group
                </Button>
              </div>
            )}
          </div>
        </Section>

        <Section id="hygiene" icon={Globe} title="Destination hygiene" description="Hardening that applies before any allow rule is evaluated.">
          <div className="space-y-4">
            <Switch
              checked={draft.block_ip_literals}
              onChange={(v) => set({ block_ip_literals: v })}
              label="Block IP-literal destinations"
              description="e.g. https://203.0.113.7/ — IP destinations then need an explicit rule, and threat intel can evaluate DNS names."
            />
            <Switch
              checked={draft.block_private_destinations}
              onChange={(v) => set({ block_private_destinations: v })}
              label="Block private and internal destinations"
              description="RFC 1918 ranges and internal suffixes need an explicit rule; resolved addresses are pinned against DNS rebinding. Loopback, link-local and metadata endpoints are always blocked."
            />
            <Switch
              checked={draft.block_raw_tcp}
              onChange={(v) => set({ block_raw_tcp: v })}
              label="Block raw TCP tunnels"
              description="CONNECT tunnels that do not carry TLS or HTTP (SSH, custom protocols)."
            />
          </div>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Allowed destination ports" error={err('allowed_ports')} hint={err('allowed_ports') ? undefined : 'Press Enter after each port.'}>
              <TagInput
                value={draft.allowed_ports}
                onChange={(v) => set({ allowed_ports: v })}
                mono
                placeholder="443"
                normalize={(t) => t.trim().replace(/^:/, '')}
                validate={(t) => (/^\d+$/.test(t) && Number(t) >= 1 && Number(t) <= 65535 ? null : `“${t}” is not a TCP port (1–65535)`)}
                suggestions={['80', '443', '8443']}
              />
            </Field>
            <Field label="Upload size limit" error={err('max_upload_mib')} hint={err('max_upload_mib') ? undefined : '0 means unlimited.'}>
              <Input type="number" min={0} step="any" value={draft.max_upload_mib} onChange={(e) => set({ max_upload_mib: e.target.value })} trailing={unit('MiB')} />
            </Field>
          </div>
          <Field label="Punycode (IDN) host names" hint="Internationalized domains such as xn--pple-43d.com can imitate well-known names.">
            {() => (
              <SegmentedControl<ThreatMode>
                aria-label="Punycode mode"
                value={draft.punycode_mode}
                onChange={(v) => set({ punycode_mode: v })}
                options={[
                  { value: 'block', label: 'Block' },
                  { value: 'monitor', label: 'Monitor' },
                  { value: 'off', label: 'Off' },
                ]}
              />
            )}
          </Field>
        </Section>

        <Section
          id="anomaly"
          icon={Siren}
          title="Anomaly detection"
          description="Raises a blocked-burst event when one server exceeds this many blocked requests within a minute — typical for malware beaconing, scanning or a broken job."
          status={<Badge tone={Number(draft.blocked_burst_threshold) > 0 ? 'success' : 'neutral'} dot>{Number(draft.blocked_burst_threshold) > 0 ? 'On' : 'Off'}</Badge>}
        >
          <Field label="Blocked requests per server and minute" error={err('blocked_burst_threshold')} hint={err('blocked_burst_threshold') ? undefined : '0 disables burst detection. Default 30.'} className="sm:max-w-[280px]">
            <Input type="number" min={0} max={100000} value={draft.blocked_burst_threshold} onChange={(e) => set({ blocked_burst_threshold: e.target.value })} trailing={unit('per minute')} />
          </Field>
        </Section>

        <Section
          id="records"
          icon={EyeOff}
          title="Query strings in traffic records"
          description="Signed URLs and API calls carry credentials in the query string (SAS tokens, S3 and CloudFront signatures, API keys). This setting applies to traffic records, the worker access log, log export and block pages. User names and passwords inside URLs are always removed."
          status={<Badge tone={draft.telemetry_query_redaction === 'none' ? 'warning' : 'success'} dot>{REDACTION_LABEL[draft.telemetry_query_redaction]}</Badge>}
        >
          <RadioCards<TelemetryQueryRedaction>
            aria-label="Query string redaction"
            className="sm:grid-cols-3"
            value={draft.telemetry_query_redaction}
            onChange={(v) => set({ telemetry_query_redaction: v })}
            options={[
              { value: 'sensitive', title: 'Mask credentials', description: 'Values of credential-like parameters (token, sig, password, api_key, …) become REDACTED. Recommended.' },
              { value: 'all', title: 'Drop query strings', description: 'Records keep scheme, host and path only.' },
              { value: 'none', title: 'Record unchanged', description: 'Full URLs, including any credentials, reach the console, the log export and your SIEM.' },
            ]}
          />
        </Section>
      </fieldset>

      {!ro && (
        <div
          className={cn(
            'flex flex-col gap-3 rounded-lg border bg-surface px-4 py-3 sm:flex-row sm:items-center sm:justify-between',
            dirty ? 'sticky bottom-3 z-20 border-accent-border shadow-pop' : 'border-border shadow-card'
          )}
        >
          <p className="text-[13px]">
            {touched && invalid ? (
              <span className="font-medium text-danger">Fix the highlighted fields before saving.</span>
            ) : dirty ? (
              <span className="font-medium text-fg">You have unsaved changes.</span>
            ) : (
              <span className="text-fg-muted">The policy is up to date.</span>
            )}
          </p>
          <div className="flex gap-2">
            <Button icon={RotateCcw} disabled={!dirty || pending === 'policy'} onClick={() => {
                setDraft(base);
                setTouched(false);
              }}>
              Reset
            </Button>
            <Button variant="primary" disabled={!dirty} loading={pending === 'policy'} onClick={save}>
              Save policy
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};
