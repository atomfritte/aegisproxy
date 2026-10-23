import React, { useEffect, useMemo, useState } from 'react';
import { ChevronRight, ExternalLink, FlaskConical, GitMerge, Plus, Search, Terminal } from 'lucide-react';
import { api, errorMessage } from '../../../api';
import { useConsole, useConsoleState, usePermissions } from '../../../data/AppData';
import { useLookups } from '../../../data/lookups';
import { cn } from '../../../lib/cn';
import { navigate } from '../../../lib/router';
import type { SimulateRequestResponse, TrafficFlow } from '../../../types';
import {
  Badge,
  Button,
  Callout,
  Combobox,
  CopyButton,
  DescriptionList,
  Drawer,
  Field,
  Input,
  PatternText,
  Select,
  Switch,
} from '../../../ui';
import { ChipList, GroupChip } from '../../../components/common/EntityChips';
import { VerdictBadge } from '../../../components/traffic/VerdictBadge';
import { newSetFromFlowUrl } from '../flowLinks';
import { extractBlockToken, portalEligible, portalUrl, reasonLabel, verdictClass } from './flowUtils';

interface Evaluation {
  allowed?: boolean;
  verdict?: string;
  tls_bypass?: boolean;
  server_id?: string;
  server_hostname?: string;
  group_ids?: string[] | null;
  matched_rule_id?: string;
  matched_rule_name?: string;
  follow_redirects?: boolean;
  session_id?: string;
  suggested_host?: string;
  suggested_path?: string;
  block_reason?: string;
  threat_category?: string;
  threat_source?: string;
  threat_indicator?: string;
  security_flags?: string[];
}

export interface SimulatorInput {
  serverIp: string;
  method: string;
  url: string;
}

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT'];

const EXAMPLES: Array<{ label: string; tone: 'success' | 'danger' | 'violet'; input: SimulatorInput & { redirect: boolean } }> = [
  {
    label: 'Allowed release download with redirect',
    tone: 'success',
    input: { serverIp: '10.20.1.15', method: 'GET', url: 'https://github.com/microsoft/vscode/releases/download/1.94.2/code_1.94.2_amd64.deb', redirect: true },
  },
  {
    label: 'Repository outside the allow list',
    tone: 'danger',
    input: { serverIp: '10.20.1.15', method: 'GET', url: 'https://github.com/torvalds/linux/archive/refs/heads/master.tar.gz', redirect: false },
  },
  {
    label: 'TLS passthrough (Windows Update)',
    tone: 'violet',
    input: { serverIp: '10.40.8.19', method: 'CONNECT', url: 'https://fe2cr.update.microsoft.com.windowsupdate.com/', redirect: false },
  },
];

export interface SimulatorDrawerProps {
  open: boolean;
  onClose: () => void;
  initial?: SimulatorInput | null;
  /** Show a simulated flow in the flow drawer. */
  onInspect: (flow: TrafficFlow, blockToken?: string) => void;
}

/** "What happens if server X requests URL Y?" — side-effect-free outside demo mode. */
export const SimulatorDrawer: React.FC<SimulatorDrawerProps> = ({ open, onClose, initial, onInspect }) => {
  const state = useConsoleState();
  const { demoMode, refresh } = useConsole();
  const perms = usePermissions();
  const { groupName } = useLookups();
  const servers = state.servers ?? [];

  const [ip, setIp] = useState('');
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [redirect, setRedirect] = useState(true);
  const [proxyUser, setProxyUser] = useState('');
  const [userAgent, setUserAgent] = useState('');
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SimulateRequestResponse | null>(null);

  useEffect(() => {
    if (!open) return;
    setIp(initial?.serverIp || servers.find((s) => s.ip === '10.20.1.15')?.ip || servers[0]?.ip || '');
    setMethod(initial?.method || 'GET');
    setUrl(initial?.url || '');
    setError(null);
    setResult(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initial]);

  const options = useMemo(() => {
    const seen = new Set<string>();
    const out = servers
      .filter((s) => (seen.has(s.ip) ? false : (seen.add(s.ip), true)))
      .map((s) => ({
        value: s.ip,
        label: s.hostname,
        description: `${s.ip}${(s.effective_group_ids ?? s.group_ids ?? []).length ? ` · ${(s.effective_group_ids ?? s.group_ids ?? []).map(groupName).join(', ')}` : ''}`,
      }));
    if (ip && !seen.has(ip)) out.unshift({ value: ip, label: ip, description: 'Unregistered source' });
    return out;
  }, [servers, ip, groupName]);

  const urlError = url && !/^https?:\/\/[^/\s]+/i.test(url.trim()) ? 'Enter an absolute http:// or https:// URL.' : null;

  const run = async (input?: SimulatorInput & { redirect: boolean }) => {
    const body = {
      server_ip: input?.serverIp ?? ip,
      method: input?.method ?? method,
      full_url: (input?.url ?? url).trim(),
      simulate_redirect: input?.redirect ?? redirect,
      proxy_auth_user: proxyUser.trim() || undefined,
      user_agent: userAgent.trim() || undefined,
    };
    if (input) {
      setIp(input.serverIp);
      setMethod(input.method);
      setUrl(input.url);
      setRedirect(input.redirect);
    }
    setBusy(true);
    setError(null);
    try {
      const r = await api.simulate.request(body);
      setResult(r);
      if (!r.dry_run) void refresh();
    } catch (err) {
      setResult(null);
      setError(errorMessage(err, 'Simulation failed'));
    } finally {
      setBusy(false);
    }
  };

  const ev = (result?.evaluation ?? {}) as Evaluation;
  const flow = result?.flow;
  const child = result?.child_flow ?? null;
  const token = extractBlockToken(result?.cli_output);

  return (
    <Drawer
      open={open}
      onClose={onClose}
      width="lg"
      title="Policy simulator"
      description="Evaluate a request against the live policy without sending it: allow rules, TLS exceptions and threat protection."
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" icon={Search} loading={busy} disabled={!ip || !url.trim() || !!urlError} type="submit" form="sim-form">
            Evaluate
          </Button>
        </>
      }
    >
      <form
        id="sim-form"
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          if (ip && url.trim() && !urlError) run();
        }}
      >
        {demoMode && (
          <div>
            <p className="mb-2 text-[12.5px] font-medium text-fg-muted">Try an example</p>
            <div className="flex flex-wrap gap-2">
              {EXAMPLES.map((x) => (
                <button
                  key={x.label}
                  type="button"
                  disabled={busy}
                  onClick={() => run(x.input)}
                  className="inline-flex items-center gap-2 rounded-md border border-border bg-surface px-2.5 py-1.5 text-left text-[12.5px] text-fg shadow-xs hover:border-border-strong hover:bg-surface-2 disabled:opacity-50"
                >
                  <span
                    className={cn('h-2 w-2 shrink-0 rounded-full', x.tone === 'success' ? 'bg-success-solid' : x.tone === 'danger' ? 'bg-danger-solid' : 'bg-violet-solid')}
                    aria-hidden
                  />
                  {x.label}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-4 sm:grid-cols-[1fr_140px]">
          <Field label="Source server" hint="The request is evaluated as if it came from this server's IP address.">
            <Combobox value={ip} onChange={setIp} options={options} placeholder="Choose a server" searchPlaceholder="Search hostname or IP…" />
          </Field>
          <Field label="Method">
            <Select value={method} onChange={(e) => setMethod(e.target.value)} options={METHODS.map((m) => ({ value: m, label: m }))} />
          </Field>
        </div>
        <Field label="URL" error={urlError}>
          <Input mono value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/acme/tool/releases/download/v1.0/tool.tar.gz" autoComplete="off" spellCheck={false} />
        </Field>
        <Switch
          checked={redirect}
          onChange={setRedirect}
          label="Follow a release redirect"
          description="For allowed github.com requests whose rule follows redirects, also evaluate the 302 target object."
        />
        <div>
          <button type="button" onClick={() => setAdvanced((a) => !a)} className="inline-flex items-center gap-1 text-[12.5px] font-medium text-fg-muted hover:text-fg" aria-expanded={advanced}>
            <ChevronRight className={cn('h-3.5 w-3.5 transition-transform', advanced && 'rotate-90')} aria-hidden />
            Proxy user and user agent
          </button>
          {advanced && (
            <div className="mt-3 grid gap-4 sm:grid-cols-2">
              <Field label="Proxy user" optional hint="Identifies servers behind NAT.">
                <Input mono value={proxyUser} onChange={(e) => setProxyUser(e.target.value)} placeholder="svc-ci-runner-02" />
              </Field>
              <Field label="User agent" optional>
                <Input mono value={userAgent} onChange={(e) => setUserAgent(e.target.value)} placeholder="curl/8.5.0" />
              </Field>
            </div>
          )}
        </div>
        <button type="submit" hidden />
      </form>

      {error && (
        <Callout tone="danger" title="The simulation failed" className="mt-5">
          {error}
        </Callout>
      )}

      {result && flow && (
        <section className="mt-6 space-y-4 border-t border-border pt-5" aria-live="polite">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-[15px] font-semibold text-fg">{ev.allowed ? 'This request would be allowed' : 'This request would be blocked'}</h3>
            <VerdictBadge verdict={ev.verdict || flow.verdict} />
            <Badge tone="neutral" icon={FlaskConical}>
              {result.dry_run ? 'Dry run, nothing recorded' : 'Recorded in the live stream'}
            </Badge>
          </div>
          <DescriptionList
            items={[
              { label: 'Server', value: ev.server_hostname || flow.server_hostname || <span className="text-fg-subtle">Unregistered source</span> },
              {
                label: 'Groups',
                value: (ev.group_ids ?? []).length ? (
                  <ChipList max={4}>
                    {(ev.group_ids ?? []).map((g) => (
                      <GroupChip key={g} id={g} />
                    ))}
                  </ChipList>
                ) : (
                  <span className="text-fg-subtle">No group</span>
                ),
              },
              { label: 'Matched rule', value: ev.matched_rule_name || <span className="text-fg-subtle">None</span> },
              { label: 'TLS', value: ev.tls_bypass ? 'Passed through (TLS exception)' : 'Decrypted and inspected' },
              { label: 'Reason', value: reasonLabel({ block_reason: ev.block_reason, verdict: (ev.verdict || flow.verdict) as TrafficFlow['verdict'], matched_rule_name: ev.matched_rule_name }), hidden: !!ev.allowed, full: true },
              {
                label: 'Threat match',
                value: [ev.threat_category, ev.threat_source, ev.threat_indicator].filter(Boolean).join(' · '),
                hidden: !ev.threat_category && !ev.threat_indicator,
                full: true,
              },
              {
                label: 'Suggested rule',
                value: <PatternText host={ev.suggested_host || flow.host} path={ev.suggested_path || '/**'} wrap />,
                hidden: !!ev.allowed || !ev.suggested_host,
                full: true,
              },
            ]}
          />

          {child && (
            <div className="rounded-lg border border-border bg-surface-2 p-3">
              <div className="mb-1.5 flex flex-wrap items-center gap-2 text-[12.5px] font-medium text-fg">
                <GitMerge className="h-4 w-4 text-fg-subtle" aria-hidden />
                Redirect target
                <VerdictBadge verdict={child.verdict} />
              </div>
              <p className="break-all font-mono text-[12px] text-fg-muted">{child.full_url}</p>
              {child.matched_rule_name && <p className="mt-1 text-[12px] text-fg-subtle">{child.matched_rule_name}</p>}
            </div>
          )}

          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => onInspect(child ?? flow, token)}>
              Inspect flow
            </Button>
            {!ev.allowed && portalEligible(ev.verdict || flow.verdict) && (
              <Button size="sm" icon={ExternalLink} onClick={() => navigate(portalUrl(flow, token))}>
                Open block portal
              </Button>
            )}
            {!perms.isReadOnly && !ev.allowed && verdictClass(ev.verdict || flow.verdict) !== 'security' && (
              <Button size="sm" variant="primary" icon={Plus} onClick={() => navigate(newSetFromFlowUrl(flow))}>
                Create rule
              </Button>
            )}
          </div>

          {result.cli_output && (
            <div className="overflow-hidden rounded-lg border border-sidebar-border bg-sidebar">
              <div className="flex items-center justify-between gap-2 border-b border-sidebar-border px-3 py-1.5">
                <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-sidebar-muted">
                  <Terminal className="h-3.5 w-3.5" aria-hidden />
                  What the server sees in its terminal
                </span>
                <CopyButton text={result.cli_output} label="Copy terminal output" size="xs" className="text-sidebar-muted hover:bg-sidebar-hover hover:text-white" />
              </div>
              <pre className="scroll-thin max-h-[340px] overflow-auto whitespace-pre p-3 font-mono text-[11.5px] leading-5 text-sidebar-fg">{result.cli_output}</pre>
            </div>
          )}
        </section>
      )}
    </Drawer>
  );
};
