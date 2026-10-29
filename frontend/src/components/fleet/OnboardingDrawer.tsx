import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, KeyRound, Monitor, ShieldCheck, Terminal, Variable } from 'lucide-react';
import { api } from '../../api';
import { useAction, useFlows } from '../../data/AppData';
import { formatDateTime, toTime } from '../../lib/format';
import { commentText, shellQuote } from '../../lib/shell';
import type { RotateTokenResponse, Server } from '../../types';
import { Button, Callout, CodeBlock, CopyButton, Drawer, RelativeTime, Spinner, TabPanel, Tabs } from '../../ui';
import { VerdictBadge } from '../traffic/VerdictBadge';

type Tab = 'linux' | 'windows' | 'env';

/**
 * Onboarding wizard: issue (rotate) the proxy token, show it once, the Linux / Windows /
 * environment snippets and a live check that waits for the server's first request.
 */
export const OnboardingDrawer: React.FC<{ open: boolean; onClose: () => void; server: Server | null }> = ({ open, onClose, server }) => {
  const { run, pending } = useAction();
  const { flows, connected } = useFlows();
  const [res, setRes] = useState<RotateTokenResponse | null>(null);
  const [issuedAt, setIssuedAt] = useState<number>(0);
  const [tab, setTab] = useState<Tab>('linux');

  useEffect(() => {
    if (open) {
      setRes(null);
      setTab('linux');
    }
  }, [open, server?.id]);

  const hasToken = !!server?.has_proxy_token;
  const firstFlow = useMemo(() => {
    if (!res || !server) return null;
    const since = issuedAt - 5_000;
    const mine = flows.filter((f) => f.server_id === server.id && (toTime(f.timestamp) ?? 0) >= since);
    return mine.length ? mine[mine.length - 1] : null;
  }, [flows, res, server, issuedAt]);

  if (!server) return null;

  const issue = async () => {
    const r = await run(() => api.servers.rotateToken(server.id), {
      key: 'rotate',
      success: hasToken ? 'Token rotated; the previous token no longer works' : 'Proxy token issued',
      errorTitle: 'The token was not issued',
    });
    if (r) {
      setRes(r);
      setIssuedAt(Date.now());
    }
  };

  const env = res
    ? [
        `# Proxy for ${commentText(server.hostname)} (user ${commentText(res.proxy_auth_user)})`,
        `export HTTPS_PROXY=${shellQuote(res.onboarding.proxy_url)}`,
        `export HTTP_PROXY=${shellQuote(res.onboarding.proxy_url)}`,
        `export NO_PROXY=${shellQuote(res.onboarding.no_proxy)}`,
        '',
        `# Proxy address without credentials: ${commentText(res.onboarding.proxy_address)}`,
      ].join('\n')
    : '';

  return (
    <Drawer
      open={open}
      onClose={onClose}
      dismissible={pending !== 'rotate'}
      width="lg"
      title={`Onboard ${server.hostname}`}
      description="Issue a proxy token, configure the server, then verify that its traffic reaches the proxy."
      footer={
        res ? (
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant={hasToken ? 'danger' : 'primary'} icon={KeyRound} loading={pending === 'rotate'} onClick={issue}>
              {hasToken ? 'Rotate token' : 'Issue token'}
            </Button>
          </>
        )
      }
    >
      <ol className="space-y-6">
        <Step n={1} title="Proxy token" done={!!res}>
          {!res ? (
            <div className="space-y-3">
              <p className="text-[13px] leading-5 text-fg-muted">
                The server authenticates every request with <span className="font-mono text-[12px]">Proxy-Authorization</span>. Only a hash of the token is stored; the
                plaintext is shown once.
              </p>
              {hasToken ? (
                <Callout tone="warning" title="A token is already configured">
                  Rotating revokes it immediately{server.token_rotated_at ? ` (issued ${formatDateTime(server.token_rotated_at)})` : ''}. The server loses access until it uses
                  the new token.
                </Callout>
              ) : (
                <Callout tone="info">No token has been issued for this server yet.</Callout>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="rounded-lg border border-border bg-surface-2 p-3">
                <div className="grid gap-3 sm:grid-cols-[auto_minmax(0,1fr)] sm:items-center">
                  <span className="text-[12px] font-medium text-fg-subtle">User</span>
                  <span className="flex min-w-0 items-center gap-1 font-mono text-[12.5px] text-fg">
                    <span className="truncate">{res.proxy_auth_user}</span>
                    <CopyButton text={res.proxy_auth_user} label="Copy user" size="xs" />
                  </span>
                  <span className="text-[12px] font-medium text-fg-subtle">Token</span>
                  <span className="flex min-w-0 items-center gap-1">
                    <code className="min-w-0 flex-1 break-all rounded bg-surface px-2 py-1 font-mono text-[12px] text-fg ring-1 ring-border" data-testid="proxy-token">
                      {res.token}
                    </code>
                    <CopyButton text={res.token} label="Copy token" />
                  </span>
                </div>
              </div>
              <Callout tone="warning" icon={AlertTriangle} title="Copy the token now">
                It is shown only once and cannot be retrieved later. Store it in the server's secret store or configuration management.
              </Callout>
            </div>
          )}
        </Step>

        <Step n={2} title="Configure the server" disabled={!res}>
          {res ? (
            <div className="space-y-3">
              <Tabs<Tab>
                idPrefix="onb"
                value={tab}
                onChange={setTab}
                aria-label="Platform"
                tabs={[
                  { id: 'linux', label: 'Linux', icon: Terminal },
                  { id: 'windows', label: 'Windows', icon: Monitor },
                  { id: 'env', label: 'Environment', icon: Variable },
                ]}
              />
              <TabPanel id={tab} idPrefix="onb">
                {tab === 'linux' && <CodeBlock title="Run as root (bash)" code={res.onboarding.linux} maxHeight={320} />}
                {tab === 'windows' && <CodeBlock title="Elevated PowerShell" code={res.onboarding.windows} maxHeight={320} />}
                {tab === 'env' && (
                  <div className="space-y-2">
                    <CodeBlock title="Shell environment" code={env} wrap />
                    <p className="text-[12px] leading-5 text-fg-subtle">
                      For tools that read the standard proxy variables. Keep the token out of shell history and world-readable files.
                    </p>
                  </div>
                )}
              </TabPanel>
            </div>
          ) : (
            <p className="text-[13px] text-fg-subtle">Snippets for Linux, Windows and plain environment variables appear after the token is issued.</p>
          )}
        </Step>

        <Step n={3} title="Verify" disabled={!res} done={!!firstFlow}>
          {res ? (
            firstFlow ? (
              <div className="flex items-start gap-3 rounded-lg border border-success-border bg-success-soft p-3 text-[13px]">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
                <div className="min-w-0 leading-5">
                  <p className="font-medium text-fg">The proxy attributed a request to this server</p>
                  <p className="flex flex-wrap items-center gap-1.5 text-fg-muted">
                    <span className="font-mono text-[12px]">
                      {firstFlow.method} {firstFlow.host}
                    </span>
                    <VerdictBadge verdict={firstFlow.verdict} />
                    <RelativeTime value={firstFlow.timestamp} />
                  </p>
                  <p className="mt-1 text-[12px] text-fg-subtle">
                    {firstFlow.proxy_auth_user ? `Identified by proxy user ${firstFlow.proxy_auth_user}.` : 'Identified by its IP address — configure the token so other hosts cannot impersonate it.'}
                  </p>
                </div>
              </div>
            ) : (
              <div className="space-y-2 text-[13px] leading-5 text-fg-muted">
                <p>
                  Run the last command of the snippet. A request to a host that is not allowed returns <span className="font-mono text-[12px]">403</span> with the
                  block page text — that already proves the proxy identifies the server.
                </p>
                <p className="flex items-center gap-2 text-fg-subtle">
                  {connected ? <Spinner className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" aria-hidden />}
                  {connected ? 'Waiting for the first request from this server…' : 'Live traffic is not connected; check the inventory for “last seen”.'}
                </p>
              </div>
            )
          ) : (
            <p className="text-[13px] text-fg-subtle">Once configured, the first request shows up here live.</p>
          )}
        </Step>
      </ol>
    </Drawer>
  );
};

const Step: React.FC<{ n: number; title: string; children: React.ReactNode; done?: boolean; disabled?: boolean }> = ({ n, title, children, done, disabled }) => (
  <li className="relative flex gap-3">
    <span
      className={
        done
          ? 'flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-success-solid text-white'
          : disabled
            ? 'flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-border-strong text-[12px] font-semibold text-fg-subtle'
            : 'flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary text-[12px] font-semibold text-primary-fg'
      }
      aria-hidden
    >
      {done ? <CheckCircle2 className="h-4 w-4" /> : n}
    </span>
    <div className="min-w-0 flex-1">
      <h3 className={disabled ? 'mb-2 text-[13.5px] font-semibold text-fg-subtle' : 'mb-2 text-[13.5px] font-semibold text-fg'}>
        <span className="sr-only">Step {n}: </span>
        {title}
      </h3>
      {children}
    </div>
  </li>
);
