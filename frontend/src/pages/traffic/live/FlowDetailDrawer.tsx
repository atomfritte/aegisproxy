import React from 'react';
import { ExternalLink, FlaskConical, GitMerge, Lock, LockOpen, Plus, Radar, ShieldAlert, ShieldCheck, Terminal } from 'lucide-react';
import { useConsoleState, usePermissions } from '../../../data/AppData';
import { formatBytes, formatDate, formatNumber } from '../../../lib/format';
import { Link, navigate } from '../../../lib/router';
import type { TrafficFlow } from '../../../types';
import { Badge, Button, ButtonLink, Callout, CopyButton, DescriptionList, Drawer, MethodList, Tooltip } from '../../../ui';
import { ChipList, GroupChip, ServerChip } from '../../../components/common/EntityChips';
import { VerdictBadge } from '../../../components/traffic/VerdictBadge';
import { newSetFromFlowUrl } from '../flowLinks';
import { clockTime, curlCommand, flowBytes, isBlockedVerdict, portalEligible, portalUrl, reasonLabel, verdictClass } from './flowUtils';

const Section: React.FC<{ title: React.ReactNode; icon?: React.ElementType; children: React.ReactNode }> = ({ title, icon: Icon, children }) => (
  <section className="border-t border-border pt-4">
    <h3 className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-fg">
      {Icon && <Icon className="h-4 w-4 text-fg-subtle" aria-hidden />}
      {title}
    </h3>
    {children}
  </section>
);

const Mono: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className }) => (
  <span className={`break-all font-mono text-[12px] ${className ?? ''}`}>{children}</span>
);

/** Explains the decision in one callout: which rule allowed it, why it was blocked, etc. */
const DecisionCallout: React.FC<{ flow: TrafficFlow }> = ({ flow }) => {
  const state = useConsoleState();
  const rule = flow.matched_rule_id ? (state.rules ?? []).find((r) => r.id === flow.matched_rule_id) : undefined;
  const ruleLink = rule?.policy_set_id ? (
    <>
      {' '}
      in{' '}
      <Link to={`/policies/${encodeURIComponent(rule.policy_set_id)}`} className="font-medium text-accent hover:underline">
        {rule.policy_set_name || rule.policy_set_id}
      </Link>
    </>
  ) : null;
  const cls = verdictClass(flow.verdict);
  if (cls === 'security') {
    const findings = (flow.dlp_findings ?? []).join(', ');
    const what: Record<string, React.ReactNode> = {
      THREAT_BLOCKED: 'The destination matches a threat-intelligence indicator.',
      MALWARE_BLOCKED: flow.av_signature ? (
        <>
          The antivirus engine found <Mono className="text-fg">{flow.av_signature}</Mono> in the downloaded content.
        </>
      ) : (
        'The antivirus engine found malware in the downloaded content.'
      ),
      DLP_BLOCKED: findings ? `Data loss prevention found ${findings} in the request body.` : 'Data loss prevention found sensitive data in the request body.',
      FILETYPE_BLOCKED: `Downloads of this file type${flow.file_type ? ` (${flow.file_type})` : ''} are blocked for this server's groups.`,
      QUARANTINED: 'The server is quarantined, so every destination is denied.',
      AUTH_FAILED:
        flow.block_reason === 'proxy_token_required'
          ? "The client sent only a proxy user name, but the server's group requires its proxy token (HTTP 407)."
          : 'The client sent proxy credentials that match no registered server (unknown, rotated or mistyped token). The proxy answered HTTP 407 and did not fall back to the source address.',
    };
    return (
      <Callout tone="danger" icon={ShieldAlert} title={flow.verdict === 'AUTH_FAILED' ? 'Proxy authentication failed' : 'Stopped by threat protection'}>
        {what[flow.verdict] ?? (reasonLabel(flow) || 'A threat-protection guardrail blocked this request.')}
        {(flow.threat_category || flow.threat_source) && (
          <span className="mt-1 block">
            {flow.threat_category && <>Category {flow.threat_category.replace(/_/g, ' ')}</>}
            {flow.threat_category && flow.threat_source && ', '}
            {flow.threat_source && <>source {flow.threat_source}</>}
          </span>
        )}
        {flow.threat_indicator && (
          <span className="mt-1 block">
            Indicator <Mono className="text-fg">{flow.threat_indicator}</Mono>
          </span>
        )}
        <span className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1">
          <Link to="/threats/events" className="font-medium text-accent hover:underline">
            Review security events
          </Link>
          {flow.verdict === 'QUARANTINED' && flow.server_id && (
            <Link to={`/servers/${encodeURIComponent(flow.server_id)}`} className="font-medium text-accent hover:underline">
              Open server
            </Link>
          )}
        </span>
      </Callout>
    );
  }
  if (cls === 'blocked') {
    return (
      <Callout tone="danger" icon={ShieldAlert} title="Blocked">
        {reasonLabel(flow)}
        {flow.matched_rule_name && flow.block_reason && (
          <span className="mt-1 block">
            Rule <span className="font-medium text-fg">{flow.matched_rule_name}</span>
            {ruleLink}
          </span>
        )}
      </Callout>
    );
  }
  if (cls === 'bypass') {
    return (
      <Callout tone="violet" icon={Lock} title="Passed through without TLS inspection">
        The destination matches a TLS inspection exception, so the connection was tunnelled without decryption. Paths and content were not inspected.{' '}
        <Link to="/tls" className="font-medium text-accent hover:underline">
          TLS exceptions
        </Link>
      </Callout>
    );
  }
  if (cls === 'learning') {
    return (
      <Callout tone="info" icon={Radar} title="Allowed by a learning session">
        The request was recorded and allowed while a learning session was active for this server.{' '}
        <Link to="/learning" className="font-medium text-accent hover:underline">
          Learning sessions
        </Link>
      </Callout>
    );
  }
  if (cls === 'allowed') {
    return (
      <Callout tone="success" icon={ShieldCheck} title={flow.verdict === 'REDIRECT_OBJECT_ALLOWED' ? 'Allowed as a linked redirect object' : 'Allowed'}>
        {flow.matched_rule_name ? (
          <>
            Matched <span className="font-medium text-fg">{flow.matched_rule_name}</span>
            {ruleLink}.
          </>
        ) : (
          'Matched an allow rule.'
        )}
      </Callout>
    );
  }
  return (
    <Callout tone="neutral" icon={FlaskConical} title="Simulated evaluation">
      This flow was produced by the policy simulator and never left the proxy.
    </Callout>
  );
};

export interface FlowDetailDrawerProps {
  flow: TrafficFlow | null;
  onClose: () => void;
  /** Re-run this request in the policy simulator. */
  onSimulate: (flow: TrafficFlow) => void;
  /** Signed token from a simulation (simulated flows are not recorded with a token). */
  blockToken?: string;
}

/** Everything about one flow: decision, request, source, inspection results, lineage, actions. */
export const FlowDetailDrawer: React.FC<FlowDetailDrawerProps> = ({ flow, onClose, onSimulate, blockToken }) => {
  const state = useConsoleState();
  const perms = usePermissions();
  if (!flow) return null;
  const groups = flow.group_ids ?? [];
  const blocked = isBlockedVerdict(flow.verdict);
  const security = verdictClass(flow.verdict) === 'security';
  const registered = !!flow.server_id && state.servers.some((s) => s.id === flow.server_id);
  const hasInspection =
    !!flow.content_sha256 || !!flow.file_type || !!flow.content_type || !!flow.av_result || !!flow.av_signature || (flow.dlp_findings ?? []).length > 0 || (flow.security_flags ?? []).length > 0;
  const hasLineage = !!flow.redirect_parent_url || !!flow.redirect_location;
  const token = flow.block_token || blockToken;

  return (
    <Drawer
      open
      onClose={onClose}
      width="lg"
      title={<span className="break-all">{flow.host}</span>}
      titleAside={<VerdictBadge verdict={flow.verdict} />}
      description={
        <>
          {formatDate(flow.timestamp)}, {clockTime(flow.timestamp)} · from {flow.server_hostname || flow.server_ip}
        </>
      }
      footer={
        <>
          <Button icon={FlaskConical} onClick={() => onSimulate(flow)} className="mr-auto">
            Simulate again
          </Button>
          {portalEligible(flow.verdict) && (
            <Button icon={ExternalLink} onClick={() => navigate(portalUrl(flow, token))}>
              Open block portal
            </Button>
          )}
          {security && perms.canManageSystem && (
            <ButtonLink to="/threats/exceptions" icon={ShieldCheck}>
              Add an exception
            </ButtonLink>
          )}
          {!perms.isReadOnly && !security && (
            <Button variant="primary" icon={Plus} onClick={() => navigate(newSetFromFlowUrl(flow))}>
              Create rule from flow
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-5">
        <div className="rounded-lg border border-border bg-surface-2">
          <div className="flex items-start gap-2 px-3 py-2.5">
            <MethodList methods={[flow.method]} className="mt-0.5 shrink-0" />
            <Mono className="min-w-0 flex-1 leading-5 text-fg">{flow.full_url}</Mono>
            <CopyButton text={flow.full_url} label="Copy URL" size="xs" className="shrink-0" />
          </div>
          <div className="flex items-center gap-2 border-t border-border px-3 py-2">
            <Terminal className="h-3.5 w-3.5 shrink-0 text-fg-subtle" aria-hidden />
            <Mono className="min-w-0 flex-1 truncate text-fg-muted">{curlCommand(flow, state.proxy_address)}</Mono>
            <CopyButton text={curlCommand(flow, state.proxy_address)} label="Copy as curl (through the proxy)" size="xs" className="shrink-0" />
          </div>
        </div>

        <DecisionCallout flow={flow} />

        <Section title="Request">
          <DescriptionList
            items={[
              { label: 'Status', value: flow.status_code ? <span className="tabular">{flow.status_code}</span> : '—' },
              { label: 'Latency', value: <span className="tabular">{formatNumber(flow.latency_ms)} ms</span> },
              { label: 'Received', value: formatBytes(flow.bytes_received || 0) },
              { label: 'Sent', value: formatBytes(flow.bytes_sent || 0) },
              { label: 'Destination', value: <Mono>{flow.resolved_ip ? `${flow.resolved_ip}${flow.port ? `:${flow.port}` : ''}` : `${flow.scheme}://${flow.host}${flow.port ? `:${flow.port}` : ''}`}</Mono> },
              {
                label: 'Trace ID',
                value: (
                  <span className="inline-flex items-center gap-1">
                    <Mono>{flow.id}</Mono>
                    <CopyButton text={flow.id} label="Copy trace ID" size="xs" />
                  </span>
                ),
              },
              { label: 'User agent', value: flow.user_agent ? <Mono>{flow.user_agent}</Mono> : '—', full: true },
            ]}
          />
        </Section>

        <Section title="Source">
          <DescriptionList
            items={[
              {
                label: 'Server',
                value: registered ? (
                  <ServerChip id={flow.server_id} />
                ) : (
                  <span>
                    {flow.server_hostname || 'Unregistered source'} <Badge tone="warning">Not registered</Badge>
                  </span>
                ),
              },
              { label: 'IP address', value: <Mono>{flow.server_ip}</Mono> },
              {
                label: 'Groups',
                value: groups.length ? (
                  <ChipList max={6}>
                    {groups.map((g) => (
                      <GroupChip key={g} id={g} />
                    ))}
                  </ChipList>
                ) : (
                  <span className="text-fg-subtle">No group</span>
                ),
                full: true,
              },
              { label: 'Proxy user', value: flow.proxy_auth_user ? <Mono>{flow.proxy_auth_user}</Mono> : '—', hidden: !flow.proxy_auth_user },
            ]}
          />
        </Section>

        <Section title="Decision">
          <DescriptionList
            items={[
              { label: 'Verdict', value: <VerdictBadge verdict={flow.verdict} /> },
              {
                label: 'TLS',
                value: flow.tls_intercepted ? (
                  <span className="inline-flex items-center gap-1.5">
                    <LockOpen className="h-3.5 w-3.5 text-fg-subtle" aria-hidden /> Decrypted and inspected
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5">
                    <Lock className="h-3.5 w-3.5 text-fg-subtle" aria-hidden /> Passed through (not decrypted)
                  </span>
                ),
              },
              { label: 'Matched rule', value: flow.matched_rule_name || <span className="text-fg-subtle">None</span>, full: true },
              { label: 'Reason', value: reasonLabel(flow), hidden: !blocked, full: true },
              { label: 'Follows redirects', value: flow.follow_redirects ? 'Yes, linked objects are allowed' : 'No', hidden: flow.follow_redirects === undefined },
              {
                label: 'Learning session',
                value: (
                  <Link to="/learning" className="font-mono text-[12px] text-accent hover:underline">
                    {flow.session_id}
                  </Link>
                ),
                hidden: !flow.session_id,
              },
            ]}
          />
        </Section>

        {hasInspection && (
          <Section title="Content inspection" icon={ShieldAlert}>
            <DescriptionList
              items={[
                {
                  label: 'File type',
                  value: (
                    <span>
                      {flow.file_type || '—'}
                      {flow.content_type && <span className="ml-1 font-mono text-[12px] text-fg-subtle">{flow.content_type}</span>}
                    </span>
                  ),
                  hidden: !flow.file_type && !flow.content_type,
                },
                {
                  label: 'Antivirus',
                  value: (
                    <span className="inline-flex flex-wrap items-center gap-1.5">
                      <Badge tone={flow.av_result === 'clean' ? 'success' : flow.av_result === 'infected' || flow.av_signature ? 'danger' : 'warning'} className="capitalize">
                        {flow.av_result || 'infected'}
                      </Badge>
                      {flow.av_signature && <Mono className="text-danger">{flow.av_signature}</Mono>}
                    </span>
                  ),
                  hidden: !flow.av_result && !flow.av_signature,
                },
                {
                  label: 'DLP findings',
                  value: (
                    <span className="flex flex-wrap gap-1">
                      {(flow.dlp_findings ?? []).map((d) => (
                        <Badge key={d} tone="danger">
                          {d}
                        </Badge>
                      ))}
                    </span>
                  ),
                  hidden: (flow.dlp_findings ?? []).length === 0,
                },
                {
                  label: 'Security flags',
                  value: (
                    <span className="flex flex-wrap gap-1">
                      {(flow.security_flags ?? []).map((d) => (
                        <Badge key={d} tone="warning">
                          {d}
                        </Badge>
                      ))}
                    </span>
                  ),
                  hidden: (flow.security_flags ?? []).length === 0,
                },
                {
                  label: 'SHA-256',
                  value: (
                    <span className="inline-flex items-start gap-1">
                      <Mono>{flow.content_sha256}</Mono>
                      <CopyButton text={flow.content_sha256 || ''} label="Copy hash" size="xs" className="shrink-0" />
                    </span>
                  ),
                  hidden: !flow.content_sha256,
                  full: true,
                },
              ]}
            />
          </Section>
        )}

        {hasLineage && (
          <Section title="Redirect lineage" icon={GitMerge}>
            <DescriptionList
              columns={1}
              items={[
                { label: 'Parent request', value: <Mono>{flow.redirect_parent_url}</Mono>, hidden: !flow.redirect_parent_url },
                { label: 'Redirect target', value: <Mono>{flow.redirect_location}</Mono>, hidden: !flow.redirect_location },
              ]}
            />
            <p className="mt-2 text-[12px] leading-5 text-fg-subtle">
              Rules with “follow redirects” allow the objects a permitted request redirects to (release assets, CDN blobs) for a short time, without opening the CDN host.
            </p>
          </Section>
        )}

        <Section title="Data plane">
          <DescriptionList
            items={[
              { label: 'Worker', value: flow.data_plane_id ? <Mono>{flow.data_plane_id}</Mono> : <span className="text-fg-subtle">Control plane (simulated or seeded)</span> },
              {
                label: 'Signed block token',
                value: token ? (
                  <Tooltip content="The block portal can attest server identity and URL for access requests.">
                    <Badge tone="success" icon={ShieldCheck}>
                      Present
                    </Badge>
                  </Tooltip>
                ) : (
                  <span className="text-fg-subtle">None</span>
                ),
                hidden: !blocked,
              },
              { label: 'Size', value: formatBytes(flowBytes(flow)) },
            ]}
          />
        </Section>
      </div>
    </Drawer>
  );
};
