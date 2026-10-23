// Microsoft Defender for Endpoint device data on servers (device sync of the Defender integration).
import React from 'react';
import { ExternalLink, ShieldAlert, ShieldCheck, ShieldHalf } from 'lucide-react';
import type { DefenderDevice, Server } from '../../types';
import { Badge, Card, CardHeader, CopyButton, DescriptionList, RelativeTime, Tone, Tooltip } from '../../ui';

/** quarantined_by value of quarantines applied by the Defender integration. */
export const DEFENDER_ACTOR = 'microsoft-defender';

export const isDefenderQuarantine = (s: Pick<Server, 'quarantined' | 'quarantined_by'>) => !!s.quarantined && s.quarantined_by === DEFENDER_ACTOR;

/** Human name for quarantined_by (users stay usernames). */
export const quarantinedByLabel = (by?: string) => (by === DEFENDER_ACTOR ? 'Microsoft Defender for Endpoint' : by || '');

const LEVEL_TONE: Record<string, Tone> = { high: 'danger', medium: 'warning', low: 'info', informational: 'neutral', none: 'success' };

export const levelTone = (v?: string): Tone => LEVEL_TONE[(v || '').toLowerCase()] ?? 'neutral';

/** "ImpairedCommunication" → "Impaired communication" */
export const humanizeDefender = (v?: string) => {
  const s = (v || '').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : 'Unknown';
};

/** Compact risk badge (lists, header meta). */
export const DefenderRiskBadge: React.FC<{ device: DefenderDevice; className?: string }> = ({ device, className }) => (
  <Tooltip content={`Microsoft Defender: risk ${humanizeDefender(device.risk_score).toLowerCase()}, exposure ${humanizeDefender(device.exposure_level).toLowerCase()}${device.isolated ? ', device isolated' : ''}`}>
    <Badge tone={device.isolated ? 'danger' : levelTone(device.risk_score)} icon={device.isolated ? ShieldAlert : ShieldHalf} className={className}>
      {device.isolated ? 'Isolated in Defender' : `Defender risk: ${humanizeDefender(device.risk_score).toLowerCase()}`}
    </Badge>
  </Tooltip>
);

/** Server detail card: risk, exposure, sensor health, isolation, last seen. */
export const DefenderDeviceCard: React.FC<{ device: DefenderDevice }> = ({ device: d }) => (
  <Card>
    <CardHeader
      icon={ShieldHalf}
      title="Microsoft Defender for Endpoint"
      description={`Device matched by ${d.matched_by === 'ip' ? 'IP address' : 'host name'}; refreshed with every device sync.`}
      actions={
        d.isolated ? (
          <Badge tone="danger" icon={ShieldAlert}>
            Isolated
          </Badge>
        ) : (
          <Badge tone="success" icon={ShieldCheck}>
            Not isolated
          </Badge>
        )
      }
      divider
    />
    <div className="p-[var(--card-p)]">
      <DescriptionList
        items={[
          {
            label: 'Risk level',
            value: (
              <Badge tone={levelTone(d.risk_score)} dot>
                {humanizeDefender(d.risk_score)}
              </Badge>
            ),
          },
          {
            label: 'Exposure level',
            value: (
              <Badge tone={levelTone(d.exposure_level)} dot>
                {humanizeDefender(d.exposure_level)}
              </Badge>
            ),
          },
          {
            label: 'Sensor health',
            value: (
              <Badge tone={/^active$/i.test(d.health_status) ? 'success' : d.health_status ? 'warning' : 'neutral'} dot>
                {humanizeDefender(d.health_status)}
              </Badge>
            ),
          },
          { label: 'Last seen by Defender', value: d.last_seen ? <RelativeTime value={d.last_seen} /> : <span className="text-fg-subtle">—</span> },
          { label: 'Device name', value: <span className="break-all font-mono text-[12.5px]">{d.computer_name || '—'}</span> },
          { label: 'Synchronized', value: <RelativeTime value={d.synced_at} /> },
          {
            label: 'Machine ID',
            full: true,
            value: (
              <span className="inline-flex max-w-full items-center gap-1">
                <span className="min-w-0 break-all font-mono text-[12px] text-fg-muted">{d.machine_id}</span>
                <CopyButton text={d.machine_id} size="xs" label="Copy machine ID" />
                <a
                  href={`https://security.microsoft.com/machines/v2/${encodeURIComponent(d.machine_id)}`}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex shrink-0 items-center gap-1 text-[12px] font-medium text-accent hover:underline"
                >
                  Defender portal <ExternalLink className="h-3 w-3" aria-hidden />
                </a>
              </span>
            ),
          },
        ]}
      />
    </div>
  </Card>
);
