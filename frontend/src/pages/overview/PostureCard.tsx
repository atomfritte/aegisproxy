import React from 'react';
import { ArrowRight, ShieldCheck } from 'lucide-react';
import { api } from '../../api';
import { useAsync } from '../../lib/hooks';
import { Link } from '../../lib/router';
import { ButtonLink, Card, Skeleton, StatusChip } from '../../ui';
import { ScoreRing, scoreBand, STATUS_META } from '../governance/posture/postureMeta';

/** Overview: compact security posture (InfoSec / Super Admin only — the caller checks the role). */
export const PostureCard: React.FC = () => {
  const { data, error } = useAsync(() => api.system.posture(), []);
  if (error) return null; // the posture page shows the error; keep the overview calm
  const checks = data?.checks ?? [];
  const fails = checks.filter((c) => c.status === 'fail');
  const warns = checks.filter((c) => c.status === 'warn');
  const top = [...fails, ...warns].slice(0, 3);
  const band = scoreBand(data?.score ?? 0);
  return (
    <Card as="section" aria-labelledby="posture-h" className="mb-6" data-testid="overview-posture">
      <div className="flex flex-col gap-4 p-[var(--card-p)] lg:flex-row lg:items-center">
        <div className="flex min-w-0 items-center gap-4">
          {data ? <ScoreRing score={data.score} size={64} /> : <Skeleton className="h-16 w-16 rounded-full" />}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 id="posture-h" className="text-[14px] font-semibold text-fg">
                Security posture
              </h2>
              {data && <StatusChip tone={band.tone} label={band.label} />}
            </div>
            <p className="mt-0.5 text-[12.5px] text-fg-muted">
              {data
                ? fails.length + warns.length === 0
                  ? `All ${checks.length} hardening checks pass.`
                  : `${fails.length} failing, ${warns.length} ${warns.length === 1 ? 'warning' : 'warnings'} of ${checks.length} hardening checks`
                : 'Running hardening checks…'}
            </p>
          </div>
        </div>
        {top.length > 0 && (
          <ul className="min-w-0 flex-1 space-y-1 border-border lg:border-l lg:pl-5">
            {top.map((c) => {
              const m = STATUS_META[c.status];
              const Icon = m.icon;
              return (
                <li key={c.id} className="flex min-w-0 items-center gap-2 text-[12.5px]">
                  <Icon className={c.status === 'fail' ? 'h-3.5 w-3.5 shrink-0 text-danger' : 'h-3.5 w-3.5 shrink-0 text-warning'} aria-label={m.label} />
                  <Link to={`/posture?status=${c.status}`} className="min-w-0 truncate text-fg hover:text-accent hover:underline">
                    {c.title}
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
        {data && top.length === 0 && (
          <p className="flex flex-1 items-center gap-2 text-[12.5px] text-success">
            <ShieldCheck className="h-4 w-4" aria-hidden />
            Nothing needs attention.
          </p>
        )}
        <ButtonLink to="/posture" size="sm" iconRight={ArrowRight} className="self-start lg:self-center">
          View posture
        </ButtonLink>
      </div>
    </Card>
  );
};
