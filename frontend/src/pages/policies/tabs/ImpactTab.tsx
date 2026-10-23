import React, { useCallback, useEffect, useState } from 'react';
import { FlaskConical, Play } from 'lucide-react';
import { api } from '../../../api';
import type { ImpactSummary, PolicySet, PolicySetSpecInput } from '../../../types';
import { Button, Callout, Card, EmptyState, Skeleton, useToast } from '../../../ui';
import { ImpactSummaryView } from '../../../components/policy/ImpactSummaryView';

/** Impact simulation of the draft (or unsaved edits) against recorded traffic. */
export const ImpactTab: React.FC<{ set: PolicySet; unsavedSpec: PolicySetSpecInput | null }> = ({ set, unsavedSpec }) => {
  const toast = useToast();
  const [impact, setImpact] = useState<ImpactSummary | null>(null);
  const [subject, setSubject] = useState<'unsaved' | 'draft' | 'published'>('draft');
  const [busy, setBusy] = useState(false);

  const run = useCallback(
    async (useUnsaved: boolean) => {
      setBusy(true);
      try {
        const res = await api.policySets.simulate(set.id, useUnsaved && unsavedSpec ? unsavedSpec : undefined);
        setImpact(res);
        setSubject(useUnsaved && unsavedSpec ? 'unsaved' : set.draft ? 'draft' : 'published');
      } catch (err) {
        toast.error(err, { title: 'Simulation failed' });
      } finally {
        setBusy(false);
      }
    },
    [set.id, set.draft, unsavedSpec, toast]
  );

  // run once when the tab opens / the saved draft changes
  useEffect(() => {
    run(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [set.id, set.draft?.updated_at, set.version]);

  const label = { unsaved: 'your unsaved edits', draft: 'the saved draft', published: 'the published version' }[subject];

  return (
    <div className="space-y-4">
      <Card padded className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent-soft text-accent">
            <FlaskConical className="h-4 w-4" aria-hidden />
          </span>
          <div>
            <p className="text-[13.5px] font-medium text-fg">Replay recorded traffic against {label}</p>
            <p className="text-[12.5px] text-fg-muted">
              Compares current verdicts with the verdicts this set would produce. Threat-protection verdicts do not change with rules and are not replayed.
            </p>
          </div>
        </div>
        <div className="flex shrink-0 gap-2">
          {unsavedSpec && (
            <Button onClick={() => run(true)} loading={busy && subject !== 'unsaved'} icon={Play}>
              Simulate unsaved edits
            </Button>
          )}
          <Button variant="primary" onClick={() => run(false)} loading={busy} icon={Play}>
            {impact ? 'Run again' : 'Run simulation'}
          </Button>
        </div>
      </Card>
      {unsavedSpec && subject !== 'unsaved' && <Callout tone="neutral">You have unsaved edits. The result below is for {label}.</Callout>}
      {!impact && busy && (
        <div className="grid grid-cols-2 gap-3 xl:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      )}
      {impact ? (
        <div className={busy ? 'opacity-60 transition-opacity' : undefined}>
          <ImpactSummaryView impact={impact} />
        </div>
      ) : (
        !busy && <EmptyState icon={FlaskConical} title="No simulation yet" description="Run a simulation to see which recorded requests would change." />
      )}
    </div>
  );
};
