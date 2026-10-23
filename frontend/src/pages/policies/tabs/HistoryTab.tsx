import React, { useState } from 'react';
import { Eye, GitCompare, GitPullRequestArrow, History, RotateCcw, Siren, Upload } from 'lucide-react';
import { api } from '../../../api';
import { useConsole } from '../../../data/AppData';
import { formatDateTime } from '../../../lib/format';
import { Link, navigate } from '../../../lib/router';
import type { PolicyDiff, PolicySet, PolicySetSpec, PolicySetVersion, PolicySetVersionSummary } from '../../../types';
import { Badge, Button, Card, CardHeader, Drawer, EmptyState, RelativeTime, Select, Skeleton, Timeline, useConfirm, useToast } from '../../../ui';
import { UserName } from '../../../components/common/EntityChips';
import { PolicyDiffView } from '../../../components/policy/PolicyDiffView';
import { RulesTable } from '../../../components/policy/RulesTable';

type Ref = string; // version number, 'published' or 'draft'

/** Version timeline with view, compare-any-two and rollback. */
export const HistoryTab: React.FC<{
  set: PolicySet;
  versions: PolicySetVersionSummary[];
  canManage: boolean;
  onChanged: () => Promise<void>;
}> = ({ set, versions, canManage, onChanged }) => {
  const { state } = useConsole();
  const toast = useToast();
  const confirm = useConfirm();
  const [viewing, setViewing] = useState<PolicySetVersion | null>(null);
  const [viewLoading, setViewLoading] = useState(false);
  const [from, setFrom] = useState<Ref>(versions[1] ? String(versions[1].version) : 'empty');
  const [to, setTo] = useState<Ref>(versions[0] ? String(versions[0].version) : 'published');
  const [compare, setCompare] = useState<{ diff: PolicyDiff; from?: PolicySetSpec; to?: PolicySetSpec; label: string } | null>(null);
  const [comparing, setComparing] = useState(false);
  const requireReview = !!state?.governance?.require_policy_review;
  const inReview = set.draft?.status === 'in_review';

  const refOptions = [
    ...(set.draft ? [{ value: 'draft', label: 'Draft (unpublished)' }] : []),
    ...versions.map((v) => ({ value: String(v.version), label: `v${v.version}${v.version === set.version ? ' (published)' : ''}` })),
    { value: 'empty', label: 'Empty set' },
  ];

  const specOf = async (ref: Ref): Promise<PolicySetSpec | undefined> => {
    if (ref === 'draft') return set.draft?.spec;
    if (ref === 'published') return set;
    if (ref === 'empty') return undefined;
    return (await api.policySets.version(set.id, Number(ref))).spec;
  };

  const runCompare = async (f: Ref, t: Ref) => {
    setComparing(true);
    try {
      const [diff, a, b] = await Promise.all([
        api.policySets.diff(set.id, f === 'draft' || f === 'empty' || f === 'published' ? f : Number(f), t === 'draft' || t === 'empty' || t === 'published' ? t : Number(t)),
        specOf(f),
        specOf(t),
      ]);
      const name = (r: Ref) => (r === 'draft' ? 'draft' : r === 'empty' ? 'empty set' : r === 'published' ? 'published' : `v${r}`);
      setCompare({ diff, from: a, to: b, label: `${name(f)} → ${name(t)}` });
    } catch (err) {
      toast.error(err, { title: 'Comparison failed' });
    } finally {
      setComparing(false);
    }
  };

  const view = async (v: number) => {
    setViewLoading(true);
    setViewing({ policy_set_id: set.id, version: v } as PolicySetVersion);
    try {
      setViewing(await api.policySets.version(set.id, v));
    } catch (err) {
      toast.error(err);
      setViewing(null);
    } finally {
      setViewLoading(false);
    }
  };

  const rollback = async (v: PolicySetVersionSummary) => {
    await confirm({
      title: `Roll back to v${v.version}?`,
      description: requireReview
        ? `Four-eyes review is on: v${v.version} is loaded into the draft and must be submitted for review. The current draft is replaced.`
        : `v${v.version} is published as a new version (v${set.version + 1}) immediately. Every worker enforces it within seconds.`,
      confirmLabel: requireReview ? 'Load into draft' : `Publish v${v.version} again`,
      tone: requireReview ? 'primary' : 'danger',
      reason: { label: 'Comment', placeholder: 'Incident or ticket number, reason for the rollback', multiline: true },
      onConfirm: async (comment) => {
        const res = await api.policySets.rollback(set.id, v.version, comment);
        await onChanged();
        if (res.published) toast.success(`Rolled back to v${v.version}`, { description: `Published as v${res.policy_set.version}.` });
        else {
          toast.success(`v${v.version} loaded into the draft`, { description: 'Review the changes and submit them for approval.' });
          navigate(`/policies/${encodeURIComponent(set.id)}/changes`);
        }
      },
    });
  };

  if (versions.length === 0) {
    return <EmptyState icon={History} title="No published versions yet" description="Every publish creates an immutable version. The last 30 are kept." />;
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
      <Card>
        <CardHeader title="Versions" description={`${versions.length} kept (the last 30 are retained)`} />
        <div className="p-[var(--card-p)]">
          <Timeline
            items={versions.map((v) => {
              const current = v.version === set.version;
              return {
                id: String(v.version),
                icon: v.emergency ? Siren : Upload,
                tone: v.emergency ? 'danger' : current ? 'accent' : 'neutral',
                current,
                title: (
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="tabular">v{v.version}</span>
                    {current && <Badge tone="accent">Published</Badge>}
                    {v.emergency && <Badge tone="danger">Emergency change</Badge>}
                    {v.change_request_id && (
                      <Link to={`/changes/${encodeURIComponent(v.change_request_id)}`} className="inline-flex">
                        <Badge tone="neutral" icon={GitPullRequestArrow}>
                          {v.change_request_id}
                        </Badge>
                      </Link>
                    )}
                  </span>
                ),
                meta: (
                  <span className="inline-flex items-center gap-1.5">
                    <UserName username={v.published_by} avatar={false} /> <RelativeTime value={v.published_at} />
                  </span>
                ),
                body: (
                  <div>
                    <p className="text-fg-muted">
                      {v.summary || 'Published'} <span className="text-fg-subtle">({v.rules} rule{v.rules === 1 ? '' : 's'})</span>
                    </p>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      <Button size="xs" variant="ghost" icon={Eye} onClick={() => view(v.version)}>
                        View
                      </Button>
                      {!current && (
                        <Button
                          size="xs"
                          variant="ghost"
                          icon={GitCompare}
                          onClick={() => {
                            setFrom(String(v.version));
                            setTo(String(set.version));
                            runCompare(String(v.version), String(set.version));
                          }}
                        >
                          Compare with published
                        </Button>
                      )}
                      {!current && canManage && !inReview && (
                        <Button size="xs" variant="ghost" icon={RotateCcw} onClick={() => rollback(v)}>
                          Roll back to this version
                        </Button>
                      )}
                    </div>
                  </div>
                ),
              };
            })}
          />
        </div>
      </Card>

      <div className="space-y-4 xl:sticky xl:top-20 xl:self-start">
        <Card>
          <CardHeader title="Compare versions" description="Pick any two states of this set." />
          <form
            className="space-y-3 p-[var(--card-p)]"
            onSubmit={(e) => {
              e.preventDefault();
              runCompare(from, to);
            }}
          >
            <label className="block">
              <span className="label mb-1.5 block">From</span>
              <Select value={from} onChange={(e) => setFrom(e.target.value)} options={refOptions} aria-label="Compare from" />
            </label>
            <label className="block">
              <span className="label mb-1.5 block">To</span>
              <Select value={to} onChange={(e) => setTo(e.target.value)} options={refOptions} aria-label="Compare to" />
            </label>
            <Button type="submit" variant="primary" icon={GitCompare} loading={comparing} disabled={from === to} fullWidth>
              Compare
            </Button>
          </form>
        </Card>
        {inReview && <p className="px-1 text-[12.5px] text-fg-subtle">Rollback is unavailable while a change request is open.</p>}
      </div>

      <Drawer open={!!compare} onClose={() => setCompare(null)} width="xl" title="Comparison" description={compare?.label}>
        {compare && <PolicyDiffView diff={compare.diff} from={compare.from} to={compare.to} emptyTitle="The two versions are identical" />}
      </Drawer>

      <Drawer
        open={!!viewing}
        onClose={() => setViewing(null)}
        width="xl"
        title={viewing ? `Version ${viewing.version}` : 'Version'}
        description={viewing?.published_at ? `Published ${formatDateTime(viewing.published_at)} by ${viewing.published_by}` : undefined}
      >
        {viewLoading || !viewing?.spec ? (
          <div className="space-y-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-10" />
            ))}
          </div>
        ) : (
          <div className="space-y-4">
            {viewing.summary && <p className="text-[13px] text-fg-muted">{viewing.summary}</p>}
            <RulesTable rows={(viewing.spec.rules ?? []).map((r) => ({ key: r.id, rule: r }))} showHits={false} />
          </div>
        )}
      </Drawer>
    </div>
  );
};
